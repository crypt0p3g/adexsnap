#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import os
import re
import struct
import sys
import tempfile
import time
import uuid


_COLOR_ENABLED = False
_ANSI = {
    "green": "\033[32m",
    "cyan": "\033[36m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _configure_color(mode):
    """Configure human-readable output without ever putting ANSI codes in redirected logs."""
    global _COLOR_ENABLED
    if mode == "always":
        _COLOR_ENABLED = True
    elif mode == "never":
        _COLOR_ENABLED = False
    else:
        _COLOR_ENABLED = (sys.stdout.isatty() and "NO_COLOR" not in os.environ
                          and os.environ.get("TERM", "") != "dumb")


def _paint(text, color):
    if not _COLOR_ENABLED:
        return text
    return _ANSI[color] + text + _ANSI["reset"]


def _colorize_text(value):
    if not _COLOR_ENABLED or not isinstance(value, str):
        return value
    value = value.replace("[+]", _paint("[+]", "green"))
    value = value.replace("[*]", _paint("[*]", "cyan"))
    value = value.replace("[!]", _paint("[!]", "yellow"))
    if value.startswith("RESULT"):
        value = value.replace("PASS", _paint("PASS", "green"))
        value = value.replace("FAIL", _paint("FAIL", "red"))
    return value


def _print(*values, **kwargs):
    print(*(_colorize_text(value) for value in values), **kwargs)

# ---------------------------------------------------------------------------
# ADSTYPE enumeration (subset the reader decodes)
# ---------------------------------------------------------------------------
ADSTYPE_DN_STRING = 1
ADSTYPE_CASE_EXACT_STRING = 2
ADSTYPE_CASE_IGNORE_STRING = 3
ADSTYPE_PRINTABLE_STRING = 4
ADSTYPE_NUMERIC_STRING = 5
ADSTYPE_BOOLEAN = 6
ADSTYPE_INTEGER = 7
ADSTYPE_OCTET_STRING = 8
ADSTYPE_UTC_TIME = 9
ADSTYPE_LARGE_INTEGER = 10
ADSTYPE_OBJECT_CLASS = 12
ADSTYPE_NT_SECURITY_DESCRIPTOR = 25
ADSTYPE_DN_WITH_BINARY = 27
ADSTYPE_DN_WITH_STRING = 28

_STRING_TYPES = frozenset(
    (
        ADSTYPE_DN_STRING,
        ADSTYPE_CASE_EXACT_STRING,
        ADSTYPE_CASE_IGNORE_STRING,
        ADSTYPE_PRINTABLE_STRING,
        ADSTYPE_NUMERIC_STRING,
        ADSTYPE_OBJECT_CLASS,
    )
)

HEADER_SIZE = 0x43E            # 1086 — effective header length; first object starts here
MARKER = 0x00010001
SIG_COMPLETE = b"win-ad-ob\x00"
SIG_PROGRESS = b"win-ad-XX\x00"

# LDAP control OIDs
OID_SD_FLAGS = "1.2.840.113556.1.4.801"       # LDAP_SERVER_SD_FLAGS_OID
OID_SHOW_DELETED = "1.2.840.113556.1.4.417"   # LDAP_SERVER_SHOW_DELETED_OID
SD_FLAGS_OWNER_GROUP_DACL = 7                 # O|G|DACL (no SACL -> no SeSecurityPrivilege)

# Standard LDAP syntax OID -> ADSTYPE (as AD publishes attributeTypes SYNTAX)
_SYNTAX_TO_ADSTYPE = {
    "1.3.6.1.4.1.1466.115.121.1.12": ADSTYPE_DN_STRING,        # DN
    "1.3.6.1.4.1.1466.115.121.1.15": ADSTYPE_CASE_IGNORE_STRING,  # DirectoryString
    "1.3.6.1.4.1.1466.115.121.1.26": ADSTYPE_CASE_IGNORE_STRING,  # IA5String
    "1.3.6.1.4.1.1466.115.121.1.44": ADSTYPE_PRINTABLE_STRING,    # PrintableString
    "1.3.6.1.4.1.1466.115.121.1.36": ADSTYPE_NUMERIC_STRING,      # NumericString
    "1.3.6.1.4.1.1466.115.121.1.38": ADSTYPE_CASE_IGNORE_STRING,  # OID
    "1.3.6.1.4.1.1466.115.121.1.27": ADSTYPE_INTEGER,            # Integer
    "1.3.6.1.4.1.1466.115.121.1.7":  ADSTYPE_BOOLEAN,            # Boolean
    "1.3.6.1.4.1.1466.115.121.1.40": ADSTYPE_OCTET_STRING,       # OctetString
    "1.3.6.1.4.1.1466.115.121.1.5":  ADSTYPE_OCTET_STRING,       # Binary
    "1.3.6.1.4.1.1466.115.121.1.24": ADSTYPE_UTC_TIME,          # GeneralizedTime -> SystemTime
    "1.3.6.1.4.1.1466.115.121.1.53": ADSTYPE_UTC_TIME,          # UTCTime -> SystemTime
    "1.2.840.113556.1.4.906": ADSTYPE_LARGE_INTEGER,            # LargeInteger / Interval
    "1.2.840.113556.1.4.907": ADSTYPE_NT_SECURITY_DESCRIPTOR,   # NT-Sec-Desc
    "1.2.840.113556.1.4.905": ADSTYPE_CASE_IGNORE_STRING,       # CaseIgnoreString (Teletex)
    "1.2.840.113556.1.4.1221": ADSTYPE_CASE_IGNORE_STRING,      # OR-Name
    "1.2.840.113556.1.4.1362": ADSTYPE_CASE_EXACT_STRING,       # CaseExactString
    "1.2.840.113556.1.4.903": ADSTYPE_DN_STRING,                # DNWithOctetString-ish -> keep as DN text
}

# Each schema Property record in a snapshot carries two type fields: an internal `syntax_id`
# (shown in the AD Explorer "Syntax" column) and the value-decoder `adsType`. Both follow from
# an attribute's AD-native (attributeSyntax OID, oMSyntax) pair. The tables below reproduce the
# pairings observed in snapshot files for every syntax AD publishes. Match rule: exact
# (OID, oMSyntax).
SYNTAX_ID_BY_ADSYNTAX = {
    ("2.5.5.1", 127): 18,   # Object(DS-DN)               -> DN_STRING(1)
    ("2.5.5.2", 6):   12,   # String(Object-Identifier)   -> CASE_IGNORE_STRING(3)  [objectClass]
    ("2.5.5.3", 27):  5,    # String(Case-sensitive)      -> CASE_EXACT_STRING(2)
    ("2.5.5.3", 20):  5,
    ("2.5.5.4", 20):  6,    # String(Teletex)/CaseIgnore  -> CASE_IGNORE_STRING(3)
    ("2.5.5.5", 22):  8,    # String(IA5)                 -> PRINTABLE_STRING(4)
    ("2.5.5.5", 19):  13,   # String(Printable)           -> PRINTABLE_STRING(4)
    ("2.5.5.6", 18):  10,   # String(Numeric)             -> NUMERIC_STRING(5)
    ("2.5.5.7", 127): 21,   # Object(DN-Binary)/OR-Name   -> OCTET_STRING(8)
    ("2.5.5.8", 1):   1,    # Boolean                     -> BOOLEAN(6)
    ("2.5.5.9", 10):  2,    # Enumeration                 -> INTEGER(7)
    ("2.5.5.9", 2):   3,    # Integer                     -> INTEGER(7)
    ("2.5.5.10", 4):  11,   # String(Octet)               -> OCTET_STRING(8)
    ("2.5.5.10", 127): 23,  # Object(Replica-Link)        -> OCTET_STRING(8)
    ("2.5.5.11", 23): 16,   # String(UTC-Time)            -> UTC_TIME(9)
    ("2.5.5.11", 24): 15,   # String(Generalized-Time)    -> UTC_TIME(9)
    ("2.5.5.12", 64): 7,    # String(Unicode)/DirString   -> CASE_IGNORE_STRING(3)
    ("2.5.5.13", 127): 22,  # Object(Presentation-Address)-> CASE_IGNORE_STRING(3)
    ("2.5.5.14", 127): 17,  # Object(Access-Point/DN-Str) -> DN_WITH_STRING(28)
    ("2.5.5.15", 66): 9,    # String(NT-Sec-Desc)         -> NT_SECURITY_DESCRIPTOR(25)
    ("2.5.5.16", 65): 4,    # LargeInteger/Interval       -> LARGE_INTEGER(10)
    ("2.5.5.17", 4):  14,   # String(Sid)                 -> OCTET_STRING(8)
    ("2.5.5.17", 127): 19,  # Object(DN-Binary)           -> DN_WITH_BINARY(27)
}
ADSTYPE_BY_SYNTAX_ID = {
    0: 0, 1: 6, 2: 7, 3: 7, 4: 10, 5: 2, 6: 3, 7: 3, 8: 4, 9: 25, 10: 5, 11: 8,
    12: 3, 13: 4, 14: 8, 15: 9, 16: 9, 17: 28, 18: 1, 19: 27, 20: 28, 21: 8, 22: 3, 23: 8,
}
# Representative syntax_id for operational attributes lacking AD-native schema syntax.
SYNTAX_ID_BY_ADSTYPE = {
    1: 18, 2: 5, 3: 7, 4: 13, 5: 10, 6: 1, 7: 3, 8: 11, 9: 15, 10: 4, 12: 12, 25: 9,
}


def _encoding_family(ads_type):
    """Group adsTypes that serialize to byte-identical value blocks, so syntax_id can be adopted
    from the schema only when it stays consistent with how the values were already encoded."""
    if ads_type in _STRING_TYPES:
        return "str"
    return {8: "oct", 7: "int", 10: "lint", 6: "bool", 9: "time", 25: "sd",
            27: "dnbin", 28: "count"}.get(ads_type, "count")

# Name-based overrides for security-critical / well-known attributes. These win over
# schema/heuristics so the raw bytes BloodHound needs are preserved verbatim.
_NAME_OVERRIDES = {
    "ntsecuritydescriptor": ADSTYPE_NT_SECURITY_DESCRIPTOR,
    "msds-allowedtoactonbehalfofotheridentity": ADSTYPE_NT_SECURITY_DESCRIPTOR,
    "objectsid": ADSTYPE_OCTET_STRING,
    "sidhistory": ADSTYPE_OCTET_STRING,
    "securityidentifier": ADSTYPE_OCTET_STRING,
    "objectguid": ADSTYPE_OCTET_STRING,
    "schemaidguid": ADSTYPE_OCTET_STRING,
    "attributesecurityguid": ADSTYPE_OCTET_STRING,
    "msds-optionalfeatureguid": ADSTYPE_OCTET_STRING,
    "objectclass": ADSTYPE_CASE_IGNORE_STRING,   # AD Explorer stores objectClass as adsType 3, not 12
    "logonhours": ADSTYPE_OCTET_STRING,
    "usercertificate": ADSTYPE_OCTET_STRING,
    "cacertificate": ADSTYPE_OCTET_STRING,
    "dnshostname": ADSTYPE_CASE_IGNORE_STRING,
    "dnsrecord": ADSTYPE_OCTET_STRING,
    "dnsproperty": ADSTYPE_OCTET_STRING,
    # GeneralizedTime attributes -> UTC_TIME (SystemTime); real AD Explorer stores these
    # as ADS_UTC_TIME, and ADExplorerSnapshot.py/BloodHound expect a parseable timestamp
    # (storing them as strings triggers "Failed to parse timestamp for attribute ...").
    "whencreated": ADSTYPE_UTC_TIME,
    "whenchanged": ADSTYPE_UTC_TIME,
    "dscorepropagationdata": ADSTYPE_UTC_TIME,
    "createtimestamp": ADSTYPE_UTC_TIME,
    "modifytimestamp": ADSTYPE_UTC_TIME,
}
# Fallback numeric attributes if schema is unavailable (keeps BloodHound-critical ints correct).
_KNOWN_INTEGER = {
    "useraccountcontrol", "samaccounttype", "grouptype", "primarygroupid",
    "systemflags", "instancetype", "msds-supportedencryptiontypes", "searchflags",
    "omsyntax", "rangelower", "rangeupper", "linkid", "dwordvalue",
    "trustdirection", "trusttype", "trustattributes",
}
_KNOWN_LARGEINT = {
    "pwdlastset", "lastlogon", "lastlogontimestamp", "accountexpires",
    "badpasswordtime", "lockouttime", "lastlogoff", "creationtime",
    "maxpwdage", "minpwdage", "lockoutduration", "lockoutobservationwindow",
    "msds-lastsuccessfulinteractivelogontime", "msds-lastfailedinteractivelogontime",
}

# AD Explorer omits these legacy SAM-domain fields when expanding domainDNS for
# the Search dialog. They remain ordinary captured object properties.
_DOMAIN_DNS_SEARCH_EXCLUSIONS = {
    "domainreplica", "forcelogoff", "modifiedcount", "objectsid",
    "oeminformation", "serverrole", "serverstate", "uascompat",
}

SNAPSHOT_QUERIES = {
    # Exact filter used by AD Explorer's native capture routine.
    "native": "(objectGUID=*)",
    # Equivalent presence filter over the identifying GUID.
    "guid": "(objectGUID=*)",
    # Conventional LDAP catch-all retained for comparison and compatibility testing.
    "class": "(objectClass=*)",
    # Same presence filter using objectGUID's schema OID as the AttributeDescription.
    "guid-oid": "(1.2.840.113556.1.4.2=*)",
    # MS-ADTS guarantees every actual object has a non-NULL identifying objectGUID.
    "guid-nonzero": r"(!(objectGUID=\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00))",
    # Stricter optional comparison filter; this is not AD Explorer's native filter.
    "guid-and-class": "(&(objectGUID=*)(objectClass=*))",
    "guid-or-class": "(|(objectGUID=*)(objectClass=*))",
    # Logically equivalent rewrites useful for testing LDAP filter handling.
    "guid-double-not": "(!(!(objectGUID=*)))",
    "guid-deleted-partition":
        "(|(&(objectGUID=*)(isDeleted=TRUE))(&(objectGUID=*)(!(isDeleted=TRUE))))",
}
# Explicit objectClass is intentional: LDAP's '*' already normally includes it, but requesting
# it by name documents and enforces the value BOFHound uses to classify every object.
SNAPSHOT_ATTRIBUTES = ["*", "objectClass", "ntSecurityDescriptor"]

# Well-known (forest-constant) schemaIDGUIDs. ADExplorerSnapshot builds BloodHound's
# objecttype_guid_map from the snapshot's Classes table (className -> schemaIDGUID) and
# Properties table (attr CN -> schemaIDGUID). With an empty Classes table, BloodHound's
# ace_applies() does objecttype_guid_map['group'|'user'|'computer'|'domain'] and raises
# KeyError. We populate the Classes table with these constants so that lookup succeeds and
# inherited-object-type ACEs resolve correctly.
WELLKNOWN_CLASS_GUIDS = {
    "domain":                 "19195a5a-6da0-11d0-afd3-00c04fd930c9",
    "domaindns":              "19195a5b-6da0-11d0-afd3-00c04fd930c9",
    "user":                   "bf967aba-0de6-11d0-a285-00aa003049e2",
    "computer":               "bf967a86-0de6-11d0-a285-00aa003049e2",
    "group":                  "bf967a9c-0de6-11d0-a285-00aa003049e2",
    "organizationalunit":     "bf967aa5-0de6-11d0-a285-00aa003049e2",
    "container":              "bf967a8b-0de6-11d0-a285-00aa003049e2",
    "grouppolicycontainer":   "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
    "trusteddomain":          "bf967ab8-0de6-11d0-a285-00aa003049e2",
    "foreignsecurityprincipal": "89e31c12-8530-11d0-afda-00c04fd930c9",
    "builtindomain":          "bf967a81-0de6-11d0-a285-00aa003049e2",
    "person":                 "bf967aac-0de6-11d0-a285-00aa003049e2",
    "organizationalperson":   "bf967aab-0de6-11d0-a285-00aa003049e2",
    "msds-groupmanagedserviceaccount": "7b8b558a-93a5-4af7-adca-c017e67f1057",
    "pkicertificatetemplate": "e5209ca2-3bba-11d2-90cc-00c04fd91ab1",
    "pkienrollmentservice":   "ee4aa692-3bba-11d2-90cc-00c04fd91ab1",
    "classschema":            "bf967a83-0de6-11d0-a285-00aa003049e2",
    "attributeschema":        "bf967a80-0de6-11d0-a285-00aa003049e2",
    "organization":           "bf967aa3-0de6-11d0-a285-00aa003049e2",
}

# ACL-relevant attributes, keyed by lDAPDisplayName(lower) -> (schemaIDGUID, canonical CN).
# BloodHound looks these up in objecttype_guid_map by the attribute's CN (from the Property
# DN's first RDN). 'service-principal-name' is referenced UNGUARDED, so its key must exist.
WELLKNOWN_ATTR_GUIDS = {
    "serviceprincipalname":   ("f3a64788-5306-11d1-a9c5-0000f80367c1", "Service-Principal-Name"),
    "member":                 ("bf9679c0-0de6-11d0-a285-00aa003049e2", "Member"),
    "msds-keycredentiallink": ("5b47d60f-6090-40b2-9f37-2a4de88f3063", "ms-DS-Key-Credential-Link"),
    "msds-allowedtoactonbehalfofotheridentity":
                              ("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79", "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity"),
    "useraccountcontrol":     ("bf967a68-0de6-11d0-a285-00aa003049e2", "User-Account-Control"),
    "gplink":                 ("f30e3bbe-9ff0-11d1-b603-0000f80367c1", "GP-Link"),
    "scriptpath":             ("bf9679a8-0de6-11d0-a285-00aa003049e2", "Script-Path"),
}


# ---------------------------------------------------------------------------
# Snapshot writer
# ---------------------------------------------------------------------------
def _wstr(s: str) -> bytes:
    """UTF-16LE + NUL terminator."""
    return s.encode("utf-16-le", "replace") + b"\x00\x00"


def _lenprefixed(s: str) -> bytes:
    """uint32 byte-length (incl. trailing NUL) + UTF-16LE text (STR encoding)."""
    data = _wstr(s)
    return struct.pack("<I", len(data)) + data


def _nullable_lenprefixed(s: str | None) -> bytes:
    """AD Explorer uses a zero length for a null optional STR pointer."""
    return _lenprefixed(s) if s else struct.pack("<I", 0)


def _sddl_to_binary(value: str) -> bytes:
    """Convert classSchema.defaultSecurityDescriptor to self-relative binary form."""
    if not value:
        return b""
    value = re.sub(r"([OGDS]):\s+", r"\1:", value.strip())
    if value in {"D:", "S:", "D:S:"}:
        # Present, empty ACLs. These are emitted by AD schema and trip winacl's
        # tokeniser; construct their canonical self-relative forms directly.
        empty_acl = b"\x02\x00\x08\x00\x00\x00\x00\x00"
        if value == "D:":
            return struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + empty_acl
        if value == "S:":
            return struct.pack("<BBHIIII", 1, 0, 0x8010, 0, 0, 20, 0) + empty_acl
        return (struct.pack("<BBHIIII", 1, 0, 0x8014, 0, 0, 20, 28)
                + empty_acl + empty_acl)
    try:
        fixed_sids = {
            "AN": "S-1-5-7", "AU": "S-1-5-11", "BU": "S-1-5-32-545",
            "CG": "S-1-3-1", "CO": "S-1-3-0", "ED": "S-1-5-9",
            "IU": "S-1-5-4", "LS": "S-1-5-19", "NS": "S-1-5-20",
            "NU": "S-1-5-2", "PS": "S-1-5-10", "RC": "S-1-5-12",
            "SU": "S-1-5-6", "SY": "S-1-5-18", "WD": "S-1-1-0",
            "AO": "S-1-5-32-548", "BA": "S-1-5-32-544", "BG": "S-1-5-32-546",
            "BO": "S-1-5-32-551", "CD": "S-1-5-32-574", "NO": "S-1-5-32-556",
            "PO": "S-1-5-32-550", "PU": "S-1-5-32-547", "RD": "S-1-5-32-555",
            "RE": "S-1-5-32-552", "RS": "S-1-5-32-553", "RU": "S-1-5-32-554",
            "SO": "S-1-5-32-549", "HI": "S-1-16-12288", "LW": "S-1-16-4096",
            "ME": "S-1-16-8192", "SI": "S-1-16-16384",
        }
        domain_relative = {"CA", "DA", "DC", "DD", "DG", "DU", "EA", "LA", "LG",
                           "PA", "RO", "SA"}
        owner_group = re.findall(r"[OG]:([A-Z]{2})(?=[OGDS]:|$)", value)
        ace_sids = []
        for body in re.findall(r"\(([^()]*)\)", value):
            fields = body.split(";")
            if len(fields) >= 6:
                ace_sids.append(fields[5])
        if any(sid in domain_relative for sid in owner_group + ace_sids):
            return b""

        def replace_owner_group(match):
            return match.group(1) + fixed_sids.get(match.group(2), match.group(2))

        value = re.sub(r"([OG]:)([A-Z]{2})(?=[OGDS]:|$)", replace_owner_group, value)

        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
        from winacl.dtyp.ace import well_known_accessmasks
    except ImportError as exc:
        raise RuntimeError(
            "class schema contains defaultSecurityDescriptor but 'winacl' is not installed; "
            "install it with: pip install winacl") from exc
    try:
        # winacl accepts a single symbolic access mask but not concatenated AD
        # rights such as RPWPCRCCDCLCLORCWOWDSDDTSW. Convert only that ACE field
        # to its equivalent numeric mask before parsing.
        def normalize_ace(match):
            body = match.group(1)
            fields = body.split(";")
            if len(fields) >= 6:
                rights = fields[2]
                tokens = [rights[i:i + 2] for i in range(0, len(rights), 2)]
                if (len(rights) > 2 and len(rights) % 2 == 0
                        and all(token in well_known_accessmasks for token in tokens)):
                    mask = 0
                    for token in tokens:
                        mask |= well_known_accessmasks[token]
                    fields[2] = hex(mask)
                fields[5] = fixed_sids.get(fields[5], fields[5])
                body = ";".join(fields)
            return "(" + body + ")"

        normalized = re.sub(r"\(([^()]*)\)", normalize_ace, value)
        descriptor = SECURITY_DESCRIPTOR.from_sddl(normalized)
        # Some winacl ACE constructors leave the optional callback/application
        # tail as None; an absent tail is represented by zero bytes on disk.
        for acl in (descriptor.Dacl, descriptor.Sacl):
            for ace in getattr(acl, "aces", ()):
                if hasattr(ace, "ApplicationData") and ace.ApplicationData is None:
                    ace.ApplicationData = b""
        return descriptor.to_bytes()
    except Exception as exc:
        raise RuntimeError("could not convert class defaultSecurityDescriptor %r: %s"
                           % (value, exc)) from exc


class _Property:
    __slots__ = ("index", "name", "ads_type", "dn", "schema_guid", "sec_guid",
                 "syntax_id", "display_hint")

    def __init__(self, index, name, ads_type, dn, schema_guid, sec_guid):
        self.index = index
        self.name = name
        self.ads_type = ads_type
        self.dn = dn
        self.schema_guid = schema_guid
        self.sec_guid = sec_guid
        self.syntax_id = 0        # AD Explorer "Syntax" column; resolved at finalize
        self.display_hint = 0


def _display_hint(name, syntax_id):
    """Display-format hint stored per property, as observed in snapshot files."""
    if syntax_id == 3:
        return 4
    if syntax_id == 4:
        if "Time" in name or "LastSet" in name or "Expires" in name or name.startswith("last"):
            return 3
        return 4
    if syntax_id == 14:
        return 2
    if "GUID" in name or "Guid" in name:
        return 1
    if "SID" in name or "Sid" in name:
        return 2
    return 0


class SnapshotWriter:
    """Streams objects to disk, then patches the header — same lifecycle as AD Explorer
    ("win-ad-XX" placeholder while writing, "win-ad-ob" once finalized)."""

    def __init__(self, path, server_name="", description="", schema=None,
                 naming_contexts=None, build_treeview=True, build_classes=True):
        self.path = path
        self.server_name = server_name
        self.description = description
        # schema: optional dict lname(lower) -> {"syntax": oid, "schemaIDGUID": 16 bytes,
        #         "attributeSecurityGUID": 16 bytes, "dn": str}
        self.schema = schema or {}
        # naming_contexts: ordered list of NC base DNs [domain, config, schema, ...] used to
        # build the GUI treeview region. None/empty -> emit the "unpopulated" marker (no tree).
        self.naming_contexts = list(naming_contexts or [])
        self.build_treeview = build_treeview
        self.build_classes = build_classes
        # Real per-forest schema captured from classSchema/attributeSchema objects during
        # enumeration (so LAPS/custom-class GUIDs are the actual ones, like genuine AD Explorer).
        self._collected_classes = {}    # className(lower) -> complete class-schema metadata
        self._collected_attr_guids = {} # attrName(lower) -> (schemaIDGUID, securityGUID, DN)
        self._collected_attr_syntax = {}  # attrName(lower) -> (attributeSyntax OID, oMSyntax int)
        self._collected_rights = {}     # name(lower) -> (name, displayName, GUID, validAccesses, appliesTo)
        self._class_display = {}        # class(lower) -> (class label, {attribute: label})
        self._props = {}          # name(lower) -> _Property
        self._prop_order = []     # _Property in index order
        self._dncache = {}        # norm(dn) -> absolute file offset of the object record
        self._dn_display = {}     # norm(dn) -> original DN string
        # Native AD Explorer stores the first occurrence of an encoded property value
        # inline, then points later identical encoded blocks back to it with a signed
        # relative offset. The native cache key is the complete block bytes, independent
        # of property index.
        self._value_cache = {}    # encoded block -> absolute offset
        self.num_objects = 0
        self.num_attributes = 0
        self.num_synthetic = 0
        self._fh = None
        # Native AD Explorer stamps the in-progress header once, at capture start,
        # and preserves that FILETIME when it patches the completed signature and
        # offsets.  Recomputing it in _finalize makes the header describe close time.
        self._capture_filetime = _filetime_now()

    # -- lifecycle ----------------------------------------------------------
    def __enter__(self):
        self._fh = open(self.path, "wb", buffering=1024 * 1024)
        self._fh.write(self._build_header(SIG_PROGRESS, 0, 0, 0, 0))  # placeholder
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._fh is None:
            return
        try:
            if exc_type is None:
                self._finalize()
        finally:
            self._fh.close()
            self._fh = None

    # -- property registry --------------------------------------------------
    def _resolve_ads_type(self, lname, sample_values):
        if lname in _NAME_OVERRIDES:
            return _NAME_OVERRIDES[lname]
        native = self._collected_attr_syntax.get(lname)
        if native:
            sid = SYNTAX_ID_BY_ADSYNTAX.get(native)
            if sid is not None:
                return ADSTYPE_BY_SYNTAX_ID[sid]
        info = self.schema.get(lname)
        if info and info.get("syntax") in _SYNTAX_TO_ADSTYPE:
            return _SYNTAX_TO_ADSTYPE[info["syntax"]]
        if lname in _KNOWN_INTEGER:
            return ADSTYPE_INTEGER
        if lname in _KNOWN_LARGEINT:
            return ADSTYPE_LARGE_INTEGER
        # Heuristic on the wire bytes: valid UTF-8 text -> string, else octet.
        for v in sample_values:
            try:
                v.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                return ADSTYPE_OCTET_STRING
        return ADSTYPE_CASE_IGNORE_STRING

    def _get_property(self, name, sample_values):
        lname = name.lower()
        prop = self._props.get(lname)
        if prop is not None:
            return prop
        ads_type = self._resolve_ads_type(lname, sample_values)
        info = self.schema.get(lname, {})
        dn = info.get("dn") or ""
        # The reader does DN.split(',')[0].split('=')[1] — guarantee a CN=... form.
        if "=" not in dn:
            dn = "CN=%s,CN=Schema,CN=Configuration" % name
        prop = _Property(
            index=len(self._prop_order),
            name=name,
            ads_type=ads_type,
            dn=dn,
            schema_guid=info.get("schemaIDGUID") or b"\x00" * 16,
            sec_guid=info.get("attributeSecurityGUID") or b"\x00" * 16,
        )
        self._props[lname] = prop
        self._prop_order.append(prop)
        return prop

    # -- value-block encoders ----------------------------------------------
    @staticmethod
    def _encode_values(ads_type, values):
        """values: list[bytes] (raw LDAP wire values). Returns the on-disk value block
        beginning with the uint32 numValues count."""
        n = len(values)
        out = bytearray(struct.pack("<I", n))
        if ads_type in _STRING_TYPES:
            # ADSI supplies NUL-terminated WCHAR strings. If an LDAP raw value
            # contains an embedded NUL, native AD Explorer stops there; retaining
            # a hidden suffix creates unreferenced bytes and shifts every later
            # object/metadata offset (observed with "DC01\0$" in
            # msDS-AdditionalSamAccountName).
            texts = [v.decode("utf-8", "replace").split("\x00", 1)[0]
                     for v in values]
            base = 4 + 4 * n
            data = bytearray()
            offs = []
            for t in texts:
                offs.append(base + len(data))
                data += _wstr(t)
            for o in offs:
                out += struct.pack("<I", o)
            out += data
        elif ads_type == ADSTYPE_OCTET_STRING:
            for v in values:
                out += struct.pack("<I", len(v))
            for v in values:
                out += v
        elif ads_type == ADSTYPE_NT_SECURITY_DESCRIPTOR:
            for v in values:
                out += struct.pack("<I", len(v))
            for v in values:
                out += v
        elif ads_type == ADSTYPE_BOOLEAN:
            for v in values:
                out += struct.pack("<I", 1 if v.strip().upper() == b"TRUE" else 0)
        elif ads_type == ADSTYPE_INTEGER:
            for v in values:
                out += struct.pack("<I", _to_int(v) & 0xFFFFFFFF)
        elif ads_type == ADSTYPE_LARGE_INTEGER:
            for v in values:
                iv = _to_int(v)
                # clamp into signed int64 range
                if iv < -(2 ** 63):
                    iv = -(2 ** 63)
                elif iv > 2 ** 63 - 1:
                    iv = 2 ** 63 - 1
                out += struct.pack("<q", iv)
        elif ads_type == ADSTYPE_UTC_TIME:
            for v in values:
                y, mo, d, h, mi, s = _parse_generalized_time(v)
                # SystemTime: wYear,wMonth,wDayOfWeek,wDay,wHour,wMinute,wSecond,wMs
                out += struct.pack("<8H", y, mo, 0, d, h, mi, s, 0)
        elif ads_type == ADSTYPE_DN_WITH_BINARY:
            parsed = [_split_dn_binary(v) for v in values]
            for raw, _dn in parsed:
                out += struct.pack("<I", len(raw))
            for raw, dn in parsed:
                out += raw + _wstr(dn)
        else:  # pragma: no cover - should not happen given the resolver
            # AD Explorer writes only numValues for unsupported structured ADS types,
            # including ADS_DN_WITH_STRING (28).
            pass
        return bytes(out)

    # -- object writing -----------------------------------------------------
    def add_object(self, attributes):
        """attributes: dict name -> list[bytes] (raw wire values). Empty attrs are skipped."""
        obj_off = self._fh.tell()
        mapping = []          # (attrIndex, encoded_value_block, is_distinguished_name)
        dn = None
        # AD Explorer writes ADsPath/distinguishedName manually as table entry zero,
        # then appends the enumerated columns. Do not depend on LDAP/dict ordering:
        # its GUI object path expects this native invariant when a tree item is opened.
        ordered = sorted(attributes.items(),
                         key=lambda item: item[0].lower() != "distinguishedname")
        for name, values in ordered:
            if not values:
                continue
            if dn is None and name.lower() == "distinguishedname":
                dn = values[0].decode("utf-8", "replace") if isinstance(values[0], bytes) else str(values[0])
            prop = self._get_property(name, values)
            # Syntax 2.5.5.7/oMSyntax 127 is advertised as ADS_OCTET_STRING in the
            # Property table, but native AD Explorer uses its DN-with-binary payload.
            native = self._collected_attr_syntax.get(name.lower())
            storage_type = (ADSTYPE_DN_WITH_BINARY
                            if native == ("2.5.5.7", 127) else prop.ads_type)
            block = self._encode_values(storage_type, values)
            mapping.append((prop.index, block, name.lower() == "distinguishedname"))

        table_size = len(mapping)
        header_len = 8 + table_size * 8      # objSize + tableSize + mapping table
        value_area = bytearray()
        table = bytearray()
        for attr_index, block, is_dn in mapping:
            # Native AD Explorer hashes the complete encoded block, independent of
            # property index. It can therefore reuse one positive local offset for
            # identical values on multiple properties in the same object. Its cache
            # evicts entries once the current write position is 1,000,000 bytes past
            # them; preserving that window is important to the GUI's mapped reader.
            current_abs = obj_off + header_len + len(value_area)
            # The native writer emits ADsPath/DN manually before enumerating the
            # remaining columns. That first value is neither looked up in nor added
            # to the shared value cache. In particular, defaultObjectCategory must
            # not alias a classSchema object's identical distinguishedName block.
            previous = None if is_dn else self._value_cache.get(block)
            reusable = (previous is not None and previous < current_abs
                        and current_abs - previous < 1_000_000)
            if reusable:
                attr_offset = previous - obj_off
            else:
                attr_offset = header_len + len(value_area)
                if not is_dn:
                    self._value_cache[block] = obj_off + attr_offset
                value_area += block
            table += struct.pack("<Ii", attr_index, attr_offset)

        obj = bytearray(struct.pack("<II", 0, table_size))
        obj += table
        obj += value_area
        struct.pack_into("<I", obj, 0, len(obj))   # objSize = total record length
        self._fh.write(obj)

        self.num_objects += 1
        # Current native AD Explorer snapshots exclude the per-object DN table row
        # from numAttributes even though that row is present in the object record.
        self.num_attributes += sum(
            1 for name, values in attributes.items()
            if values and name.lower() != "distinguishedname"
        )
        if dn:
            nd = _norm_dn(dn)
            self._dncache[nd] = obj_off
            self._dn_display.setdefault(nd, dn)
        if self.build_classes:
            self._capture_schema(attributes, dn)

    # -- schema capture (real forest schemaIDGUIDs for BloodHound) -----------
    @staticmethod
    def _attr_lookup(attributes, key):
        for k, v in attributes.items():
            if k.lower() == key and v:
                return v
        return None

    def _capture_schema(self, attributes, dn):
        """If this object is a classSchema/attributeSchema, record its real schemaIDGUID (so the
        Classes/Properties tables carry genuine per-forest GUIDs, incl. LAPS/custom) and, for
        attributes, its AD-native (attributeSyntax, oMSyntax) so we can fill the Property record's
        syntax_id / adsType the way genuine AD Explorer does."""
        oc = self._attr_lookup(attributes, "objectclass")
        if not oc:
            return
        ocset = {v.decode("utf-8", "ignore").lower() for v in oc}
        if "displayspecifier" in ocset:
            cn = self._text_attr(attributes, "cn")
            if cn.lower().endswith("-display"):
                cls = cn[:-8].lower()
                labels = {}
                for item in self._text_list(attributes, "attributedisplaynames"):
                    if "," in item:
                        attr, label = item.split(",", 1)
                        labels[attr.lower()] = label
                self._class_display[cls] = (
                    self._text_attr(attributes, "classdisplayname"), labels)
            return
        if "controlaccessright" in ocset:
            name = self._text_attr(attributes, "cn") or self._text_attr(attributes, "name")
            guid_text = self._text_attr(attributes, "rightsguid")
            try:
                guid = uuid.UUID(guid_text).bytes_le
            except (ValueError, AttributeError):
                return
            if name:
                self._collected_rights[name.lower()] = (
                    name,
                    self._text_attr(attributes, "displayname"),
                    guid,
                    self._int_attr(attributes, "validaccesses"),
                    self._text_list(attributes, "appliesto"),
                )
            return
        name = self._text_attr(attributes, "ldapdisplayname")
        if not name:
            return
        lname = name.lower()
        guid = self._attr_lookup(attributes, "schemaidguid")
        gbytes = bytes(guid[0]) if guid and len(guid[0]) == 16 else None
        if "classschema" in ocset and gbytes:
            self._collected_classes[lname] = {
                "guid": gbytes, "name": name, "dn": dn or ("CN=%s" % name),
                "common": "",
                "super": self._text_attr(attributes, "subclassof"),
                "attrs": self._text_list(attributes, "maycontain")
                         + self._text_list(attributes, "systemmaycontain")
                         + self._text_list(attributes, "mustcontain")
                         + self._text_list(attributes, "systemmustcontain"),
                "possible": self._text_list(attributes, "posssuperiors")
                            + self._text_list(attributes, "systemposssuperiors"),
                # LDAP multi-value order is not stable. AD Explorer's effective
                # class-property expansion follows the case-insensitive sorted
                # auxiliary-class list (the same order it serializes below).
                # This matters on Exchange-extended user/computer classes: using
                # wire order produces valid indices in the wrong blocks and can
                # destabilize Search Container result rendering.
                "aux": sorted(set(
                    self._text_list(attributes, "auxiliaryclass")
                    + self._text_list(attributes, "systemauxiliaryclass")
                ), key=str.casefold),
                "default_sd": _sddl_to_binary(
                    self._text_attr(attributes, "defaultsecuritydescriptor")),
            }
        if "attributeschema" in ocset:
            sec = self._attr_lookup(attributes, "attributesecurityguid")
            sbytes = bytes(sec[0]) if sec and len(sec[0]) == 16 else b"\x00" * 16
            if gbytes:
                self._collected_attr_guids[lname] = (gbytes, sbytes, dn or ("CN=%s" % name))
            asyn = self._attr_lookup(attributes, "attributesyntax")
            omsyn = self._attr_lookup(attributes, "omsyntax")
            if asyn and omsyn:
                try:
                    self._collected_attr_syntax[lname] = (
                        asyn[0].decode("ascii", "ignore").strip(),
                        int(omsyn[0].decode("ascii", "ignore").strip()),
                    )
                except (ValueError, AttributeError):
                    pass
            # AD Explorer's Properties table is the complete forest schema, not only
            # attributes encountered on returned objects. Metadata was preloaded before
            # object serialization, so this also fixes property indices and ADS types.
            prop = self._get_property(name, [b""])
            prop.dn = dn or prop.dn
            if gbytes:
                prop.schema_guid = gbytes
            prop.sec_guid = sbytes

    @classmethod
    def _text_attr(cls, attributes, key):
        vals = cls._attr_lookup(attributes, key)
        return vals[0].decode("utf-8", "replace") if vals else ""

    @classmethod
    def _text_list(cls, attributes, key):
        vals = cls._attr_lookup(attributes, key) or ()
        return [v.decode("utf-8", "replace") for v in vals]

    @classmethod
    def _int_attr(cls, attributes, key):
        vals = cls._attr_lookup(attributes, key)
        try:
            return int(vals[0]) if vals else 0
        except (ValueError, TypeError):
            return 0

    # -- finalize -----------------------------------------------------------
    def _schema_base(self):
        for base in self.naming_contexts:
            if base.lower().startswith("cn=schema,"):
                return base
        return "CN=Schema,CN=Configuration"

    def _apply_bloodhound_schema(self):
        """Give ACL-relevant properties their schemaIDGUID + canonical CN so BloodHound's
        objecttype_guid_map resolves them. Prefer REAL GUIDs/DNs collected from attributeSchema
        objects (covers LAPS/custom), fall back to forest-constant well-known values, and inject
        servicePrincipalName if absent (its map key is referenced UNGUARDED -> KeyError)."""
        if not self.build_classes:
            return
        base = self._schema_base()
        # 1. real GUIDs/DNs from collected attributeSchema objects (authoritative)
        for lname, (gbytes, sbytes, adn) in self._collected_attr_guids.items():
            prop = self._props.get(lname)
            if prop is not None:
                prop.schema_guid = gbytes
                prop.sec_guid = sbytes
                if adn and "=" in adn:
                    prop.dn = adn
        # 2. well-known fallback for the crash-critical / ACL attributes not collected
        for lname, (guidstr, cn) in WELLKNOWN_ATTR_GUIDS.items():
            prop = self._props.get(lname)
            if prop is None and lname == "serviceprincipalname":
                prop = self._get_property("servicePrincipalName", [b""])
            if prop is not None and lname not in self._collected_attr_guids:
                prop.schema_guid = uuid.UUID(guidstr).bytes_le
                prop.dn = "CN=%s,%s" % (cn, base)

    def _resolve_syntax_ids(self):
        """Fill each property's syntax_id (AD Explorer "Syntax" column) from the collected schema.
        Prefer the (attributeSyntax, oMSyntax) -> syntax_id pairing from the collected
        attributeSchema; when that syntax_id's adsType is encoding-compatible with how the values
        were already serialized, adopt the exact syntax_id + adsType. Otherwise (or with no AD-native
        syntax) derive a representative syntax_id from the already-encoded adsType so the column is
        never blank and stays consistent with the value blobs."""
        for p in self._prop_order:
            adsyn = self._collected_attr_syntax.get(p.name.lower())
            syntax_id = None
            if adsyn is not None:
                syntax_id = SYNTAX_ID_BY_ADSYNTAX.get(adsyn)
                if syntax_id is None:                       # OID known, oMSyntax variant unknown
                    syntax_id = next((v for (oid, _om), v in SYNTAX_ID_BY_ADSYNTAX.items()
                                      if oid == adsyn[0]), None)
            if syntax_id is not None:
                table_ads = ADSTYPE_BY_SYNTAX_ID.get(syntax_id, p.ads_type)
                if _encoding_family(table_ads) == _encoding_family(p.ads_type):
                    p.ads_type = table_ads                  # adopt exact schema adsType (same bytes)
                    p.syntax_id = syntax_id
                    p.display_hint = _display_hint(p.name, p.syntax_id)
                    continue
            # fallback: representative syntax_id for the adsType we actually encoded with
            p.syntax_id = SYNTAX_ID_BY_ADSTYPE.get(p.ads_type, 0)
            p.display_hint = _display_hint(p.name, p.syntax_id)

    def _build_properties_block(self):
        out = bytearray(struct.pack("<I", len(self._prop_order)))
        for p in self._prop_order:
            out += _lenprefixed(p.name)
            out += struct.pack("<iI", p.syntax_id, p.ads_type)   # syntax_id (GUI "Syntax") + adsType
            out += _lenprefixed(p.dn)
            out += (p.schema_guid + b"\x00" * 16)[:16]
            out += (p.sec_guid + b"\x00" * 16)[:16]
            out += struct.pack("<I", p.display_hint)
        return bytes(out)

    def _build_classes_block(self):
        """Build AD Explorer's class table from schema and DisplaySpecifiers metadata."""
        base = self._schema_base()
        # name(lower) -> complete class metadata
        classes = dict(self._collected_classes)
        for name, guidstr in WELLKNOWN_CLASS_GUIDS.items():
            classes.setdefault(name, {"guid": uuid.UUID(guidstr).bytes_le, "name": name,
                               "dn": "CN=%s,%s" % (name, base), "common": "", "super": "",
                               "attrs": [], "possible": [], "aux": [], "default_sd": b""})
        out = bytearray(struct.pack("<I", len(classes)))
        for lname, meta in classes.items():
            gbytes, display, dn = meta["guid"], meta["name"], meta["dn"]
            display_meta = self._class_display.get(lname, ("", {}))
            labels = self._class_display_labels(lname, classes)
            if "=" not in dn:
                dn = "CN=%s,%s" % (display, base)
            out += _lenprefixed(display)                               # className
            out += _lenprefixed(dn)                                    # DN (needs CN= for reader)
            out += _nullable_lenprefixed(display_meta[0] or meta["common"])
            out += _nullable_lenprefixed(meta["super"])
            out += (gbytes + b"\x00" * 16)[:16]                        # schemaIDGUID[16]
            default_sd = meta.get("default_sd", b"")
            out += struct.pack("<I", len(default_sd)) + default_sd
            attrs = self._class_attributes(lname, classes)
            attr_names = list(dict.fromkeys(
                a.lower() for a in attrs if a.lower() in self._props))
            blocks = [self._props[a].index for a in attr_names]
            out += struct.pack("<I", len(blocks))
            for index in blocks:
                prop_name = self._prop_order[index].name.lower()
                label = labels.get(prop_name, "")
                out += struct.pack("<I", index)
                out += _nullable_lenprefixed(label)
            extra = self._class_rights(lname, classes)
            out += struct.pack("<I", len(extra))
            out += b"".join(extra)
            possible = self._class_possible(lname, classes)
            out += struct.pack("<I", len(possible))
            for value in possible:
                out += _lenprefixed(value)
            aux = sorted(set(meta["aux"]), key=str.casefold)
            out += struct.pack("<I", len(aux))
            for value in aux:
                out += _lenprefixed(value)
        return bytes(out)

    def _class_attributes(self, lname, classes, seen=None):
        seen = set() if seen is None else seen
        if lname in seen or lname not in classes:
            return []
        seen.add(lname)
        meta = classes[lname]
        values = list(meta["attrs"])
        if meta["super"]:
            values += self._class_attributes(meta["super"].lower(), classes, seen)
        for aux in meta["aux"]:
            values += self._class_attributes(aux.lower(), classes, seen)
        values = list(dict.fromkeys(values))
        if lname == "domaindns":
            values = [value for value in values
                      if value.casefold() not in _DOMAIN_DNS_SEARCH_EXCLUSIONS]
        return values

    def _class_display_labels(self, lname, classes):
        """DisplaySpecifier labels inherit along subClassOf, as in AD Explorer."""
        labels = {}
        current, seen = lname, set()
        while current and current not in seen and current in classes:
            seen.add(current)
            for attr, label in self._class_display.get(current, ("", {}))[1].items():
                labels.setdefault(attr, label)
            current = classes[current]["super"].lower()
        return labels

    def _class_possible(self, lname, classes, seen=None):
        seen = set() if seen is None else seen
        if lname in seen or lname not in classes:
            return []
        seen.add(lname)
        meta = classes[lname]
        values = list(meta["possible"])
        if meta["super"]:
            values += self._class_possible(meta["super"].lower(), classes, seen)
        values.append("lostAndFound")
        return sorted(set(values), key=str.casefold)

    def _class_rights(self, lname, classes, seen=None):
        seen = set() if seen is None else seen
        if lname in seen or lname not in classes:
            return []
        seen.add(lname)
        meta = classes[lname]
        guids = []
        class_guid = str(uuid.UUID(bytes_le=meta["guid"])).lower()
        for _name, _display, right_guid, _valid, applies in self._collected_rights.values():
            if class_guid in {x.lower() for x in applies}:
                guids.append(right_guid)
        if meta["super"]:
            guids += self._class_rights(meta["super"].lower(), classes, seen)
        return list(dict.fromkeys(guids))

    def _build_rights_block(self):
        out = bytearray(struct.pack("<I", len(self._collected_rights)))
        for name, display, guid, valid, _applies in self._collected_rights.values():
            out += _lenprefixed(name) + _lenprefixed(display) + guid + struct.pack("<I", valid)
        return bytes(out)

    def _build_header(self, sig, num_objects, num_attributes, metadata_off, treeview_off):
        buf = bytearray(HEADER_SIZE)
        struct.pack_into("<10s", buf, 0, sig)
        struct.pack_into("<i", buf, 10, MARKER)
        struct.pack_into("<Q", buf, 14, self._capture_filetime)
        _pack_wchar_field(buf, 22, self.description, 260)
        _pack_wchar_field(buf, 542, self.server_name, 260)
        struct.pack_into("<I", buf, 1062, num_objects)
        struct.pack_into("<I", buf, 1066, num_attributes)
        struct.pack_into("<Q", buf, 1070, metadata_off)
        struct.pack_into("<Q", buf, 1078, treeview_off)
        return bytes(buf)

    def _finalize(self):
        self._apply_bloodhound_schema()                    # fix ACL property GUIDs before writing
        self._resolve_syntax_ids()                         # fill AD Explorer "Syntax" column

        # Native layout places tree-only synthetic ancestor objects immediately after
        # the counted directory objects, followed by an eight-byte zero sentinel. The
        # metadataOffset points after both. The tree itself is serialized after Rights.
        region = (self._build_treeview_region()
                  if (self.build_treeview and self.naming_contexts) else None)
        if region is not None:
            synthetic_data, region_bytes = region
            self._fh.write(synthetic_data)
            self._fh.write(b"\x00" * 8)
        else:
            region_bytes = None

        metadata_off = self._fh.tell()
        self._fh.write(self._build_properties_block())
        if self.build_classes:
            self._fh.write(self._build_classes_block())    # populated Classes table (BloodHound)
        else:
            self._fh.write(struct.pack("<I", 0))           # Classes: numClasses = 0
        self._fh.write(self._build_rights_block())

        if region_bytes is None:
            treeview_off = self._fh.tell()
            self._fh.write(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))  # unpopulated marker (no GUI tree)
        else:
            pad = (-self._fh.tell()) & 3                    # 4-byte align the region start
            if pad:
                self._fh.write(b"\x00" * pad)
            treeview_off = self._fh.tell()
            self._fh.write(region_bytes)

        # Patch the header in place: placeholder -> final.
        self._fh.seek(0)
        self._fh.write(
            self._build_header(
                SIG_COMPLETE, self.num_objects, self.num_attributes,
                metadata_off, treeview_off,
            )
        )
        self._fh.flush()

    # -- treeview (GUI navigation tree) -------------------------------------
    def _encode_dn_only_object(self, dn):
        """A minimal object record carrying only distinguishedName (used for synthetic
        ancestor containers that the GUI tree references but that weren't enumerated)."""
        prop = self._props.get("distinguishedname")
        if prop is None:
            prop = self._get_property("distinguishedName", [dn.encode("utf-8")])
        block = self._encode_values(prop.ads_type, [dn.encode("utf-8")])
        table = struct.pack("<Ii", prop.index, 16)         # attrIndex, attrOffset = 8 + 1*8
        obj = bytearray(struct.pack("<II", 0, 1)) + table + block
        struct.pack_into("<I", obj, 0, len(obj))
        return bytes(obj)

    def _build_treeview_region(self):
        """Build (synthetic_object_bytes, region_bytes) for the treeview region.

        Region = one uniform recursive node format (matching the layout observed in
        snapshot files): the region root (objectOffset sentinel 0xFFFFFFFFFFFFFFFE)
        whose container children are the naming contexts; every node references its object
        by ABSOLUTE file offset and its container children by NODE-RELATIVE byte deltas.
        """
        nc_norms = []
        for base in self.naming_contexts:
            nd = _norm_dn(base)
            if nd not in nc_norms:
                nc_norms.append(nd)
                self._dn_display.setdefault(nd, base)

        # children[parent_norm] is an insertion-ordered set of child DNs. Native
        # tree order follows discovery order, not lexical order.
        children = {}
        for nd, dn in list(self._dn_display.items()):
            base = self._which_nc(nd, nc_norms)
            if base is None:
                continue
            cur_dn, cur_nd = dn, nd
            while cur_nd != base:
                p_dn = _parent_dn(cur_dn)
                if not p_dn:
                    break
                p_nd = _norm_dn(p_dn)
                self._dn_display.setdefault(p_nd, p_dn)
                children.setdefault(p_nd, {}).setdefault(cur_nd, None)
                cur_dn, cur_nd = p_dn, p_nd

        # Synthesize any node without a real object (missing container / stub NC root).
        # Every node references its object by ABSOLUTE offset, so region placement is
        # position-independent; _finalize handles the 4-byte alignment of the region start.
        synth = bytearray()
        base_off = self._fh.tell()                         # directly after counted objects
        visited = set()

        def synthesize_preorder(nd):
            if nd in visited:
                return
            visited.add(nd)
            if nd not in self._dncache:
                self._dncache[nd] = base_off + len(synth)
                synth.extend(self._encode_dn_only_object(self._dn_display.get(nd, nd)))
                self.num_synthetic += 1
            for child in children.get(nd, {}):
                synthesize_preorder(child)

        for nd in nc_norms:
            synthesize_preorder(nd)

        def offset_of(nd):
            return self._dncache[nd]

        def split(nd):
            kids = list(children.get(nd, ()))
            conts = [k for k in kids if children.get(k)]
            leaves = [k for k in kids if not children.get(k)]
            return conts, leaves

        def emit(object_offset, cont_children, leaf_children):
            A, B = len(cont_children), len(leaf_children)
            header_size = 16 + 4 * A + 8 * B
            blobs = []
            for c in cont_children:
                cc, cl = split(c)
                blobs.append(emit(offset_of(c), cc, cl))
            rels, cur = [], header_size
            for b in blobs:
                rels.append(cur)
                cur += len(b)
            out = bytearray(struct.pack("<Q", object_offset))
            out += struct.pack("<II", A, B)
            for rel in rels:
                out += struct.pack("<I", rel)              # node-relative container child offset
            for c in leaf_children:
                out += struct.pack("<Q", offset_of(c))     # absolute leaf object offset
            for b in blobs:
                out += b
            return bytes(out)

        import sys as _sys
        _sys.setrecursionlimit(max(10000, _sys.getrecursionlimit()))
        region_bytes = emit(0xFFFFFFFFFFFFFFFE, nc_norms, [])
        return bytes(synth), region_bytes

    @staticmethod
    def _which_nc(nd, nc_norms):
        """Return the longest NC base (normalized) that nd falls under, else None."""
        best, best_len = None, -1
        for b in nc_norms:
            if (nd == b or nd.endswith("," + b)) and len(b) > best_len:
                best, best_len = b, len(b)
        return best


def _pack_wchar_field(buf, offset, text, max_chars):
    raw = (text or "").encode("utf-16-le", "replace")
    raw = raw[: (max_chars - 1) * 2]                       # leave room for a NUL
    struct.pack_into("<%ds" % len(raw), buf, offset, raw)  # rest of the field stays zero


def _to_int(v):
    try:
        return int(v.decode("ascii", "ignore").strip() or "0")
    except (ValueError, AttributeError):
        return 0


def _split_dn_binary(value):
    """Convert LDAP's B:<hex-char-count>:<hex>:<DN> representation."""
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    if not text.startswith("B:"):
        # ADSI still exposes schema syntax 21 as ADS_DN_WITH_BINARY when the LDAP
        # wire value is a bare DN rather than B:<hexlen>:<hex>:<DN>. Its native
        # fallback places the first four WCHARs (8 bytes) in BinaryValue and the
        # remaining WCHARs in DNString. Reproduce that odd but observable layout;
        # emitting a zero-length binary prefix differs from AD Explorer and can
        # make its value renderer walk the wrong representation.
        return text[:4].encode("utf-16-le"), text[4:]
    try:
        _tag, count, rest = text.split(":", 2)
        digits = int(count)
        hexpart, dn = rest[:digits], rest[digits + 1:]
        return bytes.fromhex(hexpart), dn
    except (ValueError, IndexError):
        return b"", text


def _filetime_now():
    # Windows FILETIME: 100-ns ticks since 1601-01-01 UTC.
    return int((time.time() + 11644473600) * 10_000_000)


def _split_rdns(dn):
    """Split a DN into RDNs on unescaped commas."""
    parts, cur, esc = [], [], False
    for ch in dn:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == ",":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _parent_dn(dn):
    """DN with its first RDN removed ('' at the top)."""
    rdns = _split_rdns(dn)
    return ",".join(rdns[1:]) if len(rdns) > 1 else ""


def _norm_dn(dn):
    """Normalize a DN for parent/child/NC matching: strip per-RDN whitespace + casefold."""
    return ",".join(p.strip() for p in _split_rdns(dn)).casefold()


def _parse_generalized_time(v):
    """LDAP GeneralizedTime 'YYYYMMDDHHMMSS[.f]Z' -> (y, mo, d, h, mi, s), validated so the
    reader's datetime() never raises. Falls back to 1601-01-01 on garbage."""
    import datetime as _dt
    try:
        s = v.decode("ascii", "ignore") if isinstance(v, bytes) else str(v)
    except Exception:
        return (1601, 1, 1, 0, 0, 0)
    s = s.strip()
    try:
        y, mo, d = int(s[0:4]), int(s[4:6]), int(s[6:8])
        h = int(s[8:10]) if len(s) >= 10 else 0
        mi = int(s[10:12]) if len(s) >= 12 else 0
        sec = int(s[12:14]) if len(s) >= 14 else 0
        if sec > 59:
            sec = 59
        _dt.datetime(y, mo, d, h, mi, sec)   # validate (raises on impossible dates)
        return (y, mo, d, h, mi, sec)
    except (ValueError, IndexError):
        return (1601, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# Pacer implements AD Explorer's single speed percentage. It targets the requested
# active-work/elapsed-time ratio over a rolling window; 100 performs no sleeping.
# ---------------------------------------------------------------------------
class Pacer:
    def __init__(self, percent=100):
        self.percent = int(percent)
        self._work_ms = 0.0
        self._window_start = self._now()
        self._row_start = self._window_start

    @staticmethod
    def _now():
        return time.monotonic() * 1000.0

    @property
    def active(self):
        return self.percent < 100

    def describe(self):
        return "full speed" if self.percent == 100 else "%d%% speed" % self.percent

    def before_object(self):
        self._row_start = self._now()

    def after_object(self):
        if not self.active:
            return
        now = self._now()
        self._work_ms += now - self._row_start
        delay = 100.0 * self._work_ms / self.percent - (now - self._window_start)
        if delay > 0:
            time.sleep(min(delay, 10000.0) / 1000.0)
        if self._now() - self._window_start > 30000.0:
            self._work_ms = 0.0
            self._window_start = self._now()


# ---------------------------------------------------------------------------
# LDAP collection (lazy import of ldap3 so the writer/verifier need no deps)
# ---------------------------------------------------------------------------
def _sd_flags_control_value(flags):
    # BER: SEQUENCE { INTEGER flags }
    return b"\x30\x03\x02\x01" + bytes([flags & 0xFF])


def collect(args):
    try:
        import ldap3
    except ImportError:
        sys.exit("error: the 'ldap3' package is required for collection.\n"
                 "       install it with:  pip install ldap3   (+ 'gssapi' for --kerberos)")

    port = args.port or (636 if args.ssl else 389)
    connect_host = args.dc_ip or args.dc
    # DSA fetches RootDSE/server capabilities without downloading the complete schema.
    # _preload_metadata performs the authoritative schema queries once below.
    server = ldap3.Server(connect_host, port=port, use_ssl=args.ssl, get_info=ldap3.DSA,
                          connect_timeout=args.timeout)

    conn = _bind(ldap3, server, args)
    # Authentication is complete (auto_bind=True); discard our remaining plaintext references.
    args.password = None
    try:
        conn.password = None
    except Exception:
        pass
    tgt = "" if connect_host == args.dc else " (target %s)" % args.dc
    _print("[+] Bound to %s:%d%s (%s)" % (connect_host, port, tgt, conn.authentication))

    contexts = _resolve_contexts(server)
    if not contexts:
        sys.exit("error: could not determine any naming context to snapshot.")
    server_name = _server_dns(server) or args.dc
    search_filter = SNAPSHOT_QUERIES[args.query]
    attrs = SNAPSHOT_ATTRIBUTES
    controls = [
        (OID_SD_FLAGS, True, _sd_flags_control_value(SD_FLAGS_OWNER_GROUP_DACL)),
        (OID_SHOW_DELETED, True, None),
    ]
    pacer = Pacer(args.speed)

    _print("[+] Naming contexts: %s" % ", ".join(contexts))
    _print("[+] Snapshot query: %s = %s" % (args.query, search_filter))
    _print("[+] Attributes: *, objectClass, ntSecurityDescriptor | deleted objects: yes | scope: SUBTREE")
    _print("[+] Network: timeout %ds | page size %d | %s"
          % (args.timeout, args.page_size, pacer.describe()))

    t0 = time.time()
    try:
        with SnapshotWriter(args.output, server_name=server_name,
                            description=args.description,
                            naming_contexts=contexts, build_treeview=True,
                            build_classes=True) as writer:
            _preload_metadata(conn, ldap3, server, writer, args.page_size)
            # Native file order is Schema, Configuration, then the domain NC. Keep
            # naming_contexts unchanged because it also determines GUI root order.
            for base in reversed(contexts):
                _print("[*] Enumerating %s ..." % base)
                n_before = writer.num_objects
                pages = _paged_search(conn, ldap3, base, search_filter, attrs, args.page_size,
                                      controls, writer, pacer)
                print("    -> %d objects from this context (%d pages)"
                      % (writer.num_objects - n_before, pages))

            n_obj = writer.num_objects
            n_attr = writer.num_attributes
            n_prop = len(writer._prop_order)
            n_syn = writer.num_synthetic
    finally:
        conn.unbind()
    dt = time.time() - t0
    size = os.path.getsize(args.output)
    rate = (n_obj / dt) if dt > 0 else 0.0
    _print("[+] Wrote %s  (%d objects, %d attribute-values, %d properties, %d bytes, %.1fs, %.0f obj/s)"
          % (args.output, n_obj, n_attr, n_prop, size, dt, rate))
    _print("[+] Treeview: populated for GUI (%d naming contexts, %d synthetic containers)"
          % (len(contexts), n_syn))
    _print("[+] Schema classes and searchable properties: populated")
    _print("[+] Verify with:  python3 %s verify %s"
          % (os.path.basename(__file__), args.output))


PAGED_RESULT_OID = "1.2.840.113556.1.4.319"


def _advertised_context(server, key):
    values = (getattr(server.info, "other", {}) or {}).get(key)
    if isinstance(values, (list, tuple)):
        return str(values[0]) if values else None
    return str(values) if values else None


def _preload_metadata(conn, ldap3, server, writer, page_size):
    """Load schema classes/attributes and extended rights before object encoding.

    AD Explorer performs these dedicated searches too. Preloading is important: it fixes
    Property indices and ADS types before the first directory object is serialized.
    """
    schema_nc = _advertised_context(server, "schemaNamingContext")
    config_nc = _advertised_context(server, "configurationNamingContext")
    queries = []
    if schema_nc:
        queries.append((schema_nc, "(|(objectClass=attributeSchema)(objectClass=classSchema))", [
            "distinguishedName", "objectClass", "lDAPDisplayName", "schemaIDGUID",
            "attributeSecurityGUID", "attributeSyntax", "oMSyntax",
            "subClassOf", "mustContain", "systemMustContain", "mayContain", "systemMayContain",
            "possSuperiors", "systemPossSuperiors", "auxiliaryClass", "systemAuxiliaryClass",
            "defaultSecurityDescriptor",
        ]))
    if config_nc:
        queries.append(("CN=Extended-Rights," + config_nc,
                        "(objectClass=controlAccessRight)", [
            "distinguishedName", "objectClass", "cn", "name", "displayName",
            "rightsGuid", "validAccesses", "appliesTo",
        ]))
        queries.append(("CN=409,CN=DisplaySpecifiers," + config_nc,
                        "(objectClass=displaySpecifier)", [
            "distinguishedName", "objectClass", "cn", "classDisplayName",
            "attributeDisplayNames",
        ]))
    for base, search_filter, attributes in queries:
        cookie = None
        while True:
            if not conn.search(search_base=base, search_filter=search_filter,
                               search_scope=ldap3.SUBTREE, attributes=attributes,
                               paged_size=page_size, paged_cookie=cookie):
                raise RuntimeError("metadata search failed at %s: %s" % (base, conn.result))
            for entry in conn.response or ():
                if entry.get("type") == "searchResEntry":
                    attrs = _entry_attributes(entry)
                    dnvals = SnapshotWriter._attr_lookup(attrs, "distinguishedname")
                    dn = (dnvals[0].decode("utf-8", "replace") if dnvals
                          else entry.get("dn", ""))
                    writer._capture_schema(attrs, dn)
            ctrls = (conn.result or {}).get("controls") or {}
            cookie = ((ctrls.get(PAGED_RESULT_OID) or {}).get("value") or {}).get("cookie")
            if not cookie:
                break
    _print("[+] Metadata: %d attribute definitions, %d classes, %d extended rights"
          % (len(writer._collected_attr_syntax), len(writer._collected_classes),
             len(writer._collected_rights)))


def _paged_search(conn, ldap3, base, search_filter, attrs, page_size, controls,
                  writer, pacer):
    """Manual cookie paging, retaining only one server page in memory."""
    cookie = None
    pages = 0
    while True:
        if not conn.search(search_base=base, search_filter=search_filter,
                           search_scope=ldap3.SUBTREE, attributes=attrs,
                           paged_size=page_size, paged_cookie=cookie, controls=controls):
            raise RuntimeError("snapshot search failed at %s: %s" % (base, conn.result))
        pages += 1
        for entry in conn.response or ():
            if entry.get("type") != "searchResEntry":
                continue  # skip referrals (searchResRef)
            if pacer.active:
                pacer.before_object()
                writer.add_object(_entry_attributes(entry))
                pacer.after_object()
            else:
                writer.add_object(_entry_attributes(entry))
            if writer.num_objects % 500 == 0:
                print("    %d objects..." % writer.num_objects)
        ctrls = (conn.result or {}).get("controls") or {}
        cookie = ((ctrls.get(PAGED_RESULT_OID) or {}).get("value") or {}).get("cookie")
        if not cookie:
            break
    return pages


def _set_ntlm_workstation(name):
    """Override the source hostname (Workstation field) ldap3 puts in the NTLM AUTHENTICATE
    message. ldap3 has no API for this; it reads socket.gethostname() from its ntlm module, so
    we patch that module global. Effective against DCs that negotiate NTLM VERSION (i.e. Windows)."""
    try:
        import ldap3.utils.ntlm as _ntlm
        _ntlm.gethostname = lambda: name
        return True
    except Exception:
        return False


def _bind(ldap3, server, args):
    # Follow AD's attribute;range=N-M continuation responses so large multi-valued
    # attributes (notably group membership) are not silently truncated.
    common = dict(auto_bind=True, raise_exceptions=True, receive_timeout=args.timeout,
                  auto_range=True, auto_referrals=False)
    # Kerberos SPN target: when connecting by IP (--dc-ip), the SPN must still be ldap/<--dc>.
    krb_creds = None
    if args.dc and not _looks_like_ip(args.dc):
        krb_creds = (args.dc,)

    if args.kerberos or args.username is None:
        if _looks_like_ip(args.dc):
            _print("[!] Kerberos by IP fails SPN validation; set --dc to the DC FQDN "
                  "(add --dc-ip to still connect by address)")
        return ldap3.Connection(server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS,
                                sasl_credentials=krb_creds, **common)
    if args.auth == "simple":
        user = args.username
        if args.domain and "@" not in user and "\\" not in user:
            user = "%s@%s" % (user, args.domain)
        return ldap3.Connection(server, user=user, password=args.password,
                                authentication=ldap3.SIMPLE, **common)
    # NTLM (default for username/password — signed, no cleartext, no TLS needed)
    if args.workstation:
        if _set_ntlm_workstation(args.workstation):
            suffix = (" (generated default; set --workstation NAME for a stable, auditable value)"
                      if getattr(args, "workstation_generated", False) else "")
            _print("[+] NTLM source hostname (Workstation): %s%s" % (args.workstation, suffix))
        else:
            _print("[!] Could not set the NTLM Workstation field; continuing without override")
    domain = args.domain or ""
    user = args.username
    if "\\" not in user:
        user = "%s\\%s" % (domain, user)
    return ldap3.Connection(server, user=user, password=args.password,
                            authentication=ldap3.NTLM, **common)


def _looks_like_ip(host):
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _resolve_contexts(server):
    info = server.info
    other = getattr(info, "other", {}) or {}

    def first(key):
        v = other.get(key)
        if isinstance(v, (list, tuple)):
            return str(v[0]) if v else None
        return str(v) if v else None

    default_nc = first("defaultNamingContext") or first("rootDomainNamingContext")
    config_nc = first("configurationNamingContext")
    schema_nc = first("schemaNamingContext")
    contexts = [default_nc, config_nc, schema_nc]
    missing = [name for name, value in zip(("domain", "configuration", "schema"), contexts)
               if not value]
    if missing:
        sys.exit("error: DC did not advertise required naming context(s): %s"
                 % ", ".join(missing))
    return list(dict.fromkeys(contexts))


def _server_dns(server):
    other = getattr(server.info, "other", {}) or {}
    v = other.get("dnsHostName") or other.get("dNSHostName")
    if isinstance(v, (list, tuple)):
        return str(v[0]) if v else None
    return str(v) if v else None


def _prepare_ticket(path, requested_type="auto"):
    """Return (absolute ccache path, temporary_path_or_None).

    MIT ccache files are usable directly. A KRB-CRED/kirbi is converted to a mode-0600
    temporary ccache with Impacket and removed by main() after the LDAP session ends.
    """
    if path.upper().startswith("FILE:"):
        path = path[5:]
    path = os.path.abspath(os.path.expanduser(path))
    try:
        with open(path, "rb") as fh:
            ticket_data = fh.read()
    except OSError as exc:
        raise RuntimeError("cannot read Kerberos ticket %s: %s" % (path, exc)) from exc

    prefix = ticket_data[:2]
    is_ccache = len(prefix) == 2 and prefix[0] == 0x05 and 1 <= prefix[1] <= 4
    if requested_type == "ccache" and not is_ccache:
        raise RuntimeError("%s is not an MIT ccache file" % path)
    if requested_type == "kirbi" and is_ccache:
        raise RuntimeError("%s is a ccache, not a KRB-CRED/kirbi file" % path)
    kind = "ccache" if (requested_type == "ccache" or
                         (requested_type == "auto" and is_ccache)) else "kirbi"
    if kind == "ccache":
        return path, None

    # A binary KRB-CRED is DER APPLICATION 22 (tag 0x76). Text files may contain
    # standard Base64 with arbitrary ASCII whitespace/line wrapping.
    kirbi_data = ticket_data
    if not kirbi_data.startswith(b"\x76"):
        compact = b"".join(ticket_data.split())
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if not decoded.startswith(b"\x76"):
            raise RuntimeError(
                "%s is neither an MIT ccache nor a binary/Base64 KRB-CRED" % path)
        kirbi_data = decoded

    try:
        from impacket.krb5.ccache import CCache
    except ImportError as exc:
        raise RuntimeError(
            "kirbi support requires Impacket: python3 -m pip install impacket") from exc

    fd, temporary = tempfile.mkstemp(prefix="adexsnap-ticket-", suffix=".ccache")
    os.close(fd)
    os.chmod(temporary, 0o600)
    try:
        ccache = CCache()
        ccache.fromKRBCRED(kirbi_data)
        ccache.saveFile(temporary)
    except Exception as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise RuntimeError("failed to convert kirbi ticket: %s" % exc) from exc
    return temporary, temporary


def _validate_krb5ccname(value):
    """Validate file-backed KRB5CCNAME values; leave collection backends to GSSAPI."""
    if not value:
        return
    if value.upper().startswith("FILE:"):
        path = os.path.abspath(os.path.expanduser(value[5:]))
        if not os.path.isfile(path):
            raise RuntimeError("KRB5CCNAME file does not exist: %s" % path)
        if not os.access(path, os.R_OK):
            raise RuntimeError("KRB5CCNAME file is not readable: %s" % path)
        with open(path, "rb") as fh:
            prefix = fh.read(2)
        if len(prefix) != 2 or prefix[0] != 0x05 or not 1 <= prefix[1] <= 4:
            raise RuntimeError("KRB5CCNAME FILE is not an MIT ccache: %s" % path)


def _entry_attributes(entry):
    """Return dict name -> list[bytes] from an ldap3 paged_search entry, ensuring
    distinguishedName is present."""
    raw = dict(entry.get("raw_attributes") or {})
    result = {}
    for name, values in raw.items():
        result[name] = [v if isinstance(v, bytes) else bytes(v) for v in values]
    if not any(k.lower() == "distinguishedname" for k in result):
        dn = entry.get("dn")
        if dn:
            result["distinguishedName"] = [dn.encode("utf-8")]
    return result


# ---------------------------------------------------------------------------
# Verifier / re-parser (pure stdlib; mirrors ADExplorerSnapshot.py parsing)
# ---------------------------------------------------------------------------
class _Reader:
    def __init__(self, fh):
        self.fh = fh

    def u32(self):
        return struct.unpack("<I", self.fh.read(4))[0]

    def i32(self):
        return struct.unpack("<i", self.fh.read(4))[0]

    def i64(self):
        return struct.unpack("<q", self.fh.read(8))[0]

    def wstr_at(self, pos):
        self.fh.seek(pos)
        out = bytearray()
        while True:
            b = self.fh.read(2)
            if len(b) < 2 or b == b"\x00\x00":
                break
            out += b
        return out.decode("utf-16-le", "replace")


def verify(path, dump=0):
    with open(path, "rb") as fh:
        r = _Reader(fh)
        head = fh.read(HEADER_SIZE)
        if len(head) < HEADER_SIZE:
            sys.exit("error: file smaller than a header")
        sig = head[0:10]
        marker = struct.unpack_from("<i", head, 10)[0]
        num_objects = struct.unpack_from("<I", head, 1062)[0]
        num_attributes = struct.unpack_from("<I", head, 1066)[0]
        metadata_off = struct.unpack_from("<Q", head, 1070)[0]
        treeview_off = struct.unpack_from("<Q", head, 1078)[0]
        server = head[542:1062].decode("utf-16-le", "replace").rstrip("\x00")

        ok_sig = sig == SIG_COMPLETE
        print("signature       : %r  (%s)" % (sig, "complete" if ok_sig else "IN-PROGRESS/BAD"))
        print("marker          : 0x%08x  (%s)" % (marker, "ok" if marker == MARKER else "BAD"))
        print("server          : %s" % server)
        print("numObjects      : %d" % num_objects)
        print("numAttributes   : %d" % num_attributes)
        print("metadataOffset  : %d" % metadata_off)
        print("treeviewOffset  : %d" % treeview_off)

        # Properties
        fh.seek(metadata_off)
        num_props = r.u32()
        props = []
        syntax_ids = {}
        blank_syntax = 0
        for _ in range(num_props):
            ln = r.u32()
            name = fh.read(ln).decode("utf-16-le", "replace").rstrip("\x00")
            syntax_id = r.i32()
            ads_type = r.u32()
            lndn = r.u32()
            dn = fh.read(lndn).decode("utf-16-le", "replace").rstrip("\x00")
            fh.read(16); fh.read(16); fh.read(4)
            props.append((name, ads_type, dn, syntax_id))
            syntax_ids[name.lower()] = syntax_id
            if syntax_id == 0 and ads_type != 0:
                blank_syntax += 1
            # replicate the reader's CN split to catch DN crashes early
            try:
                dn.split(",")[0].split("=")[1]
            except IndexError:
                sys.exit("error: property %r has DN %r without CN=; reader would crash" % (name, dn))
        # Classes (parsed per the reference grammar so Rights stays aligned)
        num_classes = r.u32()
        class_names = []
        class_issues = []
        cls_ok = True
        for _ in range(num_classes):
            nm = _read_class_entry(r, num_props=num_props, limit=treeview_off,
                                   errors=class_issues)
            if nm is None:
                cls_ok = False
                break
            class_names.append(nm)
        num_rights = r.u32() if cls_ok else -1
        rights_ok = cls_ok
        if rights_ok:
            try:
                for _ in range(num_rights):
                    fh.read(r.u32())
                    fh.read(r.u32())
                    if len(fh.read(20)) != 20:
                        raise struct.error("short right record")
            except struct.error:
                rights_ok = False
        print("numProperties   : %d  (syntax set: %d, blank: %d)"
              % (num_props, num_props - blank_syntax, blank_syntax))
        print("numClasses      : %d%s" % (num_classes, "" if cls_ok else "  (PARSE ERROR)"))
        for issue in class_issues[:10]:
            _print("   [!] class metadata: %s" % issue)
        print("numRights       : %s" % (num_rights if num_rights >= 0 else "(unparsed)"))
        # Check the class names BloodHound needs for objecttype_guid_map
        have = {c.lower() for c in class_names}
        need = {"group", "user", "computer", "domain"}
        missing = need - have
        if num_classes and missing:
            _print("   [!] Classes missing BloodHound entrytypes: %s" % ", ".join(sorted(missing)))

        # Objects
        dn_index = next((i for i, (nm, _t, _d, _s) in enumerate(props)
                         if nm.lower() == "distinguishedname"), None)
        fh.seek(HEADER_SIZE)
        decoded = 0
        total_values = 0
        counted_attributes = 0
        counted_dns = 0
        negative_refs = 0
        excessive_refs = 0
        dn_not_first = 0
        max_backref = 0
        objects_ok = True
        samples = []
        for i in range(num_objects):
            obj_start = fh.tell()
            obj_size = r.u32()
            table_size = r.u32()
            if obj_size < 8 + table_size * 8 or obj_start + obj_size > metadata_off:
                _print("   [!] invalid object %d size/table at %d" % (i, obj_start))
                objects_ok = False
                break
            table = [(r.u32(), r.i32()) for _ in range(table_size)]
            if (dn_index is not None and table
                    and any(index == dn_index for index, _off in table)
                    and table[0][0] != dn_index):
                dn_not_first += 1
                objects_ok = False
            attrs = {}
            has_dn = False
            for attr_index, attr_off in table:
                if attr_index >= num_props:
                    sys.exit("error: object %d references property %d >= %d"
                             % (i, attr_index, num_props))
                name, ads_type, _dn, syntax_id = props[attr_index]
                value_pos = obj_start + attr_off
                if not (HEADER_SIZE <= value_pos < metadata_off):
                    _print("   [!] object %d has out-of-range value offset %d" % (i, attr_off))
                    objects_ok = False
                    continue
                negative_refs += attr_off < 0
                if attr_off < 0:
                    max_backref = max(max_backref, -attr_off)
                if attr_off <= -1_000_000:
                    excessive_refs += 1
                    objects_ok = False
                has_dn |= name.lower() == "distinguishedname"
                try:
                    vals = _decode_value(r, value_pos, ads_type, name, syntax_id)
                except (ValueError, struct.error) as exc:
                    _print("   [!] object %d property %s has invalid value block: %s"
                          % (i, name, exc))
                    objects_ok = False
                    continue
                total_values += 1
                if dump and len(samples) < dump:
                    attrs[name] = vals
            decoded += 1
            counted_attributes += table_size
            counted_dns += int(has_dn)
            if dump and len(samples) < dump:
                samples.append((obj_start, attrs))
            fh.seek(obj_start + obj_size)

        print("objects decoded : %d/%d  (%s)"
              % (decoded, num_objects, "OK" if decoded == num_objects else "MISMATCH"))
        print("attr-values read: %d" % total_values)
        print("negative refs   : %d" % negative_refs)
        if negative_refs:
            print("backref span   : %d bytes maximum" % max_backref)
        if excessive_refs:
            _print("   [!] %d back-references exceed AD Explorer's 1,000,000-byte window"
                  % excessive_refs)
        if dn_not_first:
            _print("   [!] %d objects do not store distinguishedName as table entry zero"
                  % dn_not_first)
        count_including_dn = counted_attributes
        count_excluding_dn = counted_attributes - counted_dns
        if num_attributes == count_excluding_dn:
            count_ok = True
            count_note = "OK; header excludes %d distinguishedName rows" % counted_dns
        elif num_attributes == count_including_dn:
            count_ok = True
            count_note = "OK; header includes distinguishedName"
        else:
            count_ok = False
            count_note = "header says %d; excluding DN gives %d" % (
                num_attributes, count_excluding_dn)
        print("attribute count : %d  (%s)" % (counted_attributes, count_note))

        # Treeview / GUI navigation region
        file_size = os.fstat(fh.fileno()).st_size
        tv_ok, tv_roots = True, []
        if treeview_off and treeview_off + 8 <= file_size:
            fh.seek(treeview_off)
            magic = struct.unpack("<Q", fh.read(8))[0]
            if magic == 0xFFFFFFFFFFFFFFFE:
                stats = {"nodes": 0, "containers": 0, "leaves": 0, "errors": []}
                _, tv_roots = _walk_treeview(r, treeview_off, treeview_off, file_size,
                                             props, dn_index, stats, set())
                tv_ok = not stats["errors"]
                print("treeview        : POPULATED  (%d nodes, %d containers, %d leaves, %s)"
                      % (stats["nodes"], stats["containers"], stats["leaves"],
                         "OK" if tv_ok else "%d ERRORS" % len(stats["errors"])))
                for e in stats["errors"][:5]:
                    print("   tv error: %s" % e)
            elif magic == 0xFFFFFFFFFFFFFFFF:
                print("treeview        : UNPOPULATED (GUI tree empty; regenerate without --no-treeview)")
            else:
                print("treeview        : UNKNOWN magic 0x%016x" % magic)

        ok = (ok_sig and marker == MARKER and decoded == num_objects and objects_ok and count_ok
              and tv_ok and cls_ok and rights_ok and (not num_classes or not missing))
        _print("RESULT          : %s" % ("PASS" if ok else "FAIL"))

        for lbl in tv_roots[:8]:
            print("   NC root: %s" % lbl)
        for obj_start, attrs in samples:
            print("\n--- object @%d ---" % obj_start)
            for name, vals in list(attrs.items())[:20]:
                shown = [_pp(v) for v in vals[:3]]
                more = "" if len(vals) <= 3 else " (+%d)" % (len(vals) - 3)
                print("  %-30s %s%s" % (name, shown, more))
        return 0 if ok else 1


def _read_class_string(r, limit):
    """Read the exact nullable length-prefixed WCHAR field used in class records."""
    fh = r.fh
    length = r.u32()
    if length == 0:
        return ""
    if length < 2 or length & 1 or fh.tell() + length > limit:
        raise ValueError("invalid WCHAR length %d at %d" % (length, fh.tell() - 4))
    raw = fh.read(length)
    if not raw.endswith(b"\0\0"):
        raise ValueError("unterminated WCHAR field at %d" % (fh.tell() - length))
    return raw[:-2].decode("utf-16-le", "strict")


def _read_class_entry(r, num_props=None, limit=None, errors=None):
    """Parse one Class record per the reference grammar; returns className or None on error."""
    fh = r.fh
    limit = limit if limit is not None else os.fstat(fh.fileno()).st_size
    errors = errors if errors is not None else []
    start = fh.tell()
    try:
        name = _read_class_string(r, limit)
        dn = _read_class_string(r, limit)
        _read_class_string(r, limit)            # commonClassName
        _read_class_string(r, limit)            # subClassOf
        if not name or not dn or "=" not in dn:
            raise ValueError("class %r has unusable DN %r" % (name, dn))
        if fh.tell() + 16 > limit:
            raise ValueError("short schema GUID")
        fh.read(16)                            # schemaIDGUID
        sd_len = r.u32()
        if fh.tell() + sd_len > limit:
            raise ValueError("security descriptor overruns metadata")
        fh.read(sd_len)
        block_count = r.u32()
        if block_count > (num_props if num_props is not None else 100000):
            raise ValueError("impossible attribute count %d" % block_count)
        for _ in range(block_count):
            prop_index = r.u32()
            if num_props is not None and prop_index >= num_props:
                raise ValueError("property index %d >= %d" % (prop_index, num_props))
            _read_class_string(r, limit)        # per-class display label
        rights_count = r.u32()
        if rights_count > 100000 or fh.tell() + rights_count * 16 > limit:
            raise ValueError("invalid class-right count %d" % rights_count)
        fh.read(rights_count * 16)
        possible_count = r.u32()
        if possible_count > 100000:
            raise ValueError("invalid possible-superior count %d" % possible_count)
        for _ in range(possible_count):
            _read_class_string(r, limit)
        auxiliary_count = r.u32()
        if auxiliary_count > 100000:
            raise ValueError("invalid auxiliary-class count %d" % auxiliary_count)
        for _ in range(auxiliary_count):
            _read_class_string(r, limit)
        return name
    except (struct.error, ValueError, UnicodeDecodeError) as exc:
        errors.append("record at %d: %s" % (start, exc))
        return None


def _read_object_dn(r, off, props, dn_index):
    """Decode distinguishedName of the object record at absolute offset `off`."""
    if dn_index is None:
        return None
    fh = r.fh
    fh.seek(off)
    try:
        _obj_size = r.u32()
        table_size = r.u32()
        if table_size > 100000:
            return None
        table = [(r.u32(), r.i32()) for _ in range(table_size)]
    except struct.error:
        return None
    for attr_index, attr_off in table:
        if attr_index == dn_index and attr_index < len(props):
            _nm, ads_type, _dn, syntax_id = props[attr_index]
            vals = _decode_value(r, off + attr_off, ads_type, "distinguishedName", syntax_id)
            return vals[0] if vals else None
    return None


def _walk_treeview(r, node_pos, region_start, file_size, props, dn_index, stats, seen):
    """Recurse the treeview exactly like the binary reader (u64 objectOffset@0, u32 A@8,
    u32 B@12, u32 childOffsets[A] node-relative, u64 leafOffsets[B] absolute). Validates
    bounds/cycles and resolves each node/leaf's DN. Returns (own_dn, [child_dn,...])."""
    fh = r.fh
    if node_pos in seen:
        stats["errors"].append("cycle at node %d" % node_pos)
        return None, []
    seen.add(node_pos)
    stats["nodes"] += 1
    fh.seek(node_pos)
    obj_off = struct.unpack("<Q", fh.read(8))[0]
    a = struct.unpack("<I", fh.read(4))[0]
    b = struct.unpack("<I", fh.read(4))[0]
    if a > 1_000_000 or b > 1_000_000:
        stats["errors"].append("insane child counts A=%d B=%d at %d" % (a, b, node_pos))
        return None, []
    child_rels = [struct.unpack("<I", fh.read(4))[0] for _ in range(a)]
    leaf_offs = [struct.unpack("<Q", fh.read(8))[0] for _ in range(b)]

    own = None
    if obj_off != 0xFFFFFFFFFFFFFFFE:
        if HEADER_SIZE <= obj_off < region_start:
            own = _read_object_dn(r, obj_off, props, dn_index)
        else:
            stats["errors"].append("node objectOffset %d out of range" % obj_off)

    child_labels = []
    for rel in child_rels:
        cpos = node_pos + rel
        if not (region_start <= cpos < file_size and cpos > node_pos):
            stats["errors"].append("container child rel %d out of range at node %d" % (rel, node_pos))
            continue
        stats["containers"] += 1
        lbl, _ = _walk_treeview(r, cpos, region_start, file_size, props, dn_index, stats, seen)
        child_labels.append(lbl)
    for lo in leaf_offs:
        if not (HEADER_SIZE <= lo < region_start):
            stats["errors"].append("leaf objectOffset %d out of range" % lo)
            continue
        stats["leaves"] += 1
        child_labels.append(_read_object_dn(r, lo, props, dn_index))
    return own, child_labels


def _decode_value(r, pos, ads_type, name, syntax_id=None):
    fh = r.fh
    fh.seek(pos)
    n = r.u32()
    out = []
    if ads_type in _STRING_TYPES:
        offs = [r.u32() for _ in range(n)]
        for o in offs:
            out.append(r.wstr_at(pos + o))
    elif ads_type == ADSTYPE_OCTET_STRING and syntax_id == 21:
        # This syntax is labelled OCTET_STRING in metadata but has the same
        # native payload as ADS_DN_WITH_BINARY.
        lens = [r.u32() for _ in range(n)]
        for ln in lens:
            remaining = os.fstat(fh.fileno()).st_size - fh.tell()
            if ln > remaining:
                raise ValueError("DN-binary length %d exceeds %d remaining bytes"
                                 % (ln, remaining))
            raw = fh.read(ln)
            if raw.startswith(b"B:"):
                raise ValueError("raw LDAP B:<length>:<hex>:<DN> text was not converted")
            chars = bytearray()
            while True:
                pair = fh.read(2)
                if pair in (b"", b"\x00\x00"):
                    break
                chars += pair
            out.append((raw, chars.decode("utf-16-le", "replace")))
    elif ads_type == ADSTYPE_OCTET_STRING:
        lens = [r.u32() for _ in range(n)]
        for ln in lens:
            b = fh.read(ln)
            if len(b) == 16 and name.lower().endswith("guid"):
                out.append(str(uuid.UUID(bytes_le=b)))
            else:
                out.append(b)
    elif ads_type == ADSTYPE_NT_SECURITY_DESCRIPTOR:
        lens = [r.u32() for _ in range(n)]
        for ln in lens:
            out.append(fh.read(ln))
    elif ads_type == ADSTYPE_BOOLEAN:
        for _ in range(n):
            out.append(bool(r.u32()))
    elif ads_type == ADSTYPE_INTEGER:
        for _ in range(n):
            out.append(r.u32())
    elif ads_type == ADSTYPE_LARGE_INTEGER:
        for _ in range(n):
            out.append(r.i64())
    elif ads_type == ADSTYPE_UTC_TIME:
        import calendar, datetime as _dt
        for _ in range(n):
            y, mo, dow, d, h, mi, s, ms = struct.unpack("<8H", fh.read(16))
            out.append(calendar.timegm(_dt.datetime(y, mo, d, h, mi, s).timetuple()))
    elif ads_type == ADSTYPE_DN_WITH_BINARY:
        lens = [r.u32() for _ in range(n)]
        for ln in lens:
            raw = fh.read(ln)
            chars = bytearray()
            while True:
                pair = fh.read(2)
                if pair in (b"", b"\x00\x00"):
                    break
                chars += pair
            out.append((raw, chars.decode("utf-16-le", "replace")))
    elif ads_type == ADSTYPE_DN_WITH_STRING:
        out.extend(["<ADS_DN_WITH_STRING has no serialized payload>"] * n)
    else:
        out.append("<unhandled adsType %d>" % ads_type)
    return out


def _pp(v):
    if isinstance(v, bytes):
        return v[:24].hex() + ("..." if len(v) > 24 else "")
    s = str(v)
    return s if len(s) <= 60 else s[:57] + "..."


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _default_workstation_name():
    """Return the shape Windows uses for automatically named desktop hosts."""
    return "DESKTOP-" + uuid.uuid4().hex[:7].upper()


def _timestamped_output_path(path):
    directory, filename = os.path.split(path)
    stem, extension = os.path.splitext(filename)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = os.path.join(directory, "%s-%s%s" % (stem, stamp, extension))
    suffix = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, "%s-%s-%d%s" % (stem, stamp, suffix, extension))
        suffix += 1
    return candidate


def _add_color_options(parser):
    color = parser.add_mutually_exclusive_group()
    color.add_argument("--color", choices=("auto", "always", "never"), metavar="WHEN",
                       help="color output: auto, always, or never (default: auto)")
    color.add_argument("--no-color", dest="color", action="store_const", const="never",
                       help="disable ANSI colors (same as --color never)")
    parser.set_defaults(color="auto")


def _bounded_int(label, minimum, maximum):
    def parse(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("%s must be an integer" % label) from exc
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(
                "%s must be between %d and %d" % (label, minimum, maximum))
        return number
    return parse


def build_parser():
    p = argparse.ArgumentParser(
        prog="adexsnap.py",
        description="Create an Active Directory snapshot in the AD Explorer .dat format.",
        epilog="""The default query matches the filter AD Explorer uses for a full snapshot:
  filter       --query native = (objectGUID=*)
  contexts     domain + Configuration + Schema
  attributes   * + objectClass (explicit) + ntSecurityDescriptor
  controls     deleted objects + owner/group/DACL security data
  metadata     complete schema Properties + Classes + DisplaySpecifiers + Extended Rights

Commands:
  adexsnap.py snapshot ...   collect a complete snapshot
  adexsnap.py verify FILE    validate a snapshot without a DC
  adexsnap.py queries        print every supported full-snapshot filter

Recommended NTLM capture (password prompt):
  adexsnap.py snapshot --dc dc.example.com --dc-ip 192.0.2.10 \\
      -u auditor -d EXAMPLE -o snapshot.dat

The password is prompted without echo when -p is omitted. Avoid -p because command-line
passwords may be retained by shell history and visible to other local processes.

Current Kerberos cache:
  export KRB5CCNAME=FILE:/path/auditor.ccache
  adexsnap.py snapshot --dc dc.example.com -k -o snapshot.dat

Validate the result:
  adexsnap.py verify snapshot.dat

Performance defaults:
  --page-size 1000 is the normal AD server maximum and recommended default.
  --speed 100 adds no delay. Lower values intentionally sleep between objects.
  --timeout applies to connecting and waiting for each LDAP network response.

Use 'adexsnap.py snapshot --help' for authentication, ticket, LDAPS, and tuning
examples. Output names receive a timestamp suffix unless --force is specified.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command")

    snap = sub.add_parser(
        "snapshot", help="connect to a DC and write a full .dat snapshot",
        description="Collect a full-scope snapshot and write it in the AD Explorer .dat format.",
        epilog="""Fixed capture settings:
  default:      --query native = (objectGUID=*)
  contexts:     domain, Configuration, Schema
  attributes:   *, objectClass (explicit), ntSecurityDescriptor
  controls:     deleted objects and owner/group/DACL security data
  metadata:     complete schema properties, classes, DisplaySpecifiers and Extended Rights

Recommended: --page-size 1000 --speed 100 --timeout 30
Lower --speed only reduces load; it does not change snapshot contents.
Run 'adexsnap.py queries' to list equivalent full-snapshot filters.
Omit -p to keep the password out of command history and process arguments.
When --workstation is omitted for NTLM, a DESKTOP-XXXXXXX value is generated. Set it
explicitly when a stable, recognizable audit value is preferred.

Examples:
  # NTLM, non-echoing password prompt, connect to a fixed IP
  adexsnap.py snapshot --dc dc01.example.com --dc-ip 192.0.2.10 \\
      -u auditor -d EXAMPLE --workstation AUDIT01 -o snapshot.dat

  # Simple bind is permitted only with LDAPS
  adexsnap.py snapshot --dc dc01.example.com --ssl --auth simple \\
      -u auditor@example.com -o snapshot.dat

  # Existing default Kerberos cache
  export KRB5CCNAME=FILE:/path/user.ccache
  adexsnap.py snapshot --dc dc01.example.com -k -o snapshot.dat

  # Explicit raw ccache, or auto-detected ccache/raw/Base64 kirbi
  adexsnap.py snapshot --dc dc01.example.com --ccache user.ccache -o snapshot.dat
  adexsnap.py snapshot --dc dc01.example.com --ticket ticket.bin -o snapshot.dat

  # Explicit raw or Base64 kirbi (requires Impacket for conversion)
  adexsnap.py snapshot --dc dc01.example.com --kirbi ldap.kirbi -o snapshot.dat

  # Lower server load; pacing is not a stealth guarantee
  adexsnap.py snapshot --dc dc01.example.com -u auditor -d EXAMPLE \\
      --page-size 999 --speed 50 --timeout 60 -o snapshot.dat

There is no native all-traffic SOCKS option: GSSAPI may use DNS and contact a KDC outside
ldap3. Use a system-level TUN/VPN when every connection must traverse one route.
Colors default to auto; use --no-color (or --color never) for plain logs.
Output names receive a timestamp suffix unless --force is specified.""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    snap.add_argument("--dc", required=True, help="DC hostname/FQDN (or IP) — the logical target "
                      "used for the Kerberos SPN and the snapshot header")
    snap.add_argument("--dc-ip", dest="dc_ip", help="IP address to actually connect to (when --dc "
                      "is a name that won't resolve, or to force a specific host); --dc stays the "
                      "SPN/header name")
    snap.add_argument("--workstation", help="source hostname in the NTLM bind; defaults to a "
                      "generated DESKTOP-XXXXXXX name. Set this explicitly for stable audit logs")
    snap.add_argument("-o", "--output", required=True, help="snapshot .dat filename to write")
    snap.add_argument("-u", "--username", help="username (omit to use current Kerberos ticket)")
    snap.add_argument("-p", "--password",
                      help="password (not recommended: omit to use the non-echoing prompt)")
    snap.add_argument("-d", "--domain", help="NETBIOS/DNS domain for the user")
    snap.add_argument("--auth", choices=["ntlm", "simple"], default="ntlm",
                      help="auth for username/password (default: ntlm; use simple only over --ssl)")
    snap.add_argument("-k", "--kerberos", action="store_true",
                      help="use GSSAPI Kerberos; credential precedence is explicit ticket, "
                           "KRB5CCNAME, then the system default cache")
    ticket = snap.add_mutually_exclusive_group()
    ticket.add_argument("--ticket", metavar="PATH",
                        help="auto-detect a raw ccache or raw/Base64 KRB-CRED file; implies Kerberos")
    ticket.add_argument("--ccache", metavar="PATH",
                        help="use a raw MIT FILE ccache (PATH or FILE:PATH); implies Kerberos")
    ticket.add_argument("--kirbi", metavar="PATH",
                        help="convert a raw or Base64 kirbi/KRB-CRED file to a temporary ccache")
    snap.add_argument("--query", choices=tuple(SNAPSHOT_QUERIES), default="native",
                      metavar="MODE", help="equivalent full-snapshot LDAP filter mode "
                                           "(default: native; run 'queries' for details)")

    perf = snap.add_argument_group("network and performance")
    perf.add_argument("--timeout", type=_bounded_int("timeout", 1, 3600), default=30,
                      metavar="SECONDS", help="connect and LDAP-response timeout (1..3600; default: 30)")
    perf.add_argument("--page-size", type=_bounded_int("page size", 1, 1000), default=1000,
                      metavar="ENTRIES", help="LDAP entries per page (1..1000; recommended: 1000)")
    perf.add_argument("--speed", type=_bounded_int("speed", 1, 100), default=100,
                      metavar="PERCENT", help="capture speed (1..100; 100 = no throttling)")

    snap.add_argument("--ssl", action="store_true", help="use LDAPS (port 636)")
    snap.add_argument("--port", type=_bounded_int("port", 1, 65535),
                      help="override LDAP port (1..65535)")
    snap.add_argument("--description", default="", help="snapshot description string")
    snap.add_argument("--force", action="store_true",
                      help="use the exact output name and allow replacing an existing file")
    _add_color_options(snap)

    v = sub.add_parser(
        "verify", help="parse and validate a .dat snapshot (no DC needed)",
        description="Parse the complete snapshot and validate AD Explorer-sensitive structures.",
        epilog="""Examples:
  adexsnap.py verify snapshot.dat
  adexsnap.py verify snapshot.dat --dump 3

PASS returns exit status 0; FAIL returns 1. --dump prints the first N decoded objects and is
intended for diagnosis, not for exporting the directory.""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    v.add_argument("path", help="snapshot .dat file")
    v.add_argument("--dump", type=int, default=0, metavar="N",
                   help="decode and print the first N objects' attributes")
    _add_color_options(v)

    queries = sub.add_parser(
        "queries", help="list equivalent full-snapshot LDAP filters",
        description="List filters usable with snapshot --query.",
        epilog="""Example:
  adexsnap.py queries
  adexsnap.py snapshot --dc dc01.example.com -u auditor -d EXAMPLE \\
      --query native -o snapshot.dat

Query variants are for interoperability and detection testing; they do not promise reduced
logging. Scope, controls, attributes, metadata, and encoding remain unchanged.""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_color_options(queries)
    return p


def list_queries():
    print("Equivalent full-snapshot LDAP filters\n")
    width = max(map(len, SNAPSHOT_QUERIES))
    for name, ldap_filter in SNAPSHOT_QUERIES.items():
        suffix = (_paint("  (AD Explorer native; recommended)", "green")
                  if name == "native" else "")
        print("  %-*s  %s%s" % (width, name, ldap_filter, suffix))
    print("\nOnly the equivalent filter expression changes. Contexts, attributes, controls,\n"
          "metadata, paging, and snapshot encoding remain identical.")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    _configure_color(getattr(args, "color", "auto"))
    if args.command == "snapshot":
        selected_ticket = args.ticket or args.ccache or args.kirbi
        requested_type = "ccache" if args.ccache else "kirbi" if args.kirbi else "auto"
        temporary_ticket = None
        previous_ccache = os.environ.get("KRB5CCNAME")
        args.kerberos = bool(args.kerberos or selected_ticket or args.username is None)
        args.workstation_generated = False
        if not args.kerberos and args.auth == "ntlm" and not args.workstation:
            args.workstation = _default_workstation_name()
            args.workstation_generated = True
        if selected_ticket:
            try:
                ccache_path, temporary_ticket = _prepare_ticket(selected_ticket, requested_type)
            except RuntimeError as exc:
                sys.exit("error: %s" % exc)
            os.environ["KRB5CCNAME"] = "FILE:" + ccache_path
            _print("[+] Kerberos credential: %s%s"
                  % (requested_type if requested_type != "auto" else
                     ("ccache" if temporary_ticket is None else "kirbi -> temporary ccache"),
                     " (removed after use)" if temporary_ticket else ""))
        elif args.kerberos:
            try:
                _validate_krb5ccname(previous_ccache)
            except RuntimeError as exc:
                sys.exit("error: %s" % exc)
            if previous_ccache:
                _print("[+] Kerberos credential: KRB5CCNAME=%s" % previous_ccache)
            else:
                _print("[+] Kerberos credential: system default cache (KRB5CCNAME is not set)")
        if not args.kerberos and args.auth == "simple" and not args.ssl:
            sys.exit("error: --auth simple requires --ssl; use NTLM or Kerberos otherwise")
        if not args.kerberos and args.username and args.password is None:
            import getpass
            args.password = getpass.getpass("Password: ")
        if not args.force:
            args.output = _timestamped_output_path(args.output)
        elif os.path.exists(args.output):
            _print("[!] Replacing existing output: %s" % args.output)
        try:
            return collect(args) or 0
        finally:
            if selected_ticket:
                if previous_ccache is None:
                    os.environ.pop("KRB5CCNAME", None)
                else:
                    os.environ["KRB5CCNAME"] = previous_ccache
            if temporary_ticket:
                try:
                    os.unlink(temporary_ticket)
                except OSError:
                    pass
    if args.command == "verify":
        return verify(args.path, dump=args.dump)
    if args.command == "queries":
        return list_queries()
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
