# adexsnap

Active Directory snapshots from Linux and macOS, in the AD Explorer `.dat` format.

adexsnap collects a full Active Directory snapshot from the command line and writes it in the
`.dat` format used by Sysinternals AD Explorer. The resulting file can be opened in AD Explorer
and is also supported by ADExplorerSnapshot.py and BOFHound.

The writer includes directory objects, schema and class metadata, extended rights, security
descriptors, value back-references, and the tree index used for navigation. The built-in
verifier checks the finished file before you open it or give it to another tool.

This project is not affiliated with or endorsed by Microsoft or Sysinternals. AD Explorer is
a Microsoft product; the snapshot format was implemented from analysis of snapshot files.

Only use this against directories you are authorized to enumerate. A snapshot can contain
ACLs, credentials-related metadata, and other sensitive information from the directory.

## Authorized and defensive use

For penetration testing and red-team work, obtain written authorization, define the target
scope, and agree how snapshots will be stored and destroyed before collecting. For blue-team
work, use the tool to validate directory exposure, compare authorized captures over time, and
exercise LDAP/Kerberos detections in a lab or approved assessment. The tool is for collection
and analysis; it does not bypass authorization or make enumeration invisible.

Treat every `.dat` file as sensitive: store it encrypted, restrict access to the engagement
team, and delete it when the retention period ends. The `.gitignore` excludes `.dat`,
`.ccache`, `.kirbi`, and `.keytab` files so they are not committed by accident.

## Requirements

- Python 3.10 or newer
- `ldap3`
- `winacl`
- `pycryptodome` for NTLM support on Python versions without built-in MD4
- a platform GSSAPI provider when using Kerberos (`gssapi` on most Linux/macOS systems)
- `impacket` only when converting a kirbi/KRB-CRED file

## Installation

```bash
python3 -m venv env
source env/bin/activate
python3 -m pip install -r requirements.txt

# Optional: Kerberos (gssapi) and kirbi/KRB-CRED conversion (impacket)
python3 -m pip install -r requirements-optional.txt
```

The base requirements are enough for NTLM, simple bind, and `verify`. The optional file adds
`gssapi` for Kerberos and `impacket` for kirbi conversion; install only the one you need if
you prefer:

```bash
python3 -m pip install gssapi      # Kerberos with a ccache
python3 -m pip install impacket    # kirbi/KRB-CRED input
```

The verifier does not need the LDAP collection dependencies, so it can also be used on a
machine that cannot build the collection stack. On minimal systems, install the operating
system's Kerberos development/runtime packages before installing `gssapi`.

The project is developed and tested on macOS and Linux with Python 3.10 or newer. Windows is
not currently part of the tested support matrix; the file format and LDAP logic are intended
to be portable, but Kerberos/GSSAPI setup is platform-specific.

## Quick start

NTLM prompts for the password without echoing it:

```bash
python3 adexsnap.py snapshot \
  --dc dc01.example.com --dc-ip 192.0.2.10 \
  -u auditor -d EXAMPLE --workstation AUDIT01 -o example.dat
```

Kerberos uses the current credential cache:

```bash
export KRB5CCNAME=FILE:/absolute/path/auditor.ccache
python3 adexsnap.py snapshot \
  --dc dc01.example.com --dc-ip 192.0.2.10 --kerberos -o example.dat
```

Check the result:

```bash
python3 adexsnap.py verify example.dat
```

`--dc` is the logical DC name. It is stored in the snapshot header and is also used for the
Kerberos `ldap/<dc>` SPN. `--dc-ip` is only the address used for the network connection. Keep
the FQDN in `--dc` when connecting to a fixed IP with Kerberos.

## Connecting to a DC

Use the normal DNS name when it resolves:

```bash
python3 adexsnap.py snapshot \
  --dc dc01.example.com -u auditor -d EXAMPLE -o example.dat
```

If DNS is unavailable, keep the name for the SPN and supply the address separately:

```bash
python3 adexsnap.py snapshot \
  --dc dc01.example.com --dc-ip 192.0.2.10 \
  -u auditor -d EXAMPLE -o example.dat
```

For LDAPS, use `--ssl` (port 636 by default). `--port` can override the LDAP port:

```bash
python3 adexsnap.py snapshot \
  --dc dc01.example.com --ssl -u auditor -d EXAMPLE -o example.dat
```

The default settings are `--page-size 1000`, `--speed 100`, and `--timeout 30`. To add
delays and request smaller pages, for example:

```bash
python3 adexsnap.py snapshot \
  --dc dc01.example.com -u auditor -d EXAMPLE \
  --page-size 500 --speed 50 --timeout 60 -o example.dat
```

Changing page size or speed changes request timing; it is not a promise of reduced logging or
detected activity.

## Authentication

### NTLM

Use `-u USER -d DOMAIN` and leave out `-p` to get a password prompt. The `--workstation`
value is sent as NTLM authentication metadata. It does not rename the local computer. If it
is omitted, adexsnap generates a Windows-style `DESKTOP-XXXXXXX` value for that run.

Avoid `-p` where possible because command-line arguments can remain in shell history and may
be visible in the local process list.

### Kerberos

Credential sources are checked in this order:

1. `--ticket`, `--ccache`, or `--kirbi`
2. `KRB5CCNAME`
3. the platform's default credential cache

Examples:

```bash
# MIT FILE ccache; both PATH and FILE:PATH are accepted
python3 adexsnap.py snapshot \
  --dc dc01.example.com --ccache /absolute/path/user.ccache -o example.dat

# Raw ccache, raw DER kirbi, or Base64 KRB-CRED detected automatically
python3 adexsnap.py snapshot \
  --dc dc01.example.com --ticket ticket.bin -o example.dat

# Explicit kirbi/KRB-CRED; requires Impacket
python3 adexsnap.py snapshot \
  --dc dc01.example.com --kirbi ldap-ticket.kirbi -o example.dat
```

`KRB5CCNAME` should keep its normal `TYPE:residual` form, such as `FILE:`, `DIR:`, or
`KCM:`. A kirbi is converted to a temporary mode-`0600` ccache and removed after the LDAP
session. The input ticket file is not changed.

Useful checks before a capture:

```bash
printf '%s\n' "$KRB5CCNAME"
klist
```

### Simple bind

Simple bind is accepted only over LDAPS:

```bash
python3 adexsnap.py snapshot \
  --dc dc01.example.com --ssl --auth simple \
  -u auditor@example.com -o example.dat
```

## SOCKS5 and network routing

There is currently no `--socks5` option. `ldap3` does not provide a supported proxy setting
for this workflow, and adding a socket monkey-patch would only cover the LDAP TCP connection.
Kerberos/GSSAPI may separately resolve names and contact a KDC, so an apparent SOCKS option
could give a false impression that all traffic was proxied.

When every connection must use the same route, use a system-level TUN/VPN or a process-level
wrapper that has been tested with both Python and the host Kerberos libraries. If a cache
already contains the exact LDAP service ticket, a KDC connection may not be needed, but DNS
and LDAP still need to use the intended route.

## What gets collected

The capture includes:

- the domain, Configuration, and Schema naming contexts
- objects from those contexts in the order AD Explorer expects
- normal attributes plus `objectClass` and `ntSecurityDescriptor`
- deleted objects using the Show Deleted control
- owner, group, and DACL security information (not SACLs)
- schema attributes and classes, DisplaySpecifiers, and Extended Rights
- the populated AD Explorer tree index

The default filter is `(objectGUID=*)`, matching AD Explorer's capture query. Use
`python3 adexsnap.py queries` to see the available equivalent filter variants:

```bash
python3 adexsnap.py snapshot ... --query native
```

The variants change only the filter. Scope, controls, attributes, metadata, paging, and file
encoding stay the same.

## Output and verification

The collector writes one LDAP page at a time and uses a 1 MiB file buffer. It loads the
metadata it needs before serializing directory objects, then finalizes the file only after all
queries succeed. A failed capture leaves the `win-ad-XX` signature, which the verifier will
reject as an incomplete snapshot.

```bash
python3 adexsnap.py verify example.dat
python3 adexsnap.py verify example.dat --dump 3
```

`RESULT: PASS` means the file's structural checks passed. It does not prove that the directory
stayed unchanged during enumeration. Two captures can differ because of replication, volatile
attributes, timestamps, or writes made while they were collected. Compare decoded content,
not just file sizes or hashes.

A successful verification looks like this (counts will differ between directories):

```text
signature       : b'win-ad-ob\x00'  (complete)
objects decoded : 3691/3691  (OK)
treeview        : POPULATED  (..., OK)
RESULT          : PASS
```

Output color defaults to `auto` and is disabled for redirected output. Use `--no-color`,
`--color never`, or `NO_COLOR=1` for plain logs.

Output names receive a `YYYYMMDD-HHMMSS` suffix by default. If a file with that timestamp
already exists, a counter is added. Use `--force` when you deliberately want the exact output
name and are prepared to replace an existing file:

```bash
python3 adexsnap.py snapshot --dc dc01.example.com \
  -u auditor -d EXAMPLE -o example.dat --force
```

See [LICENSE](LICENSE) for licensing terms.

## Troubleshooting

| Problem | What to check |
|---|---|
| `ldap3 package is required` | Activate the intended environment and install `requirements.txt`. |
| `winacl is not installed` | Install `winacl`; verification alone does not need it. |
| Kerberos fails when `--dc` is an IP | Put the DC FQDN in `--dc` and its address in `--dc-ip`. |
| `KRB5CCNAME file does not exist` | Use an absolute `FILE:/path/cache` or pass `--ccache`. |
| kirbi conversion asks for Impacket | Install `impacket`, or provide a ccache instead. |
| `--auth simple requires --ssl` | Add `--ssl`, or use NTLM/Kerberos. |
| Bind timeout | Check DNS, routing, firewall rules, port, TLS, and `--timeout`. |
| Naming contexts are missing | Confirm the endpoint is an AD DS RootDSE and the account can read it. |
| The file retains `win-ad-XX` | The capture stopped before finalization; rerun from the beginning. |
| AD Explorer cannot navigate the file | Run `verify` and do not use a file that returns `FAIL`. |
| Two captures differ | Check replication and volatile attributes; compare decoded content. |

For a useful bug report, keep the console output, the command with secrets removed, Python and
dependency versions, verifier output, and the smallest non-sensitive reproduction.

## Interoperability notes

Snapshots produced by this tool open in AD Explorer and are parsed by ADExplorerSnapshot.py
and BOFHound. AD Explorer is sensitive to record ordering, DN placement, value-cache offsets,
metadata offsets, and the tree index, and the serializer and verifier account for these
details. If a future AD Explorer release changes the format, run `verify` and open an issue
with the version that stopped working.

Trust graph output requires real `trustedDomain` objects and correctly encoded trust
attributes. Likewise, BOFHound/BloodHound output depends on the source directory containing
the relevant product-specific objects and security descriptors; the snapshot writer cannot
invent missing SCCM, PKI, trust, or other directory data.

## Development

Run the test suite with:

```bash
python3 -m unittest -v
```

The tests cover snapshot parsing and validation, CLI options, authentication inputs, and
ticket conversion helpers.
