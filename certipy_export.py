#!/usr/bin/env python3
"""Convert an adexsnap/AD Explorer snapshot into Certipy offline input."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import struct
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


REGISTRY_KEY = (
    r"HKEY_USERS\.DEFAULT\Software\Microsoft\Cryptography"
    r"\CertificateTemplateCache"
)

# Certipy maps the cache value names on the right back to the LDAP names on
# the left. The final item controls how the value is represented in a .reg file.
REGISTRY_FIELDS: Tuple[Tuple[str, str, str], ...] = (
    ("displayName", "DisplayName", "string"),
    ("pKIExpirationPeriod", "ValidityPeriod", "filetime"),
    ("pKIOverlapPeriod", "RenewalOverlap", "filetime"),
    ("msPKI-Enrollment-Flag", "msPKI-Enrollment-Flag", "dword"),
    ("msPKI-Private-Key-Flag", "msPKI-Private-Key-Flag", "dword"),
    ("msPKI-Certificate-Name-Flag", "msPKI-Certificate-Name-Flag", "dword"),
    ("msPKI-Certificate-Policy", "msPKI-Certificate-Policy", "multi"),
    ("msPKI-Minimal-Key-Size", "msPKI-Minimal-Key-Size", "dword"),
    ("msPKI-RA-Signature", "msPKI-RA-Signature", "dword"),
    ("msPKI-Template-Schema-Version", "msPKI-Template-Schema-Version", "dword"),
    (
        "msPKI-RA-Application-Policies",
        "msPKI-RA-Application-Policies",
        "multi",
    ),
    ("pKIExtendedKeyUsage", "ExtKeyUsageSyntax", "multi"),
    ("nTSecurityDescriptor", "Security", "binary"),
)

SNAPSHOT_ATTRIBUTES = {
    "objectClass",
    "name",
    "cn",
    "distinguishedName",
    "objectSid",
    "certificateTemplates",
    *(field[0] for field in REGISTRY_FIELDS),
}


@dataclass
class ExportMetadata:
    snapshot: str
    registry_output: str
    domain: str
    domain_sid: Optional[str]
    ca_name: str
    ca_names: List[str]
    published: List[str]
    owned_sids: List[str]
    template_count: int
    templates_without_security_descriptor: List[str]
    published_templates_missing_from_snapshot: List[str]
    used_published_union: bool


def _normalise_object(obj: Dict[str, List[object]]) -> Dict[str, List[object]]:
    return {name.casefold(): values for name, values in obj.items()}


def _values(obj: Dict[str, List[object]], name: str) -> List[object]:
    value = obj.get(name.casefold(), [])
    return value if isinstance(value, list) else [value]


def _collapse(values: List[object]) -> object:
    if not values:
        return []
    if len(values) == 1:
        return values[0]
    return values


def _as_strings(value: object) -> List[str]:
    if value is None or value == []:
        return []
    values = value if isinstance(value, list) else [value]
    result = []
    for item in values:
        if isinstance(item, bytes):
            result.append(item.decode("utf-8", errors="replace"))
        else:
            result.append(str(item))
    return result


def _first_string(obj: Dict[str, List[object]], *names: str) -> Optional[str]:
    for name in names:
        values = _as_strings(_values(obj, name))
        if values:
            return values[0]
    return None


def _sid_from_bytes(data: bytes) -> Optional[str]:
    if len(data) < 8:
        return None
    revision = data[0]
    count = data[1]
    if len(data) < 8 + count * 4:
        return None
    authority = int.from_bytes(data[2:8], "big")
    subauthorities = [
        str(struct.unpack_from("<I", data, 8 + index * 4)[0])
        for index in range(count)
    ]
    return "S-%d-%d%s" % (
        revision,
        authority,
        "".join("-" + item for item in subauthorities),
    )


def _as_sid(value: object) -> Optional[str]:
    values = value if isinstance(value, list) else [value]
    for item in values:
        if isinstance(item, bytes):
            sid = _sid_from_bytes(item)
            if sid:
                return sid
        elif str(item).startswith("S-"):
            return str(item)
    return None


def _domain_from_dn(dn: str) -> Optional[str]:
    labels = []
    for component in dn.split(","):
        key, separator, value = component.strip().partition("=")
        if separator and key.casefold() == "dc":
            labels.append(value)
    return ".".join(labels) if labels else None


def collect_snapshot(reader) -> Tuple[List[Dict[str, object]], Dict[str, List[str]], str, Optional[str]]:
    """Collect the AD CS objects and domain identity in one snapshot pass."""
    templates: List[Dict[str, object]] = []
    cas: Dict[str, List[str]] = {}
    domain = None
    domain_sid = None

    for raw_object in reader.iter_objects(SNAPSHOT_ATTRIBUTES):
        obj = _normalise_object(raw_object)
        object_classes = {item.casefold() for item in _as_strings(_values(obj, "objectClass"))}

        if "pkicertificatetemplate" in object_classes:
            name = _first_string(obj, "name", "cn")
            if not name:
                continue
            template: Dict[str, object] = {"name": name}
            for ldap_name, _registry_name, _kind in REGISTRY_FIELDS:
                value = _collapse(_values(obj, ldap_name))
                if value is not None and value != []:
                    template[ldap_name] = value
            templates.append(template)
            continue

        if "pkienrollmentservice" in object_classes:
            name = _first_string(obj, "name", "cn")
            if name:
                cas[name] = _as_strings(_values(obj, "certificateTemplates"))
            continue

        if "domaindns" in object_classes and domain is None:
            dn = _first_string(obj, "distinguishedName")
            domain = _domain_from_dn(dn) if dn else None
            domain_sid = _as_sid(_values(obj, "objectSid"))

    templates.sort(key=lambda item: str(item["name"]).casefold())
    cas = dict(sorted(cas.items(), key=lambda item: item[0].casefold()))
    if not domain:
        server = getattr(reader, "server", "").strip()
        domain = server.split(".", 1)[1] if "." in server else "UNKNOWN"
    return templates, cas, domain.upper(), domain_sid


def select_publication(
    cas: Dict[str, List[str]], selected_ca: Optional[str]
) -> Tuple[str, List[str], bool]:
    if selected_ca:
        match = next(
            (name for name in cas if name.casefold() == selected_ca.casefold()),
            None,
        )
        if match is None:
            available = ", ".join(cas) if cas else "none"
            raise ValueError(
                "CA %r is not in the snapshot (available: %s)"
                % (selected_ca, available)
            )
        return match, list(cas[match]), False
    if len(cas) == 1:
        name = next(iter(cas))
        return name, list(cas[name]), False
    if not cas:
        return "UNKNOWN", [], False

    published_by_name = {}
    for names in cas.values():
        for name in names:
            published_by_name.setdefault(name.casefold(), name)
    published = sorted(published_by_name.values(), key=str.casefold)
    return "adexsnap (%d CAs)" % len(cas), published, True


def default_owned_sids(domain_sid: Optional[str]) -> List[str]:
    """Return the low-privilege SID baseline used by Certipy live enumeration."""
    sids = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"]
    if domain_sid:
        sids.extend((domain_sid + "-513", domain_sid + "-515"))
    return sids


def _to_bytes(value: object, *, filetime: bool = False) -> bytes:
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("expected one binary value, got %d" % len(value))
        value = value[0]
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, int):
        data = struct.pack("<q", value) if filetime else bytes([value])
    elif isinstance(value, str):
        try:
            data = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("binary attribute is not hexadecimal") from exc
    else:
        raise ValueError("unsupported binary value %s" % type(value).__name__)
    if filetime and len(data) != 8:
        raise ValueError("FILETIME value must contain 8 bytes, got %d" % len(data))
    return data


def _to_dword(value: object) -> int:
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("expected one DWORD value, got %d" % len(value))
        value = value[0]
    if isinstance(value, bytes):
        value = int.from_bytes(value, "little", signed=True)
    return int(value) & 0xFFFFFFFF


def _reg_string(value: object) -> str:
    values = _as_strings(value)
    text = values[0] if values else ""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _reg_hex(name: str, prefix: str, data: bytes, values_per_line: int = 24) -> List[str]:
    tokens = ["%02x" % byte for byte in data]
    if not tokens:
        return ['"%s"=%s:' % (name, prefix)]
    chunks = [
        tokens[index:index + values_per_line]
        for index in range(0, len(tokens), values_per_line)
    ]
    if len(chunks) == 1:
        return ['"%s"=%s:%s' % (name, prefix, ",".join(chunks[0]))]
    lines = ['"%s"=%s:%s,\\' % (name, prefix, ",".join(chunks[0]))]
    for index, chunk in enumerate(chunks[1:]):
        continuation = index < len(chunks) - 2
        lines.append("  " + ",".join(chunk) + (",\\" if continuation else ""))
    return lines


def _registry_value(name: str, kind: str, value: object) -> List[str]:
    if kind == "string":
        return ['"%s"="%s"' % (name, _reg_string(value))]
    if kind == "dword":
        return ['"%s"=dword:%08x' % (name, _to_dword(value))]
    if kind == "binary":
        return _reg_hex(name, "hex", _to_bytes(value))
    if kind == "filetime":
        return _reg_hex(name, "hex", _to_bytes(value, filetime=True))
    if kind == "multi":
        values = _as_strings(value)
        data = ("\x00".join(values) + "\x00\x00").encode("utf-16-le")
        return _reg_hex(name, "hex(7)", data)
    raise ValueError("unsupported registry value kind: %s" % kind)


def registry_text(templates: Sequence[Dict[str, object]]) -> str:
    lines = ["Windows Registry Editor Version 5.00", ""]
    for template in templates:
        template_name = str(template["name"])
        if "\\" in template_name or "]" in template_name:
            raise ValueError("template name cannot be used as a registry key: %r"
                             % template_name)
        lines.extend(("[%s\\%s]" % (REGISTRY_KEY, template_name), ""))
        for ldap_name, registry_name, kind in REGISTRY_FIELDS:
            if ldap_name in template:
                lines.extend(_registry_value(registry_name, kind, template[ldap_name]))
        lines.append("")
    return "\r\n".join(lines)


def write_registry(path: Path, templates: Sequence[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xff\xfe" + registry_text(templates).encode("utf-16-le"))


def export_snapshot(
    snapshot_path,
    registry_output,
    *,
    domain: Optional[str] = None,
    ca: Optional[str] = None,
    owned_sids: Optional[Sequence[str]] = None,
    use_default_sids: bool = True,
    force: bool = False,
    reader_factory=None,
) -> ExportMetadata:
    """Export one snapshot and return the exact context required by Certipy."""
    if reader_factory is None:
        from adexsnap import SnapshotReader
        reader_factory = SnapshotReader

    snapshot_path = Path(snapshot_path).expanduser().resolve()
    registry_output = Path(registry_output).expanduser().resolve()
    if registry_output.suffix.casefold() != ".reg":
        raise ValueError("registry output must end in .reg")
    if registry_output.exists() and not force:
        raise ValueError("output already exists; choose another path or use --force: %s"
                         % registry_output)

    with reader_factory(snapshot_path) as reader:
        templates, cas, discovered_domain, domain_sid = collect_snapshot(reader)
    if not templates:
        raise ValueError("no pKICertificateTemplate objects found")
    ca_name, published, used_union = select_publication(cas, ca)

    if owned_sids is None:
        sid_context = default_owned_sids(domain_sid) if use_default_sids else []
    else:
        sid_context = [sid.strip() for sid in owned_sids if sid.strip()]
    missing_security = [
        str(template["name"])
        for template in templates
        if "nTSecurityDescriptor" not in template
    ]
    exported_names = {str(template["name"]).casefold() for template in templates}
    missing_published = [
        name for name in published if name.casefold() not in exported_names
    ]
    write_registry(registry_output, templates)
    return ExportMetadata(
        snapshot=str(snapshot_path),
        registry_output=str(registry_output),
        domain=(domain or discovered_domain).upper(),
        domain_sid=domain_sid,
        ca_name=ca_name,
        ca_names=list(cas),
        published=published,
        owned_sids=sid_context,
        template_count=len(templates),
        templates_without_security_descriptor=missing_security,
        published_templates_missing_from_snapshot=missing_published,
        used_published_union=used_union,
    )


def certipy_command(
    certipy_bin: str,
    metadata: ExportMetadata,
    output_prefix: Path,
    formats: Sequence[str],
    enabled_only: bool = False,
    vulnerable_only: bool = False,
    hide_admins: bool = False,
) -> List[str]:
    command = [
        certipy_bin,
        "parse",
        metadata.registry_output,
        "-format",
        "reg",
        "-domain",
        metadata.domain,
        "-ca",
        metadata.ca_name,
        "-output",
        str(output_prefix),
    ]
    if metadata.published:
        command.extend(("-published", ",".join(metadata.published)))
    if metadata.owned_sids:
        command.extend(("-sids", ",".join(metadata.owned_sids)))
    command.extend("-" + output_format for output_format in formats)
    if enabled_only:
        command.append("-enabled")
    if vulnerable_only:
        command.append("-vulnerable")
    if hide_admins:
        command.append("-hide-admins")
    return command


def report_paths(output_prefix: Path, formats: Sequence[str]) -> List[Path]:
    paths = []
    if "text" in formats:
        paths.append(Path(str(output_prefix) + "_Certipy.txt"))
    if "json" in formats:
        paths.append(Path(str(output_prefix) + "_Certipy.json"))
    if "csv" in formats:
        paths.extend((
            Path(str(output_prefix) + "_Templates_Certipy.csv"),
            Path(str(output_prefix) + "_CAs_Certipy.csv"),
        ))
    return paths


def available_report_prefix(output_prefix: Path, formats: Sequence[str]) -> Path:
    if not any(path.exists() for path in report_paths(output_prefix, formats)):
        return output_prefix
    counter = 1
    while True:
        candidate = Path("%s-%d" % (output_prefix, counter))
        if not any(path.exists() for path in report_paths(candidate, formats)):
            return candidate
        counter += 1


def _add_arguments(parser):
    parser.add_argument("path", help="completed adexsnap/AD Explorer .dat snapshot")
    parser.add_argument("-o", "--output", required=True, help="Certipy-compatible .reg file")
    parser.add_argument(
        "--force", action="store_true", help="allow replacing the .reg and metadata outputs"
    )
    parser.add_argument("--domain", help="override the discovered AD DNS domain")
    parser.add_argument(
        "--ca",
        help="select one enrollment CA (default: sole CA or union of all CAs)",
    )
    sid_group = parser.add_mutually_exclusive_group()
    sid_group.add_argument(
        "--owned-sids",
        help="replace the default low-privilege context with comma-separated SIDs",
    )
    sid_group.add_argument(
        "--no-default-sids",
        action="store_true",
        help="do not pass a low-privilege SID context to Certipy",
    )
    parser.add_argument(
        "--report-output",
        help="Certipy report prefix (default: .reg output path without extension)",
    )
    parser.add_argument(
        "--report-format",
        action="append",
        choices=("text", "json", "csv"),
        help="report format; repeat as needed (default: text and json)",
    )
    parser.add_argument("--enabled", action="store_true", help="report enabled templates only")
    parser.add_argument(
        "--vulnerable", action="store_true", help="report vulnerable templates only"
    )
    parser.add_argument(
        "--hide-admins", action="store_true", help="hide administrator permissions"
    )
    parser.add_argument(
        "--run-certipy", action="store_true", help="run Certipy after writing the .reg file"
    )
    parser.add_argument(
        "--certipy-bin", default="certipy", help="Certipy executable (default: certipy)"
    )
    parser.add_argument("--metadata-output", help="optional JSON export metadata path")
    return parser


def add_subparser(subparsers):
    parser = subparsers.add_parser(
        "certipy",
        help="export AD CS data for Certipy's offline parser",
        description=(
            "Read AD CS objects from a completed snapshot, write the certificate-template "
            "cache format accepted by `certipy parse`, and optionally create reports."
        ),
    )
    return _add_arguments(parser)


def run_from_args(args, reader_factory=None) -> int:
    metadata_path = None
    if args.metadata_output:
        metadata_path = Path(args.metadata_output).expanduser().resolve()
        if metadata_path.exists() and not args.force:
            print("error: metadata output already exists; use --force: %s" % metadata_path,
                  file=sys.stderr)
            return 1
    try:
        owned_sids = None
        if args.owned_sids is not None:
            owned_sids = [item.strip() for item in args.owned_sids.split(",") if item.strip()]
        metadata = export_snapshot(
            args.path,
            args.output,
            domain=args.domain,
            ca=args.ca,
            owned_sids=owned_sids,
            use_default_sids=not args.no_default_sids,
            force=args.force,
            reader_factory=reader_factory,
        )
    except (EOFError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    if metadata_path is not None:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(asdict(metadata), indent=2) + "\n", encoding="utf-8")

    formats = args.report_format or ["text", "json"]
    requested_prefix = (
        Path(args.report_output).expanduser().resolve()
        if args.report_output
        else Path(metadata.registry_output).with_suffix("")
    )
    output_prefix = (
        available_report_prefix(requested_prefix, formats)
        if args.run_certipy else requested_prefix
    )
    command = certipy_command(
        args.certipy_bin,
        metadata,
        output_prefix,
        formats,
        enabled_only=args.enabled,
        vulnerable_only=args.vulnerable,
        hide_admins=args.hide_admins,
    )

    print("[+] Exported %d templates to %s"
          % (metadata.template_count, metadata.registry_output))
    print("[*] Domain: %s" % metadata.domain)
    print("[*] CA context: %s" % metadata.ca_name)
    print("[*] Published templates: %d" % len(metadata.published))
    if metadata.used_published_union:
        print("[!] Multiple CAs found; enabled status uses the union of published templates. "
              "Use --ca for a per-CA report.", file=sys.stderr)
    if not metadata.ca_names:
        print("[!] No pKIEnrollmentService objects found; templates will be disabled.",
              file=sys.stderr)
    if metadata.templates_without_security_descriptor:
        print("[!] %d templates lack nTSecurityDescriptor; ACL findings are incomplete."
              % len(metadata.templates_without_security_descriptor), file=sys.stderr)
    if metadata.published_templates_missing_from_snapshot:
        print("[!] CA publication data references templates absent from the snapshot: %s"
              % ", ".join(metadata.published_templates_missing_from_snapshot),
              file=sys.stderr)

    if not args.run_certipy:
        print("[*] Run Certipy with:")
        print(shlex.join(command))
        return 0

    if shutil.which(args.certipy_bin) is None and not Path(args.certipy_bin).is_file():
        print("error: Certipy executable not found: %s" % args.certipy_bin, file=sys.stderr)
        return 1
    if output_prefix != requested_prefix:
        print("[!] Existing reports preserved; using output prefix %s" % output_prefix,
              file=sys.stderr)
    print("[*] Running: %s" % shlex.join(command))
    result = subprocess.run(command, check=False)
    missing_reports = [path for path in report_paths(output_prefix, formats) if not path.exists()]
    if result.returncode == 0 and missing_reports:
        print("error: Certipy returned success but did not create: %s"
              % ", ".join(map(str, missing_reports)), file=sys.stderr)
        return 1
    return result.returncode


def build_parser():
    parser = argparse.ArgumentParser(
        description="Export an adexsnap/AD Explorer snapshot for Certipy offline analysis."
    )
    return _add_arguments(parser)


def main(argv=None):
    return run_from_args(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
