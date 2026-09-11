import importlib.util
import base64
import os
import stat
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock


HERE = os.path.dirname(__file__)
SPEC = importlib.util.spec_from_file_location("adexsnap", os.path.join(HERE, "adexsnap.py"))
NG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NG)


class FormatTests(unittest.TestCase):
    def test_default_ntlm_workstation_is_windows_shaped(self):
        captured = {}

        def fake_collect(args):
            captured["args"] = args
            return 0

        with mock.patch.object(NG, "collect", side_effect=fake_collect):
            result = NG.main(["snapshot", "--dc", "dc.example.com", "-u", "auditor",
                              "-d", "EXAMPLE", "-p", "test", "-o", "unused.dat",
                              "--no-color"])
        self.assertEqual(result, 0)
        self.assertRegex(captured["args"].workstation, r"^DESKTOP-[0-9A-F]{7}$")
        self.assertTrue(captured["args"].workstation_generated)

    def test_color_can_be_forced_or_disabled(self):
        try:
            NG._configure_color("always")
            self.assertIn("\033[32m", NG._colorize_text("[+] complete"))
            self.assertIn("\033[31m", NG._colorize_text("RESULT          : FAIL"))
            NG._configure_color("never")
            self.assertEqual(NG._colorize_text("[+] complete"), "[+] complete")
        finally:
            NG._configure_color("never")

    def test_color_cli_modes(self):
        parser = NG.build_parser()
        auto = parser.parse_args(["verify", "snapshot.dat"])
        plain = parser.parse_args(["verify", "snapshot.dat", "--no-color"])
        forced = parser.parse_args(["queries", "--color", "always"])
        self.assertEqual(auto.color, "auto")
        self.assertEqual(plain.color, "never")
        self.assertEqual(forced.color, "always")

    def test_output_path_gets_timestamp_suffix(self):
        with mock.patch.object(NG.datetime, "datetime") as datetime_class:
            datetime_class.now.return_value.strftime.return_value = "20260911-120000"
            with mock.patch.object(NG.os.path, "exists", return_value=False):
                self.assertEqual(NG._timestamped_output_path("captures/example.dat"),
                                 "captures/example-20260911-120000.dat")

    def test_output_path_adds_counter_for_same_second(self):
        with mock.patch.object(NG.datetime, "datetime") as datetime_class:
            datetime_class.now.return_value.strftime.return_value = "20260911-120000"
            with mock.patch.object(NG.os.path, "exists", side_effect=[True, True, False]):
                self.assertEqual(NG._timestamped_output_path("example.dat"),
                                 "example-20260911-120000-2.dat")

    def test_force_is_a_snapshot_option(self):
        parser = NG.build_parser()
        args = parser.parse_args(["snapshot", "--dc", "dc.example", "-o", "out.dat", "--force"])
        self.assertTrue(args.force)

    def test_ccache_is_used_directly(self):
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b"\x05\x04test")
            os.close(fd)
            prepared, temporary = NG._prepare_ticket(path, "auto")
            self.assertEqual(prepared, os.path.abspath(path))
            self.assertIsNone(temporary)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            os.unlink(path)

    def test_file_krb5ccname_is_validated(self):
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b"\x05\x04test")
            os.close(fd)
            self.assertIsNone(NG._validate_krb5ccname("FILE:" + path))
            with self.assertRaises(RuntimeError):
                NG._validate_krb5ccname("FILE:" + path + ".missing")
            # Collection backends are resolved by GSSAPI, not treated as files.
            self.assertIsNone(NG._validate_krb5ccname("KCM:"))
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            os.unlink(path)

    def test_binary_and_base64_kirbi_conversion(self):
        class FakeCCache:
            converted = []

            def fromKRBCRED(self, data):
                self.converted.append(data)

            def saveFile(self, path):
                with open(path, "wb") as fh:
                    fh.write(b"\x05\x04converted")

        impacket = types.ModuleType("impacket")
        krb5 = types.ModuleType("impacket.krb5")
        ccache = types.ModuleType("impacket.krb5.ccache")
        ccache.CCache = FakeCCache
        modules = {"impacket": impacket, "impacket.krb5": krb5,
                   "impacket.krb5.ccache": ccache}
        kirbi = b"\x76\x03abc"
        for payload in (kirbi, base64.encodebytes(kirbi)):
            fd, source = tempfile.mkstemp()
            os.write(fd, payload)
            os.close(fd)
            temporary = None
            try:
                with mock.patch.dict(sys.modules, modules):
                    prepared, temporary = NG._prepare_ticket(source, "kirbi")
                self.assertEqual(prepared, temporary)
                self.assertEqual(stat.S_IMODE(os.stat(temporary).st_mode), 0o600)
                self.assertEqual(FakeCCache.converted[-1], kirbi)
            finally:
                os.unlink(source)
                if temporary and os.path.exists(temporary):
                    os.unlink(temporary)

    def test_all_query_modes_parse_and_default_is_native(self):
        parser = NG.build_parser()
        base = ["snapshot", "--dc", "dc.example", "-o", "out.dat"]
        self.assertEqual(parser.parse_args(base).query, "native")
        self.assertEqual(
            NG.SNAPSHOT_QUERIES["native"],
            "(objectGUID=*)",
        )
        self.assertEqual(NG.SNAPSHOT_QUERIES["guid"], "(objectGUID=*)")
        self.assertEqual(NG.SNAPSHOT_QUERIES["class"], "(objectClass=*)")
        self.assertEqual(NG.SNAPSHOT_ATTRIBUTES,
                         ["*", "objectClass", "ntSecurityDescriptor"])
        for mode in NG.SNAPSHOT_QUERIES:
            self.assertEqual(parser.parse_args(base + ["--query", mode]).query, mode)

    def test_performance_ranges(self):
        self.assertEqual(NG._bounded_int("speed", 1, 100)("25"), 25)
        with self.assertRaises(Exception):
            NG._bounded_int("speed", 1, 100)("0")
        with self.assertRaises(Exception):
            NG._bounded_int("page size", 1, 1000)("1001")

    def test_speed_100_never_throttles(self):
        pacer = NG.Pacer(100)
        self.assertFalse(pacer.active)
        self.assertEqual(pacer.describe(), "full speed")

    def test_speed_50_sleeps_to_half_duty_cycle(self):
        pacer = NG.Pacer(50)
        pacer._window_start = 0.0
        pacer._row_start = 0.0
        pacer._work_ms = 0.0
        pacer._now = mock.Mock(side_effect=[10.0, 20.0])
        with mock.patch.object(NG.time, "sleep") as sleep:
            pacer.after_object()
        sleep.assert_called_once_with(0.01)

    def test_security_descriptor_lengths_precede_all_values(self):
        block = NG.SnapshotWriter._encode_values(
            NG.ADSTYPE_NT_SECURITY_DESCRIPTOR, [b"abc", b"12345"])
        self.assertEqual(block, struct.pack("<III", 2, 3, 5) + b"abc12345")

    def test_string_values_stop_at_embedded_nul_like_adsi(self):
        block = NG.SnapshotWriter._encode_values(
            NG.ADSTYPE_CASE_IGNORE_STRING, [b"DC01\x00$"])
        self.assertEqual(block, struct.pack("<II", 1, 8) + NG._wstr("DC01"))

    def test_trust_fields_are_integers_even_without_preloaded_schema(self):
        writer = NG.SnapshotWriter("unused")
        for name in ("trustDirection", "trustType", "trustAttributes"):
            self.assertEqual(writer._resolve_ads_type(name.lower(), [b"3"]),
                             NG.ADSTYPE_INTEGER)

    def test_dn_with_binary_layout(self):
        block = NG.SnapshotWriter._encode_values(
            NG.ADSTYPE_DN_WITH_BINARY, [b"B:4:0102:CN=One,DC=x"])
        self.assertEqual(block[:8], struct.pack("<II", 1, 2))
        self.assertEqual(block[8:10], b"\x01\x02")
        self.assertTrue(block.endswith(NG._wstr("CN=One,DC=x")))

    def test_bare_dn_binary_uses_native_adsi_fallback(self):
        raw, dn = NG._split_dn_binary(b"CN=Discovery,DC=x")
        self.assertEqual(raw, "CN=D".encode("utf-16-le"))
        self.assertEqual(dn, "iscovery,DC=x")

    def test_syntax_21_uses_dn_binary_payload_but_keeps_octet_metadata(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with NG.SnapshotWriter(path, build_treeview=False, build_classes=False) as writer:
                writer._collected_attr_syntax["wellknownobjects"] = ("2.5.5.7", 127)
                writer.add_object({
                    "distinguishedName": [b"DC=x"],
                    "wellKnownObjects": [b"B:4:0102:CN=One,DC=x"],
                })
            with open(path, "rb") as fh:
                fh.seek(NG.HEADER_SIZE)
                start = fh.tell()
                _size, count = struct.unpack("<II", fh.read(8))
                table = [struct.unpack("<Ii", fh.read(8)) for _ in range(count)]
                # The second value block begins n=1, binary length=2, raw=0102.
                fh.seek(start + table[1][1])
                self.assertEqual(fh.read(10), struct.pack("<II", 1, 2) + b"\x01\x02")
            self.assertEqual(writer._props["wellknownobjects"].ads_type,
                             NG.ADSTYPE_OCTET_STRING)
        finally:
            os.unlink(path)

    def test_nullable_string_is_a_real_null(self):
        self.assertEqual(NG._nullable_lenprefixed(""), b"\x00\x00\x00\x00")
        self.assertEqual(NG._nullable_lenprefixed(None), b"\x00\x00\x00\x00")
        self.assertEqual(NG._nullable_lenprefixed("x"), NG._lenprefixed("x"))

    def test_class_attributes_are_direct_then_super_then_auxiliary(self):
        writer = NG.SnapshotWriter("unused")
        classes = {
            "child": {"attrs": ["own", "shared"], "super": "parent", "aux": ["aux"]},
            "parent": {"attrs": ["parent", "shared"], "super": "", "aux": []},
            "aux": {"attrs": ["auxattr"], "super": "", "aux": []},
        }
        self.assertEqual(writer._class_attributes("child", classes),
                         ["own", "shared", "parent", "auxattr"])

    def test_auxiliary_classes_are_captured_in_native_sorted_order(self):
        writer = NG.SnapshotWriter("unused")
        attrs = {
            "objectClass": [b"top", b"classSchema"],
            "lDAPDisplayName": [b"sample"],
            "schemaIDGUID": [bytes(range(16))],
            "auxiliaryClass": [b"zAux", b"aAux"],
            "systemAuxiliaryClass": [b"mAux"],
        }
        writer._capture_schema(attrs, "CN=Sample,CN=Schema,DC=x")
        self.assertEqual(writer._collected_classes["sample"]["aux"],
                         ["aAux", "mAux", "zAux"])

    def test_domaindns_search_list_omits_native_legacy_fields(self):
        writer = NG.SnapshotWriter("unused")
        classes = {
            "domaindns": {"attrs": ["name"], "super": "domain", "aux": []},
            "domain": {"attrs": ["objectSid", "forceLogoff", "description"],
                       "super": "", "aux": []},
        }
        self.assertEqual(writer._class_attributes("domaindns", classes),
                         ["name", "description"])

    def test_display_labels_inherit_from_superclass(self):
        writer = NG.SnapshotWriter("unused")
        writer._class_display = {
            "child": ("", {"name": "Child name"}),
            "parent": ("", {"name": "Parent name", "description": "Description"}),
        }
        classes = {
            "child": {"super": "parent"},
            "parent": {"super": ""},
        }
        self.assertEqual(writer._class_display_labels("child", classes),
                         {"name": "Child name", "description": "Description"})

    def test_metadata_preload_registers_schema_properties_and_extended_rights(self):
        writer = NG.SnapshotWriter("unused")
        attr_guid = b"A" * 16
        sec_guid = b"B" * 16
        writer._capture_schema({
            "objectClass": [b"top", b"attributeSchema"],
            "lDAPDisplayName": [b"customAttribute"],
            "schemaIDGUID": [attr_guid],
            "attributeSecurityGUID": [sec_guid],
            "attributeSyntax": [b"2.5.5.12"],
            "oMSyntax": [b"64"],
        }, "CN=customAttribute,CN=Schema,CN=Configuration,DC=x")
        prop = writer._props["customattribute"]
        self.assertEqual(prop.schema_guid, attr_guid)
        self.assertEqual(prop.sec_guid, sec_guid)

        right_guid = "00299570-246d-11d0-a768-00aa006e0529"
        writer._capture_schema({
            "objectClass": [b"top", b"controlAccessRight"],
            "cn": [b"User-Force-Change-Password"],
            "displayName": [b"Reset Password"],
            "rightsGuid": [right_guid.encode()],
            "validAccesses": [b"256"],
            "appliesTo": [b"bf967aba-0de6-11d0-a285-00aa003049e2"],
        }, "CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=x")
        right = writer._collected_rights["user-force-change-password"]
        self.assertEqual(right[2], NG.uuid.UUID(right_guid).bytes_le)
        self.assertEqual(right[3], 256)

    def test_header_excludes_dn_and_repeated_values_use_backreferences(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with NG.SnapshotWriter(path, build_treeview=False, build_classes=False) as writer:
                for dn in ("CN=A,DC=x", "CN=B,DC=x"):
                    writer.add_object({"distinguishedName": [dn.encode()], "name": [b"same"]})
            with open(path, "rb") as fh:
                header = fh.read(NG.HEADER_SIZE)
                self.assertEqual(struct.unpack_from("<I", header, 1066)[0], 2)
                offsets = []
                for _ in range(2):
                    start = fh.tell()
                    size, count = struct.unpack("<II", fh.read(8))
                    offsets.extend(struct.unpack("<Ii", fh.read(8))[1] for _ in range(count))
                    fh.seek(start + size)
                self.assertEqual(sum(offset < 0 for offset in offsets), 1)
        finally:
            os.unlink(path)

    def test_identical_blocks_across_properties_share_local_offset(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with NG.SnapshotWriter(path, build_treeview=False, build_classes=False) as writer:
                writer.add_object({"distinguishedName": [b"DC=x"],
                                   "displayName": [b"same"], "name": [b"same"]})
            with open(path, "rb") as fh:
                fh.seek(NG.HEADER_SIZE)
                _size, count = struct.unpack("<II", fh.read(8))
                table = [struct.unpack("<Ii", fh.read(8)) for _ in range(count)]
            # displayName and name use the same encoded string value block.
            self.assertEqual(table[1][1], table[2][1])
            self.assertGreater(table[1][1], 0)
        finally:
            os.unlink(path)

    def test_distinguished_name_is_not_a_value_cache_source(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            dn = b"CN=Sample,CN=Schema,DC=x"
            with NG.SnapshotWriter(path, build_treeview=False,
                                   build_classes=False) as writer:
                writer.add_object({"distinguishedName": [dn],
                                   "defaultObjectCategory": [dn]})
            with open(path, "rb") as fh:
                fh.seek(NG.HEADER_SIZE + 8)
                table = [struct.unpack("<Ii", fh.read(8)) for _ in range(2)]
            self.assertNotEqual(table[0][1], table[1][1])
            self.assertGreater(table[0][1], 0)
            self.assertGreater(table[1][1], 0)
        finally:
            os.unlink(path)

    def test_distinguished_name_is_always_first_object_table_entry(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with NG.SnapshotWriter(path, build_treeview=False, build_classes=False) as writer:
                writer.add_object({"objectClass": [b"top"], "name": [b"x"],
                                   "distinguishedName": [b"DC=x"]})
                dn_index = writer._props["distinguishedname"].index
            with open(path, "rb") as fh:
                fh.seek(NG.HEADER_SIZE + 8)
                first_property = struct.unpack("<I", fh.read(4))[0]
            self.assertEqual(first_property, dn_index)
        finally:
            os.unlink(path)

    def test_capture_filetime_is_preserved_during_finalize(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        original_clock = NG._filetime_now
        try:
            writer = NG.SnapshotWriter(path, build_treeview=False,
                                       build_classes=False)
            started = writer._capture_filetime
            NG._filetime_now = lambda: started + 999999999
            with writer:
                writer.add_object({"distinguishedName": [b"DC=x"]})
            with open(path, "rb") as fh:
                header = fh.read(NG.HEADER_SIZE)
            self.assertEqual(struct.unpack_from("<Q", header, 14)[0], started)
        finally:
            NG._filetime_now = original_clock
            os.unlink(path)

    def test_synthetic_tree_objects_precede_metadata_with_native_sentinel(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with NG.SnapshotWriter(path, naming_contexts=["DC=x"],
                                   build_classes=False) as writer:
                writer.add_object({
                    "distinguishedName": [b"CN=Leaf,OU=Missing,DC=x"],
                    "objectClass": [b"top"],
                })
            with open(path, "rb") as fh:
                header = fh.read(NG.HEADER_SIZE)
                metadata = struct.unpack_from("<Q", header, 1070)[0]
                fh.seek(NG.HEADER_SIZE)
                object_size = struct.unpack("<I", fh.read(4))[0]
                counted_end = NG.HEADER_SIZE + object_size
                fh.seek(counted_end)
                gap = fh.read(metadata - counted_end)
            self.assertGreater(len(gap), 8)
            self.assertEqual(gap[-8:], b"\0" * 8)
            self.assertGreater(struct.unpack_from("<I", gap, 0)[0], 16)
        finally:
            os.unlink(path)

    def test_backreference_window_matches_native_one_megabyte_limit(self):
        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with NG.SnapshotWriter(path, build_treeview=False, build_classes=False) as writer:
                writer.add_object({"distinguishedName": [b"CN=A,DC=x"], "name": [b"same"]})
                # Move the next object beyond the native cache window.
                writer._fh.write(b"\0" * 1_000_000)
                writer.add_object({"distinguishedName": [b"CN=B,DC=x"], "name": [b"same"]})
            with open(path, "rb") as fh:
                fh.seek(NG.HEADER_SIZE)
                first_size = struct.unpack("<I", fh.read(4))[0]
                second = NG.HEADER_SIZE + first_size + 1_000_000
                fh.seek(second + 8)
                table = [struct.unpack("<Ii", fh.read(8)) for _ in range(2)]
            self.assertGreater(table[1][1], 0)
        finally:
            os.unlink(path)

    def test_reference_snapshot_if_present(self):
        reference = os.path.join(os.path.dirname(HERE), "a.dat")
        if os.path.exists(reference):
            self.assertEqual(NG.verify(reference), 0)


if __name__ == "__main__":
    unittest.main()
