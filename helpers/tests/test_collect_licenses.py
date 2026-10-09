"""Source-built providers must retain a verified, complete license inventory."""

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_licenses as licenses


VERSION = "50.0.1"
CRATE_HASH = "a" * 64
LOCK = f'''version = 4
[[package]]
name = "cryptography-rust"
version = "0.50.1"
[[package]]
name = "example"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{CRATE_HASH}"
'''.encode()
PROJECT = b'''[project]
name = "cryptography"
version = "50.0.1"
[tool.maturin]
locked = true
'''


def archive_bytes(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data, kind in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                member.linkname = "../../outside"
            archive.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


def source_archive(lock=LOCK, project=PROJECT):
    return archive_bytes([(f"cryptography-{VERSION}/Cargo.lock", lock, tarfile.REGTYPE),
                          (f"cryptography-{VERSION}/pyproject.toml", project, tarfile.REGTYPE)])


class LicenseInventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="connectwallet-licenses-")
        self.addCleanup(self.directory.cleanup)
        # Match the collector's canonical PROJECT path. CI temp roots can be
        # aliases/junctions (notably /var -> /private/var on macOS).
        self.output = Path(self.directory.name).resolve()
        self.enterContext(patch.object(licenses, "OUTPUT", self.output))
        self.enterContext(patch.object(licenses, "CACHE", self.output))
        self.enterContext(patch.object(licenses, "MANIFEST", []))

    def source(self, data, returned=None):
        self.enterContext(patch.object(licenses, "CRYPTOGRAPHY_SDISTS", {
            VERSION: ("https://files.pythonhosted.org/reviewed.tar.gz", hashlib.sha256(data).hexdigest())}))
        fetch = self.enterContext(patch.object(licenses, "fetch", return_value=data if returned is None else returned))
        return fetch

    def test_source_inventory_checks_lock_and_keeps_original_provenance(self):
        data = source_archive()
        self.source(data)
        components = licenses.source_components(VERSION)
        self.assertEqual(components, [{"name": "example", "version": "1.2.3",
                                      "hashes": [{"alg": "SHA-256", "content": CRATE_HASH}]}])
        self.assertEqual((self.output / f"cryptography-{VERSION}/Cargo.lock").read_bytes(), LOCK)
        self.assertEqual((self.output / f"cryptography-{VERSION}/pyproject.toml").read_bytes(), PROJECT)
        provenance = json.loads((self.output / f"cryptography-{VERSION}/source-provenance.json").read_text())
        self.assertEqual(provenance["sdistSha256"], hashlib.sha256(data).hexdigest())
        self.assertIn("not binary build attestation", provenance["inventory"])
        for entry in licenses.MANIFEST:
            self.assertEqual(entry["sha256"], hashlib.sha256((self.output / entry["file"]).read_bytes()).hexdigest())

    def test_wrong_source_digest_or_unknown_version_cannot_write_inventory(self):
        self.source(source_archive(), returned=b"tampered download")
        with self.assertRaisesRegex(ValueError, "checksum"):
            licenses.source_components(VERSION)
        with self.assertRaisesRegex(ValueError, "No reviewed"):
            licenses.source_components("50.0.2")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_source_requires_exact_unique_bounded_regular_members(self):
        lock_name = f"cryptography-{VERSION}/Cargo.lock"
        project_member = (f"cryptography-{VERSION}/pyproject.toml", PROJECT, tarfile.REGTYPE)
        for members in [
            [project_member],
            [("../Cargo.lock", LOCK, tarfile.REGTYPE), project_member],
            [(lock_name, LOCK, tarfile.REGTYPE)] * 2 + [project_member],
            [(lock_name, b"", tarfile.SYMTYPE), project_member],
            [(lock_name, b"x" * (1024 * 1024 + 1), tarfile.REGTYPE), project_member],
        ]:
            with self.subTest(members=[item[0] for item in members]):
                data = archive_bytes(members)
                self.source(data)
                with self.assertRaises(ValueError):
                    licenses.source_components(VERSION)
                self.assertEqual(licenses.MANIFEST, [])

    def test_source_version_and_locked_build_are_required(self):
        for project in [PROJECT.replace(b"50.0.1", b"50.0.2"), PROJECT.replace(b"true", b"false")]:
            with self.subTest(project=project):
                self.source(source_archive(project=project))
                with self.assertRaisesRegex(ValueError, "version or locked"):
                    licenses.source_components(VERSION)

    def test_lockfile_rejects_missing_hash_foreign_source_duplicates_and_empty_inventory(self):
        for lock in [
            LOCK.replace(CRATE_HASH.encode(), b""),
            LOCK.replace(b"registry+https://github.com/rust-lang/crates.io-index", b"git+https://example.org/repo"),
            LOCK + LOCK[LOCK.index(b'[[package]]\nname = "example"'):],
            LOCK.replace(b"cryptography-rust", b"unrelated-local"),
            b"version = 4\npackage = []\n",
        ]:
            with self.subTest(lock=lock):
                with self.assertRaises(ValueError):
                    licenses.lockfile_components(lock)

    def test_only_absent_sbom_uses_source_inventory(self):
        distribution = Mock(version=VERSION)
        distribution.read_text.return_value = None
        with patch.object(licenses, "source_components", return_value=["source"]) as fallback:
            self.assertEqual(licenses.rust_components(distribution), ["source"])
            fallback.assert_called_once_with(VERSION)
        for malformed in ["{", '{"components": []}']:
            distribution.read_text.return_value = malformed
            with patch.object(licenses, "source_components") as fallback:
                with self.assertRaises(ValueError):
                    licenses.rust_components(distribution)
                fallback.assert_not_called()

    def test_wheel_inventory_retains_its_own_checksums(self):
        component = {"name": "example", "version": "1.2.3", "bom-ref": "registry+crates/example",
                     "hashes": [{"alg": "SHA-256", "content": CRATE_HASH}]}
        distribution = Mock(version=VERSION)
        distribution.read_text.return_value = json.dumps({"components": [component]})
        with patch.object(licenses, "source_components") as fallback:
            self.assertEqual(licenses.rust_components(distribution), [component])
            fallback.assert_not_called()

    def test_both_openssl_runtimes_are_collected_without_wheel_sbom(self):
        self.assertEqual(licenses.openssl_versions(None, "OpenSSL 3.6.3 9 Jun 2026", "OpenSSL 3.0.18 30 Sep 2025"),
                         {"3.6.3", "3.0.18"})
        sbom = json.dumps({"components": [{"name": "openssl", "version": "4.0.2"}]})
        self.assertEqual(licenses.openssl_versions(sbom, "OpenSSL 4.0.2 25 Aug 2026"), {"4.0.2"})
        for invalid in ["LibreSSL 3.3.6", "OpenSSL 3.6.3-beta1", "unknown"]:
            with self.assertRaisesRegex(ValueError, "OpenSSL"):
                licenses.openssl_versions(None, invalid)

    def test_crate_checksum_mismatch_and_missing_notices_fail_closed(self):
        data = archive_bytes([("example-1.2.3/README.md", b"no license", tarfile.REGTYPE)])
        component = {"name": "example", "version": "1.2.3",
                     "hashes": [{"alg": "SHA-256", "content": CRATE_HASH}]}
        with patch.object(licenses, "fetch", return_value=data):
            with self.assertRaisesRegex(ValueError, "checksum"):
                licenses.crate_notices(component)
            component["hashes"][0]["content"] = hashlib.sha256(data).hexdigest()
            with self.assertRaisesRegex(ValueError, "No original license"):
                licenses.crate_notices(component)


if __name__ == "__main__":
    unittest.main()
