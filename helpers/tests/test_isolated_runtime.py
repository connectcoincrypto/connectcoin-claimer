"""Exercise the real source entry point without inheriting the test sys.path."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend


BRIDGE = Path(__file__).resolve().parents[1] / "claims_bridge.py"


class IsolatedRuntimeTests(unittest.TestCase):
    def invoke(self, arguments, frames=""):
        with tempfile.TemporaryDirectory(prefix="connectwallet-isolation-") as directory:
            # Neither cwd, PYTHONPATH, nor user-site hooks may supply helper
            # modules. Poison files make loss of -I or a cwd import observable.
            poison = Path(directory)
            for name in ("claims_service.py", "rsa_probe.py", "sitecustomize.py", "usercustomize.py"):
                (poison / name).write_text("raise RuntimeError('untrusted import')\n", encoding="utf-8")
            package = poison / "connectcoin_p2c_tools"
            package.mkdir()
            (package / "__init__.py").write_text("raise RuntimeError('untrusted vendor')\n", encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": directory, "PYTHONUSERBASE": directory}
            return subprocess.run(
                [sys.executable, "-I", str(BRIDGE), *arguments],
                input=frames, cwd=directory, env=env, text=True,
                capture_output=True, timeout=20, check=False,
            )

    def test_service_starts_and_shuts_down_from_untrusted_directory(self):
        frames = "\n".join(json.dumps(frame) for frame in (
            {"type": "start", "protocol": 4, "options": {"connectionsPerSecond": 100, "concurrency": 100}},
            {"type": "shutdown"},
        )) + "\n"
        result = self.invoke(["--service"], frames)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual([json.loads(line) for line in result.stdout.splitlines()],
                         [{"type": "ready", "protocol": 4, "roots": 1,
                           "security": {"rsaPublicExponentMaxBits": 64}}])

    def test_isolated_self_test_uses_trusted_dependencies(self):
        result = self.invoke(["--self-test"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {
            "type": "ready", "protocol": 4, "roots": 1,
            "security": {"cryptographyVersion": cryptography.__version__,
                         "minimumCryptographyVersion": "50.0.1",
                         "opensslVersion": backend.openssl_version_text(),
                         "rsaPublicExponentMaxBits": 64},
        })

    def test_self_test_exits_with_error_for_vulnerable_loaded_dependency(self):
        # Simulate an old embedded package without installing or contacting one.
        script = (
            "import cryptography, runpy, sys; "
            "cryptography.__version__ = '47.0.0'; "
            "sys.argv = [sys.argv[1], '--self-test']; "
            "runpy.run_path(sys.argv[0], run_name='__main__')"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script, str(BRIDGE)],
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")
        frame = json.loads(result.stdout)
        self.assertEqual(frame["type"], "error")
        self.assertIn("cryptography 50.0.1", frame["message"])
        self.assertIn("loaded 47.0.0", frame["message"])

    def test_service_rejects_wrong_protocol_without_starting_work(self):
        for protocol in (1, 2, 3):
            with self.subTest(protocol=protocol):
                frame = {"type": "start", "protocol": protocol, "options": {}}
                result = self.invoke(["--service"], json.dumps(frame) + "\n")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, "")
                frames = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual(len(frames), 1)
                self.assertEqual(frames[0]["type"], "error")
                self.assertIn("protocol 4", frames[0]["message"])

    def test_rsa_probe_uses_trusted_import_and_sanitizes_invalid_input(self):
        result = self.invoke(["--probe-rsa"], '{"domain":"private.local","rootVersion":1,"validationTime":1800000000}\n')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {
            "type": "error", "message": "Invalid or incomplete RSA probe request."})

    def test_unknown_rsa_probe_arguments_do_not_start_work(self):
        result = self.invoke(["--probe-rsa", "--unsafe"])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["type"], "error")

    def test_required_exponent_capability_works_in_isolated_modes(self):
        required = "--require-rsa-exponent-64"
        result = self.invoke(["--self-test", required])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["security"]["rsaPublicExponentMaxBits"], 64)
        result = self.invoke(["--probe-rsa", required], "{}\n")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {
            "type": "error", "message": "Invalid or incomplete RSA probe request."})
        result = self.invoke([required], "{}\n")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {
            "type": "error", "message": "request must contain only context and options"})


if __name__ == "__main__":
    unittest.main()
