"""Unit tests for spec validation and PHP generation."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shellshock.creator import auth, drivers, generator, readers
from shellshock.creator.spec import WebShellSpec
from shellsuite.protocol import contract


class SpecTests(unittest.TestCase):
    def test_rejects_unknown_vector(self):
        with self.assertRaises(ValueError):
            WebShellSpec(vector="nope", mode="plain").validate()

    def test_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            WebShellSpec(vector="cookie", mode="nope").validate()

    def test_rejects_unknown_driver(self):
        with self.assertRaises(ValueError):
            WebShellSpec(vector="cookie", mode="plain", driver="nope").validate()

    def test_encrypted_requires_secret(self):
        with self.assertRaises(ValueError):
            WebShellSpec(vector="cookie", mode="encrypted").validate()

    def test_auth_requires_secret(self):
        with self.assertRaises(ValueError):
            WebShellSpec(vector="cookie", mode="auth").validate()

    def test_plain_rejects_secret(self):
        with self.assertRaises(ValueError):
            WebShellSpec(vector="cookie", mode="plain", secret="x").validate()

    def test_default_driver_is_first(self):
        spec = WebShellSpec(vector="cookie", mode="plain")
        self.assertEqual(spec.resolved_driver, drivers.DEFAULT_DRIVER)


class GeneratorTests(unittest.TestCase):
    def test_cookie_plain_uses_default_driver(self):
        php = generator.generate(WebShellSpec(vector="cookie", mode="plain"))
        self.assertIn(contract.PARAM_NAMES["cookie"], php)
        self.assertIn(contract.RESPONSE_BEGIN, php)
        self.assertIn(contract.RESPONSE_END, php)
        self.assertIn(drivers.DEFAULT_DRIVER, php)
        self.assertNotIn("{{", php)  # every placeholder was filled
        for other in drivers.DRIVERS:  # only ONE driver is embedded
            if other != drivers.DEFAULT_DRIVER:
                self.assertNotIn(other, php)

    def test_explicit_driver_is_embedded(self):
        php = generator.generate(
            WebShellSpec(vector="cookie", mode="plain", driver="passthru")
        )
        self.assertIn("passthru(", php)
        self.assertNotIn("shell_exec", php)

    def test_cookie_plain_is_php52_compatible(self):
        php = generator.generate(WebShellSpec(vector="cookie", mode="plain"))
        self.assertNotIn("??", php)  # null-coalescing is PHP 7.0+
        self.assertIn("isset(", php)

    def test_header_plain_uses_cgi_style_server_key(self):
        php = generator.generate(WebShellSpec(vector="header", mode="plain"))
        self.assertIn("$_SERVER", php)
        self.assertIn('"HTTP_"', php)
        self.assertIn("strtoupper", php)
        self.assertIn('str_replace("-", "_"', php)
        self.assertIn(contract.PARAM_NAMES["header"], php)
        self.assertIn(contract.RESPONSE_BEGIN, php)
        self.assertIn(contract.RESPONSE_END, php)
        self.assertNotIn("{{", php)
        # The header the Manager sends must map to the key PHP exposes it as.
        expected = "HTTP_" + contract.PARAM_NAMES["header"].upper().replace("-", "_")
        self.assertEqual(expected, "HTTP_X_SHELLSHOCK")

    def test_post_plain_reads_post_superglobal(self):
        php = generator.generate(WebShellSpec(vector="post", mode="plain"))
        self.assertIn("$_POST", php)
        self.assertIn('$_POST["%s"]' % contract.PARAM_NAMES["post"], php)
        self.assertIn(contract.RESPONSE_BEGIN, php)
        self.assertIn(contract.RESPONSE_END, php)
        self.assertNotIn("{{", php)

    def test_every_vector_is_php52_compatible(self):
        for vector in contract.VECTORS:
            for mode in ("plain", "auth", "encrypted"):
                php = generator.generate(
                    WebShellSpec(
                        vector=vector,
                        mode=mode,
                        secret=None if mode == "plain" else "x",
                    )
                )
                self.assertNotIn("??", php, (vector, mode))  # PHP 7.0+
                self.assertIn("isset(", php, (vector, mode))

    def test_auth_embeds_hash_and_gate(self):
        secret = "hunter2"
        expected = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        for vector in contract.VECTORS:
            php = generator.generate(
                WebShellSpec(vector=vector, mode="auth", secret=secret)
            )
            self.assertIn(contract.AUTH_PARAM_NAMES[vector], php, vector)
            self.assertIn(expected, php, vector)
            self.assertIn('hash("sha256"', php, vector)
            self.assertIn("$__ss_ok", php, vector)
            self.assertNotIn("{{", php, vector)

    def test_plain_has_no_auth_material(self):
        php = generator.generate(WebShellSpec(vector="cookie", mode="plain"))
        self.assertIn("$__ss_ok = true;", php)
        self.assertNotIn("hash(", php)
        for name in contract.AUTH_PARAM_NAMES.values():
            self.assertNotIn(name, php)

    def test_encrypted_includes_crypto_and_decrypt(self):
        for vector in contract.VECTORS:
            php = generator.generate(
                WebShellSpec(vector=vector, mode="encrypted", secret="hunter2")
            )
            self.assertIn("function __ss_decrypt", php, vector)
            self.assertIn("function __ss_encrypt", php, vector)
            self.assertIn('hash_hmac("sha256"', php, vector)
            self.assertIn(contract.ENCRYPTED_PREFIX, php, vector)
            self.assertIn(
                "$__ss_cmd = __ss_decrypt($__ss_cmd, $__ss_auth);", php, vector
            )
            self.assertIn(
                "__ss_encrypt(__ss_run($__ss_cmd), $__ss_auth)", php, vector
            )
            self.assertIn(contract.AUTH_PARAM_NAMES[vector], php, vector)

    def test_non_encrypted_modes_have_no_crypto(self):
        for mode in ("plain", "auth"):
            php = generator.generate(
                WebShellSpec(
                    vector="cookie",
                    mode=mode,
                    secret=None if mode == "plain" else "x",
                )
            )
            self.assertNotIn("__ss_decrypt", php, mode)
            self.assertNotIn("__ss_encrypt", php, mode)
            self.assertNotIn("hash_hmac", php, mode)

    def test_generated_shell_urldecodes_values(self):
        for vector in contract.VECTORS:
            for mode in ("plain", "auth", "encrypted"):
                php = generator.generate(
                    WebShellSpec(
                        vector=vector,
                        mode=mode,
                        secret=None if mode == "plain" else "x",
                    )
                )
                self.assertIn("urldecode(", php, (vector, mode))

    def test_guard_supports_every_contract_vector(self):
        for vector in contract.VECTORS:
            php = auth.guard(vector, "deadbeef")
            self.assertIn(contract.AUTH_PARAM_NAMES[vector], php, vector)

    def test_guard_rejects_unknown_vector(self):
        with self.assertRaises(ValueError):
            auth.guard("nope", "deadbeef")

    def test_readers_cover_contract_vectors(self):
        self.assertEqual(set(readers._READERS), set(contract.VECTORS))
        readers.assert_conformance()

    def test_read_is_fully_rendered(self):
        for vector in contract.VECTORS:
            php = readers.read(vector, "$__ss_x", "NAME")
            self.assertNotIn("{", php, vector)

    def test_assert_conformance_detects_mismatch(self):
        with mock.patch.dict(readers._READERS, {"extra": "x"}):
            with self.assertRaises(ValueError):
                readers.assert_conformance()

    def test_write_default_goes_under_shells_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                path = generator.write(
                    WebShellSpec(vector="cookie", mode="plain", name="web1")
                )
            self.assertEqual(path.name, "web1.php")
            self.assertTrue(path.is_file())
            self.assertEqual(path.parent, Path(tmp) / "shells")


if __name__ == "__main__":
    unittest.main()
