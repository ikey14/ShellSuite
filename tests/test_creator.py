"""Unit tests for spec validation and PHP generation."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shellshock.creator import generator, drivers
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
            php = generator.generate(WebShellSpec(vector=vector, mode="plain"))
            self.assertNotIn("??", php, vector)  # null-coalescing is PHP 7.0+
            self.assertIn("isset(", php, vector)

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
