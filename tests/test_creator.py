"""Unit tests for spec validation and PHP generation."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shellshock.creator import generator
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
        self.assertEqual(spec.resolved_driver, contract.DEFAULT_DRIVER)


class GeneratorTests(unittest.TestCase):
    def test_cookie_plain_uses_default_driver(self):
        php = generator.generate(WebShellSpec(vector="cookie", mode="plain"))
        self.assertIn(contract.PARAM_NAMES["cookie"], php)
        self.assertIn(contract.RESPONSE_BEGIN, php)
        self.assertIn(contract.RESPONSE_END, php)
        self.assertIn(contract.DEFAULT_DRIVER, php)
        self.assertNotIn("{{", php)  # every placeholder was filled
        for other in contract.DRIVERS:  # only ONE driver is embedded
            if other != contract.DEFAULT_DRIVER:
                self.assertNotIn(other, php)

    def test_explicit_driver_is_embedded(self):
        php = generator.generate(
            WebShellSpec(vector="cookie", mode="plain", driver="passthru")
        )
        self.assertIn("passthru(", php)
        self.assertNotIn("shell_exec", php)

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
