"""Import smoke tests for the GUI modules (no window is created)."""

from __future__ import annotations

import unittest


class GuiImportTests(unittest.TestCase):
    def test_import_gui_modules(self):
        import shellsuite.gui.app  # noqa: F401
        import shellsuite.gui.icons  # noqa: F401
        import shellsuite.gui.widgets  # noqa: F401
        import shellshock.gui  # noqa: F401


if __name__ == "__main__":
    unittest.main()
