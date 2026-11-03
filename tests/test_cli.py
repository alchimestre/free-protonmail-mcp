import unittest

from free_protonmail_mcp.cli import terminal_text


class TerminalRenderingTests(unittest.TestCase):
    def test_preview_cannot_emit_terminal_escape_or_bidi_controls(self):
        rendered = terminal_text("Subject\x1b[2J\rforged\u202esend\nBody\ttext")
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\n", rendered)
        self.assertIn("Body", rendered)


if __name__ == "__main__":
    unittest.main()
