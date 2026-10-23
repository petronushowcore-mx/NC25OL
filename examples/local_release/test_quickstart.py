"""The published quickstart transcript comes from a real local release."""
from pathlib import Path
import unittest

import quickstart


class QuickstartTest(unittest.TestCase):
    def test_document_release_transcript(self):
        expected = Path(__file__).with_name('quickstart-expected.txt').read_text(encoding='utf-8').splitlines()
        self.assertEqual(quickstart.run(), expected, 'QUICKSTART_TRANSCRIPT_MISMATCH')


if __name__ == '__main__':
    unittest.main()
