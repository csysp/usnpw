from __future__ import annotations

import os
import unittest
from pathlib import Path

from usnpw.core.password_engine import load_bip39_wordlist


class PasswordEngineTests(unittest.TestCase):
    def test_bip39_wordlist_missing_file_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "not found"):
            load_bip39_wordlist(".tmp_missing_bip39_wordlist.txt")

    def test_bip39_wordlist_wrong_count_raises(self) -> None:
        path = Path(".tmp_test_bip39_wordlist_count.txt")
        try:
            path.write_text("abandon\n", encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "2048"):
                load_bip39_wordlist(str(path))
        finally:
            try:
                path.unlink()
            except OSError:
                pass

    def test_bip39_wordlist_duplicate_word_raises(self) -> None:
        path = Path(".tmp_test_bip39_wordlist_dupes.txt")
        try:
            words = [f"w{i}" for i in range(2047)] + ["w0"]
            path.write_text("\n".join(words) + "\n", encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "unique"):
                load_bip39_wordlist(str(path))
        finally:
            try:
                path.unlink()
            except OSError:
                pass

    def test_bip39_wordlist_whitespace_word_raises(self) -> None:
        path = Path(".tmp_test_bip39_wordlist_ws.txt")
        try:
            words = [f"w{i}" for i in range(2047)] + ["hello world"]
            path.write_text("\n".join(words) + "\n", encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "whitespace"):
                load_bip39_wordlist(str(path))
        finally:
            try:
                path.unlink()
            except OSError:
                pass

    def test_bip39_wordlist_valid_loads(self) -> None:
        path = Path(".tmp_test_bip39_wordlist_ok.txt")
        try:
            words = [f"w{i}" for i in range(2048)]
            path.write_text("\n".join(words) + "\n", encoding="utf-8", newline="\n")
            loaded = load_bip39_wordlist(str(path))
            self.assertEqual(len(loaded), 2048)
        finally:
            try:
                path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUTF8", "1")
    unittest.main(verbosity=2)

