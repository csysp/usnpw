from __future__ import annotations

import os
import unittest

from usnpw.core.export_crypto import decrypt_text, encrypt_text


class ExportCryptoTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "DPAPI export crypto is Windows-only in stdlib build")
    def test_encrypt_decrypt_roundtrip(self) -> None:
        plaintext = "line1\nline2\n"
        encrypted = encrypt_text(plaintext, "correct horse battery staple")
        restored = decrypt_text(encrypted, "correct horse battery staple")
        self.assertEqual(restored, plaintext)

    @unittest.skipUnless(os.name == "nt", "DPAPI export crypto is Windows-only in stdlib build")
    def test_wrong_passphrase_fails(self) -> None:
        encrypted = encrypt_text("secret\n", "pass-one")
        with self.assertRaisesRegex(ValueError, "decryption failed"):
            decrypt_text(encrypted, "pass-two")

    @unittest.skipUnless(os.name == "nt", "DPAPI export crypto is Windows-only in stdlib build")
    def test_invalid_header_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid encrypted export header"):
            decrypt_text("not-encrypted", "x")


if __name__ == "__main__":
    unittest.main()
