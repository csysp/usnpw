from __future__ import annotations

import os

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _CRYPTPROTECT_UI_FORBIDDEN = 0x01
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    def _make_data_blob(data: bytes) -> tuple["_DATA_BLOB", ctypes.Array | None]:
        if not data:
            return _DATA_BLOB(0, None), None
        buf = (ctypes.c_byte * len(data)).from_buffer_copy(data)
        blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
        return blob, buf

    def dpapi_protect(data: bytes, entropy: bytes) -> bytes:
        in_blob, _ = _make_data_blob(data)
        ent_blob, _ = _make_data_blob(entropy)
        out_blob = _DATA_BLOB()
        ok = _crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(ent_blob) if entropy else None,
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
        try:
            return bytes(ctypes.string_at(out_blob.pbData, out_blob.cbData))
        finally:
            if out_blob.pbData:
                _kernel32.LocalFree(out_blob.pbData)

    def dpapi_unprotect(data: bytes, entropy: bytes) -> bytes:
        in_blob, _ = _make_data_blob(data)
        ent_blob, _ = _make_data_blob(entropy)
        out_blob = _DATA_BLOB()
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(ent_blob) if entropy else None,
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise OSError(ctypes.get_last_error(), "CryptUnprotectData failed")
        try:
            return bytes(ctypes.string_at(out_blob.pbData, out_blob.cbData))
        finally:
            if out_blob.pbData:
                _kernel32.LocalFree(out_blob.pbData)

else:

    def dpapi_protect(data: bytes, entropy: bytes) -> bytes:
        raise RuntimeError("DPAPI unavailable on this OS")

    def dpapi_unprotect(data: bytes, entropy: bytes) -> bytes:
        raise RuntimeError("DPAPI unavailable on this OS")
