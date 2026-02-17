from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorDetail:
    code: str
    message: str


class UsnPwError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        normalized = _normalize_code(code)
        clean_message = message.strip() or "unspecified error"
        self.code = normalized
        self.message = clean_message
        super().__init__(clean_message)

    def as_detail(self) -> ErrorDetail:
        return ErrorDetail(code=self.code, message=self.message)


def _normalize_code(code: str) -> str:
    lowered = code.strip().lower()
    if not lowered:
        return "invalid_request"
    out = []
    for ch in lowered:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        elif ch in ("-", " ", "."):
            out.append("_")
    normalized = "".join(out).strip("_")
    return normalized or "invalid_request"


def error_detail_from_exception(
    exc: BaseException,
    *,
    default_code: str = "invalid_request",
    default_message: str = "invalid request",
) -> ErrorDetail:
    if isinstance(exc, UsnPwError):
        return exc.as_detail()
    message = str(exc).strip() or default_message
    return ErrorDetail(code=_normalize_code(default_code), message=message)


def make_error(code: str, message: str) -> UsnPwError:
    return UsnPwError(code=code, message=message)


def error_payload(code: str, message: str) -> dict[str, object]:
    detail = ErrorDetail(code=_normalize_code(code), message=message.strip() or "unspecified error")
    return {"error": {"code": detail.code, "message": detail.message}}


def error_payload_from_exception(
    exc: BaseException,
    *,
    default_code: str = "invalid_request",
    default_message: str = "invalid request",
) -> dict[str, object]:
    detail = error_detail_from_exception(exc, default_code=default_code, default_message=default_message)
    return {"error": {"code": detail.code, "message": detail.message}}


def format_error_text(
    exc: BaseException,
    *,
    default_code: str = "invalid_request",
    default_message: str = "invalid request",
) -> str:
    detail = error_detail_from_exception(exc, default_code=default_code, default_message=default_message)
    return f"{detail.code}: {detail.message}"

