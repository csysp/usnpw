"""Core generation engines, models, and service APIs for USnPw."""

from __future__ import annotations


def generate_passwords(request):
    from usnpw.core.password_service import generate_passwords as _generate_passwords

    return _generate_passwords(request)


def generate_usernames(request):
    from usnpw.core.username_service import generate_usernames as _generate_usernames

    return _generate_usernames(request)


__all__ = ["generate_passwords", "generate_usernames"]
