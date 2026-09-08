"""URL construction and secret redaction helpers."""

import re
from pathlib import Path
from urllib.parse import quote, urlsplit

from dbmcp.errors import UrlError
from dbmcp.profiles import Profile

_URL_SCHEMES = ("postgresql://", "mysql://", "redis://", "rediss://", "sqlite://")
# Matches a URL authority fragment (`scheme://user:pass@`), used to scrub
# URLs embedded inside larger error strings.
_URL_FRAGMENT_RE = re.compile(r"(?:postgresql|mysql|redis|rediss|sqlite)://[^\s@]*@")


def build_url(profile: Profile, password: str | None) -> str:
    """Build a connection URL for profile and password."""
    if profile.db_type == "postgres":
        if not profile.host or profile.port is None or not profile.user or not profile.dbname:
            raise UrlError("missing required postgres connection field")
        host = _wrap_ipv6(profile.host)
        pw = quote(password, safe="") if password else ""
        url = f"postgresql://{profile.user}:{pw}@{host}:{profile.port}/{profile.dbname}"
        if profile.sslmode:
            url = f"{url}?sslmode={profile.sslmode}"
        return url

    if profile.db_type == "redis":
        if not profile.host or profile.port is None:
            raise UrlError("missing required redis connection field")
        scheme = "rediss" if profile.tls else "redis"
        user = profile.user or ""
        pw = quote(password, safe="") if password else ""
        db = profile.dbname if profile.dbname is not None else "0"
        host = _wrap_ipv6(profile.host)
        return f"{scheme}://{user}:{pw}@{host}:{profile.port}/{db}"

    if profile.db_type == "sqlite":
        if not profile.dbname:
            raise UrlError("missing required sqlite dbname")
        return f"sqlite:///{Path(profile.dbname).resolve()}"

    if profile.db_type == "mysql":
        raise UrlError("mysql does not use URL connection strings")

    raise UrlError(f"unsupported db_type: {profile.db_type}")


def redact(text: str, password: str | None) -> str:
    """Replace raw/encoded password and any full URL containing it with ***."""
    if not password:
        return text

    encoded = quote(password, safe="")
    if text == password or text == encoded:
        return "***"

    # If the entire text is a URL that contains the password, redact the whole URL.
    lowered = text.lower()
    if any(lowered.startswith(scheme) for scheme in _URL_SCHEMES):
        if password in text or encoded in text:
            return "***"

    text = text.replace(password, "***").replace(encoded, "***")
    # Mask any URL fragment (scheme://...@) that still embeds the credential
    # after the inline replacement, e.g. inside a longer error string.
    return _URL_FRAGMENT_RE.sub(lambda m: "***" if "***" in m.group(0) else m.group(0), text)


def _wrap_ipv6(host: str) -> str:
    """Wrap an IPv6 address in brackets for URL usage."""
    if ":" in host and not host.startswith("["):
        # Validate IPv6 by urlsplitting the host portion.
        try:
            urlsplit(f"http://[{host}]")
        except ValueError:
            raise UrlError(f"invalid host: {host}") from None
        return f"[{host}]"
    return host
