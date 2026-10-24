from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup


WHITESPACE_RE = re.compile(r"\s+")


def normalize_url(url: str, base_url: str | None = None) -> str:
    absolute = urljoin(base_url or url, url)
    parts = urlsplit(absolute)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    host = f"[{host}]" if ":" in host else host
    netloc = host if port is None or default_port else f"{host}:{port}"
    if "@" in parts.netloc:
        netloc = parts.netloc.rsplit("@", 1)[0] + "@" + netloc
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def extract_visible_text(html: str, *, ignore_dynamic: bool = False) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for element in soup(["script", "style", "noscript", "template"]):
        element.decompose()
    if ignore_dynamic:
        for element in soup.select('[data-ignore="dynamic"]'):
            element.decompose()
    return soup.get_text(" ", strip=True)


def normalize_text(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text).strip()


def text_hash(html: str) -> str:
    normalized = normalize_text(extract_visible_text(html, ignore_dynamic=True))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
