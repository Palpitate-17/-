from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from time import monotonic
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from scanner.common.models import PageInput
from scanner.common.text_utils import normalize_url

from .contracts import ScanRequest
from .security import ScopeError, is_url_in_scope, validate_fetch_target


@dataclass(slots=True)
class CrawlResult:
    pages: list[PageInput] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)


class WebCrawler:
    REDIRECT_CODES = {301, 302, 303, 307, 308}
    DISCOVERY_ATTRIBUTES = {
        "a": "href",
        "iframe": "src",
        "script": "src",
        "link": "href",
    }

    def __init__(self, request: ScanRequest, *, allow_lab_mode: bool,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.request = request
        self.allow_lab_mode = allow_lab_mode
        self.transport = transport
        self._last_request_at = 0.0

    async def _throttle(self) -> None:
        interval = 1.0 / self.request.rate_limit_rps
        wait = interval - (monotonic() - self._last_request_at)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_at = monotonic()

    def _should_enqueue(self, url: str, source_tag: str) -> bool:
        if not is_url_in_scope(url, self.request):
            return False
        suffix = PurePosixPath(urlsplit(url).path).suffix.lower()
        if source_tag == "script":
            return suffix in {"", ".js", ".json"}
        if source_tag == "link":
            return suffix in self.request.sensitive_file_extensions and suffix != ".css"
        return suffix in {"", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp"} \
            or suffix in self.request.sensitive_file_extensions

    def _discover(self, page: PageInput) -> list[str]:
        if "html" not in page.content_type.lower():
            return []
        soup = BeautifulSoup(page.body, "html.parser")
        discovered: list[str] = []
        for tag_name, attribute in self.DISCOVERY_ATTRIBUTES.items():
            for tag in soup.find_all(tag_name):
                raw = tag.get(attribute)
                if not isinstance(raw, str) or not raw.strip() or raw.startswith(("#", "mailto:", "tel:")):
                    continue
                try:
                    candidate = normalize_url(urljoin(page.final_url, raw.strip()))
                except ValueError:
                    continue
                if self._should_enqueue(candidate, tag_name) and candidate not in discovered:
                    discovered.append(candidate)
        return discovered

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> PageInput:
        current = url
        for _ in range(6):
            current = await validate_fetch_target(
                current, self.request, allow_lab_mode=self.allow_lab_mode
            )
            await self._throttle()
            async with client.stream("GET", current, follow_redirects=False) as response:
                if response.status_code in self.REDIRECT_CODES and response.headers.get("location"):
                    target = normalize_url(urljoin(current, response.headers["location"]))
                    if not is_url_in_scope(target, self.request):
                        raise ScopeError("重定向目标超出授权范围")
                    current = target
                    continue
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self.request.max_response_bytes:
                        raise ValueError("响应正文超过配置上限")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                encoding = response.encoding or "utf-8"
                body = raw.decode(encoding, errors="replace")
                return PageInput(
                    url=url,
                    final_url=str(response.url),
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type", "application/octet-stream"),
                    body=body,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    fetched_at=datetime.now(timezone.utc).isoformat(),
                )
        raise ScopeError("站内重定向次数超过 5 次")

    async def crawl(self) -> CrawlResult:
        result = CrawlResult()
        start = normalize_url(str(self.request.target_url))
        queue: list[tuple[str, int]] = [(start, 0)]
        queued = {start}
        visited: set[str] = set()
        timeout = httpx.Timeout(self.request.timeout_seconds)
        headers = {"User-Agent": "HengXun-Authorized-Inspector/0.3"}
        async with httpx.AsyncClient(
            timeout=timeout, headers=headers, transport=self.transport, trust_env=False
        ) as client:
            while queue and len(result.pages) < self.request.max_pages:
                url, depth = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                try:
                    page = await self._fetch(client, url)
                except (httpx.HTTPError, ScopeError, ValueError, UnicodeError) as exc:
                    result.errors.append({"url": url, "error": str(exc)[:300]})
                    continue
                result.pages.append(page)
                if depth >= self.request.max_depth:
                    continue
                for discovered in self._discover(page):
                    if discovered not in queued:
                        queued.add(discovered)
                        queue.append((discovered, depth + 1))
        result.discovered_urls = sorted(queued)
        return result
