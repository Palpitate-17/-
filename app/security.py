from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from scanner.common.text_utils import normalize_url

from .contracts import ScanRequest


class ScopeError(ValueError):
    pass


def _host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    host = hostname.lower().rstrip(".")
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts)


def _path_allowed(path: str, allowed_paths: list[str], denied_paths: list[str]) -> bool:
    if any(path.startswith(prefix) for prefix in denied_paths):
        return False
    return any(path.startswith(prefix) for prefix in allowed_paths)


def is_url_in_scope(url: str, request: ScanRequest) -> bool:
    try:
        normalized = normalize_url(url)
        parts = urlsplit(normalized)
        _ = parts.port
    except (ValueError, TypeError):
        return False
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
        return False
    target_host = urlsplit(str(request.target_url)).hostname or ""
    allowed_hosts = request.allowed_hosts or [target_host.lower()]
    return _host_allowed(parts.hostname, allowed_hosts) and _path_allowed(
        parts.path or "/", request.allowed_paths, request.denied_paths
    )


async def _resolved_addresses(hostname: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    def resolve() -> list[tuple]:
        return socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)

    try:
        records = await asyncio.to_thread(resolve)
    except socket.gaierror as exc:
        raise ScopeError(f"目标域名解析失败：{hostname}") from exc
    return {ipaddress.ip_address(record[4][0]) for record in records}


def _public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_reserved or address.is_unspecified
    )


async def validate_request_scope(request: ScanRequest, *, allow_lab_mode: bool) -> None:
    if not request.authorization_confirmed:
        raise ScopeError("必须确认已经获得目标网站授权")
    target = str(request.target_url)
    parts = urlsplit(target)
    if parts.username or parts.password:
        raise ScopeError("目标 URL 不允许包含用户名或密码")
    if not is_url_in_scope(target, request):
        raise ScopeError("目标 URL 不在声明的授权范围内")
    if request.lab_mode and not allow_lab_mode:
        raise ScopeError("服务器未启用本地靶场模式")
    if request.lab_mode:
        return
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = await _resolved_addresses(parts.hostname or "", port)
    if not addresses or any(not _public_address(address) for address in addresses):
        raise ScopeError("生产模式拒绝私有、回环、链路本地或保留地址")


async def validate_fetch_target(url: str, request: ScanRequest, *, allow_lab_mode: bool) -> str:
    normalized = normalize_url(url)
    if not is_url_in_scope(normalized, request):
        raise ScopeError("抓取地址超出授权范围")
    if request.lab_mode and allow_lab_mode:
        return normalized
    parts = urlsplit(normalized)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = await _resolved_addresses(parts.hostname or "", port)
    if not addresses or any(not _public_address(address) for address in addresses):
        raise ScopeError("解析结果包含非公网地址，已停止抓取")
    return normalized
