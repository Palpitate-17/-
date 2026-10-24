from __future__ import annotations

import asyncio

import pytest

from app.contracts import ScanRequest
from app.security import ScopeError, is_url_in_scope, validate_request_scope


def _request(**overrides) -> ScanRequest:
    values = {
        "target_url": "http://127.0.0.1:8001/allowed",
        "authorization_confirmed": True,
        "allowed_hosts": ["127.0.0.1"],
        "allowed_paths": ["/allowed"],
        "denied_paths": ["/allowed/private"],
        "lab_mode": False,
    }
    values.update(overrides)
    return ScanRequest(**values)


def test_scope_blocks_host_confusion_and_denied_path():
    request = _request()
    assert is_url_in_scope("http://127.0.0.1:8001/allowed/page", request)
    assert not is_url_in_scope("http://127.0.0.1.evil.invalid/allowed", request)
    assert not is_url_in_scope("http://127.0.0.1:8001/allowed/private/item", request)
    assert not is_url_in_scope("file:///allowed/page", request)


def test_production_mode_rejects_loopback_address():
    with pytest.raises(ScopeError, match="私有、回环"):
        asyncio.run(validate_request_scope(_request(), allow_lab_mode=False))


def test_lab_mode_requires_server_side_enablement():
    with pytest.raises(ScopeError, match="未启用本地靶场模式"):
        asyncio.run(validate_request_scope(_request(lab_mode=True), allow_lab_mode=False))


def test_authorization_confirmation_is_mandatory():
    with pytest.raises(ScopeError, match="获得目标网站授权"):
        asyncio.run(validate_request_scope(
            _request(authorization_confirmed=False, lab_mode=True), allow_lab_mode=True
        ))
