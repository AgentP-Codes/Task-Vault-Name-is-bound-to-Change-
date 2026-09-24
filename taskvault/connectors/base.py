"""A small HTTP client with an injectable transport (stdlib only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


class HttpError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status, self.body = status, body


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body or b"null")

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Transport(Protocol):
    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> Response: ...


def urllib_transport(timeout: float = 30) -> Transport:
    def send(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Response:
        if not url.lower().startswith(("https://", "http://")):
            raise ValueError("only http(s) URLs are allowed")        # never file:// or custom schemes
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - https URLs from config
                return Response(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as e:
            return Response(e.code, dict(e.headers or {}), e.read())
    return send


TokenSource = Callable[[], str]


class HttpClient:
    def __init__(self, base_url: str, token: str | TokenSource | None = None,
                 headers: dict[str, str] | None = None, transport: Transport | None = None):
        if not base_url.startswith("https://") and not base_url.startswith("http://localhost"):
            raise ValueError("base_url must use https")
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.headers = headers or {}
        self.transport = transport or urllib_transport()

    def _auth(self) -> dict[str, str]:
        if self._token is None:
            return {}
        tok = self._token() if callable(self._token) else self._token
        return {"Authorization": f"Bearer {tok}"}

    def request(self, method: str, path: str, params: dict[str, Any] | None = None,
                json_body: Any = None, raw: bool = False, allow_404: bool = False) -> Any:
        url = path if path.startswith("https://") else self.base_url + "/" + path.lstrip("/")
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json", **self.headers, **self._auth()}
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        r = self.transport(method, url, headers, body)
        if r.status == 404 and allow_404:
            return None
        if r.status >= 400:
            raise HttpError(r.status, r.text)
        return r if raw else (r.json() if r.body else None)


def quote(segment: Any) -> str:
    """URL-encode a single path segment so keys can't change the path."""
    text = str(segment)
    if text in ("", ".", ".."):
        raise ValueError("a key can't be empty, '.' or '..'")
    return urllib.parse.quote(text, safe="")
