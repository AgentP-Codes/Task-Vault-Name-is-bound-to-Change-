"""Generic REST APIs."""

from __future__ import annotations

from typing import Any

from .base import HttpClient, quote


class RESTConnector:
    """GET a record: RESTConnector(client, "/customers/{key}", pick=["name", "email"])."""

    def __init__(self, client: HttpClient, path_template: str, pick: list[str] | None = None,
                 unwrap: str | None = None):
        if "{key}" not in path_template:
            raise ValueError("path_template needs {key}")
        self.client, self.path, self.pick, self.unwrap = client, path_template, pick, unwrap

    def __call__(self, key: Any) -> dict | None:
        data = self.client.request("GET", self.path.format(key=quote(key)), allow_404=True)
        if data is None:
            return None
        if self.unwrap:
            data = data.get(self.unwrap)
        return {k: data.get(k) for k in self.pick} if self.pick else data


class RESTSink:
    """POST/PUT/PATCH to a fixed endpoint; sink arguments become the JSON body."""

    def __init__(self, client: HttpClient, method: str, path: str, allowed_args: list[str] | None = None):
        self.client, self.method, self.path, self.allowed = client, method.upper(), path, allowed_args

    def __call__(self, **args: Any) -> Any:
        if self.allowed is not None and (bad := set(args) - set(self.allowed)):
            raise ValueError(f"unexpected arguments {sorted(bad)}")
        return self.client.request(self.method, self.path, json_body=args)
