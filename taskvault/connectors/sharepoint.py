"""SharePoint / OneDrive documents via Microsoft Graph."""

from __future__ import annotations

from typing import Any

from .base import HttpClient, quote


class SharePointConnector:
    """key = drive item id, or a path inside the site's default library (e.g. "Policies/refunds.txt")."""

    def __init__(self, site_id: str, client: HttpClient | None = None, token: Any = None,
                 aliases: dict[str, str] | None = None, max_bytes: int = 2_000_000, transport: Any = None):
        self.client = client or HttpClient("https://graph.microsoft.com/v1.0", token=token, transport=transport)
        self.site, self.aliases, self.max_bytes = quote(site_id), aliases or {}, max_bytes

    def _item_path(self, key: str) -> str:
        if "/" in key or "." in key:
            if ".." in key.split("/"):
                raise ValueError("path traversal is not allowed")
            safe = "/".join(quote(p) for p in key.strip("/").split("/"))
            return f"/sites/{self.site}/drive/root:/{safe}:"
        return f"/sites/{self.site}/drive/items/{quote(key)}"

    def __call__(self, key: Any) -> dict | None:
        path = self._item_path(self.aliases.get(str(key), str(key)))
        meta = self.client.request("GET", path, allow_404=True)
        if meta is None:
            return None
        if int(meta.get("size") or 0) > self.max_bytes:
            raise ValueError(f"{meta.get('name')} is larger than max_bytes")
        content = self.client.request("GET", f"{path}/content", raw=True)
        return {"name": meta.get("name"), "modified": meta.get("lastModifiedDateTime"),
                "web_url": meta.get("webUrl"), "body": content.text}
