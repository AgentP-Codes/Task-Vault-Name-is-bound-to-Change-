"""Google Drive documents (Docs exported as plain text, other files downloaded)."""

from __future__ import annotations

from typing import Any

from .base import HttpClient, quote

GOOGLE_DOC = "application/vnd.google-apps.document"
GOOGLE_SHEET = "application/vnd.google-apps.spreadsheet"


class GoogleDriveConnector:
    """key = Drive file id (or an alias from `aliases`, so policies can say `refund_policy`)."""

    def __init__(self, client: HttpClient | None = None, token: Any = None,
                 aliases: dict[str, str] | None = None, max_bytes: int = 2_000_000, transport: Any = None):
        self.client = client or HttpClient("https://www.googleapis.com/drive/v3", token=token, transport=transport)
        self.aliases, self.max_bytes = aliases or {}, max_bytes

    def __call__(self, key: Any) -> dict | None:
        file_id = self.aliases.get(str(key), str(key))
        meta = self.client.request("GET", f"/files/{quote(file_id)}",
                                   params={"fields": "id,name,mimeType,modifiedTime,size",
                                           "supportsAllDrives": "true"}, allow_404=True)
        if meta is None:
            return None
        mime = meta.get("mimeType", "")
        export = f"/files/{quote(file_id)}/export"
        if mime == GOOGLE_DOC:
            r = self.client.request("GET", export, params={"mimeType": "text/plain"}, raw=True)
        elif mime == GOOGLE_SHEET:
            r = self.client.request("GET", export, params={"mimeType": "text/csv"}, raw=True)
        else:
            if int(meta.get("size") or 0) > self.max_bytes:
                raise ValueError(f"{meta.get('name')} is larger than max_bytes")
            r = self.client.request("GET", f"/files/{quote(file_id)}", params={"alt": "media"}, raw=True)
        return {"name": meta.get("name"), "mime_type": mime, "modified": meta.get("modifiedTime"),
                "body": r.text[: self.max_bytes]}
