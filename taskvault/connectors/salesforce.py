"""Salesforce via the REST API. Bring an OAuth access token (or a callable that refreshes one)."""

from __future__ import annotations

import re
from typing import Any

from .base import HttpClient, quote

API = "v61.0"
SF_ID = re.compile(r"^[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?$")


class SalesforceConnector:
    """Read one sObject record by Id, or by an external-id / unique field.

        SalesforceConnector(client, "Contact", fields=["Id", "Name", "Email"])            # key = record Id
        SalesforceConnector(client, "Contact", fields=[...], match_field="Customer_Id__c") # key = your id
    """

    def __init__(self, client: HttpClient, sobject: str, fields: list[str], match_field: str | None = None):
        for name in [sobject, *fields, *([match_field] if match_field else [])]:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
                raise ValueError(f"invalid Salesforce name {name!r}")
        self.client, self.sobject, self.fields, self.match = client, sobject, fields, match_field

    def __call__(self, key: Any) -> dict | None:
        if self.match:
            value = str(key).replace("\\", "\\\\").replace("'", "\\'")
            soql = f"SELECT {', '.join(self.fields)} FROM {self.sobject} WHERE {self.match} = '{value}' LIMIT 2"
            data = self.client.request("GET", f"/services/data/{API}/query", params={"q": soql})
            records = data.get("records", [])
            if len(records) > 1:
                raise LookupError(f"{self.match}={key!r} matches more than one {self.sobject}")
            rec = records[0] if records else None
        else:
            if not SF_ID.match(str(key)):
                return None
            rec = self.client.request("GET", f"/services/data/{API}/sobjects/{self.sobject}/{quote(key)}",
                                      params={"fields": ",".join(self.fields)}, allow_404=True)
        if rec is None:
            return None
        return {f: rec.get(f) for f in self.fields}


class SalesforceSink:
    """Create or update records: sink(Id=..., **fields) updates; without Id it creates."""

    def __init__(self, client: HttpClient, sobject: str, writable: list[str]):
        self.client, self.sobject, self.writable = client, sobject, set(writable)

    def __call__(self, Id: str | None = None, **fields: Any) -> Any:  # noqa: N803 - Salesforce naming
        if bad := set(fields) - self.writable:
            raise ValueError(f"fields not writable: {sorted(bad)}")
        base = f"/services/data/{API}/sobjects/{self.sobject}"
        if Id:
            if not SF_ID.match(Id):
                raise ValueError("invalid record Id")
            self.client.request("PATCH", f"{base}/{quote(Id)}", json_body=fields)
            return {"id": Id, "updated": True}
        return self.client.request("POST", base, json_body=fields)
