"""Send email over SMTP (STARTTLS)."""

from __future__ import annotations

import smtplib
from collections.abc import Callable
from email.message import EmailMessage
from typing import Any


class SMTPSink:
    def __init__(self, host: str, port: int = 587, username: str | None = None, password: str | None = None,
                 sender: str = "", smtp_factory: Callable[..., Any] = smtplib.SMTP):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.sender, self.smtp_factory = sender, smtp_factory

    def __call__(self, to: str | list[str], subject: str, body: str) -> str:
        msg = EmailMessage()
        msg["From"], msg["Subject"] = self.sender, subject
        msg["To"] = ", ".join(to) if isinstance(to, list) else to
        msg.set_content(body)
        with self.smtp_factory(self.host, self.port) as s:
            s.starttls()
            if self.username:
                s.login(self.username, self.password or "")
            s.send_message(msg)
        return "sent"
