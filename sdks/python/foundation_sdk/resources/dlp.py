"""DLP resource — data loss prevention, content scanning, download interception."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class DLPResource:
    """Data loss prevention: classification checks, content scanning, download policies."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def check_download(self, *, file_id: str, destination: str = "laptop") -> dict[str, Any]:
        return self._t.request("POST", "/api/dlp/v1/check-download",
                                json={"file_id": file_id, "destination": destination})

    async def check_download_async(
        self, *, file_id: str, destination: str = "laptop"
    ) -> dict[str, Any]:
        return await self._t.request_async("POST", "/api/dlp/v1/check-download",
                                            json={"file_id": file_id,
                                                  "destination": destination})

    def scan_content(self, *, content: str, content_type: str = "text",
                      sensitivity_threshold: str = "L4") -> dict[str, Any]:
        return self._t.request("POST", "/api/dlp/v1/scan",
                                json={"content": content, "content_type": content_type,
                                      "sensitivity_threshold": sensitivity_threshold})

    def classify_file(self, *, file_id: str, sensitivity: str,
                       reason: str = "") -> dict[str, Any]:
        return self._t.request("POST", "/api/dlp/v1/classify",
                                json={"file_id": file_id, "sensitivity": sensitivity,
                                      "reason": reason})

    def get_sensitive_words(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/dlp/v1/sensitive-words")

    def add_sensitive_word(self, *, word: str, category: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/dlp/v1/sensitive-words",
                                json={"word": word, "category": category})
