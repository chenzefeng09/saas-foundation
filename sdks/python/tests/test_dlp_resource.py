"""DLP SDK request-shape regression tests."""

from __future__ import annotations

from typing import Any

from foundation_sdk.resources.dlp import DLPResource


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, path, kwargs))
        return {"allowed": True}

    async def request_async(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, path, kwargs))
        return {"allowed": True}


def test_check_download_sends_destination_not_clearance() -> None:
    transport = _RecordingTransport()
    resource = DLPResource(transport)  # type: ignore[arg-type]

    resource.check_download(file_id="file_1", destination="usb")

    assert transport.calls == [
        (
            "POST",
            "/api/dlp/v1/check-download",
            {"json": {"file_id": "file_1", "destination": "usb"}},
        )
    ]


async def test_check_download_async_defaults_to_laptop() -> None:
    transport = _RecordingTransport()
    resource = DLPResource(transport)  # type: ignore[arg-type]

    await resource.check_download_async(file_id="file_1")

    assert transport.calls[0][2]["json"] == {
        "file_id": "file_1",
        "destination": "laptop",
    }
