"""Google Drive client behavior that the fake Drive does not exercise."""

import pytest
from googleapiclient.errors import HttpError

from scoped_drive_mcp.drive_client import (
    DriveAccessError,
    DriveExportTooLargeError,
    DriveNotFoundError,
    GoogleDriveClient,
    drive_field_mask,
)


class _Resp:
    def __init__(self, status: int):
        self.status = status
        self.reason = "no"


def _http(status: int, body: bytes = b'{"error":{"message":"Insufficient Permission"}}'):
    return HttpError(_Resp(status), body)


class _Req:
    def __init__(self, outcome):
        self.outcome = outcome
        self.headers: dict[str, str] = {}

    def execute(self, num_retries=0):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class _Files:
    """Records each call's arguments (and its request, for headers) and answers with the
    next outcome: a value, or an exception to raise."""

    def __init__(self, calls: list[dict], outcomes: list):
        self.calls = calls
        self.outcomes = outcomes

    def _next(self, **kwargs) -> _Req:
        request = _Req(self.outcomes.pop(0))
        self.calls.append({**kwargs, "_request": request})
        return request

    get = list = export = get_media = _next


def _client(calls: list[dict], outcomes: list) -> GoogleDriveClient:
    client = GoogleDriveClient(credentials=object())

    class _Svc:
        def files(self):
            return _Files(calls, outcomes)

    client._local.service = _Svc()
    return client


def test_field_mask_asks_for_the_shortcut_target() -> None:
    assert drive_field_mask("id,shortcutDetails") == "id,shortcutDetails(targetId)"
    assert drive_field_mask("shortcutDetails(targetId)") == "shortcutDetails(targetId)"


@pytest.mark.parametrize("status", [403, 404])
def test_get_file_treats_a_hidden_file_as_missing(status: int) -> None:
    """drive.file hides a file this app has never opened, with 403 or 404."""
    calls: list[dict] = []
    client = _client(calls, [_http(status)])
    with pytest.raises(DriveNotFoundError):
        client.get_file("doc-from-docs", "id,name")
    assert calls[0]["fields"] == "id,name"
    with pytest.raises(HttpError):  # any other failure is not "missing"
        _client([], [_http(500)]).get_file("x", "id")


def test_list_files_retries_without_all_drives_for_drive_file() -> None:
    calls: list[dict] = []
    client = _client(calls, [_http(403), {"files": [{"id": "itinerary"}]}])
    listed = client.list_files("'root' in parents", "id,name,shortcutDetails", 10, order_by="name")
    assert listed["files"] == [{"id": "itinerary"}]
    assert calls[0]["corpora"] == "allDrives"
    assert "corpora" not in calls[1]
    assert calls[0]["includeItemsFromAllDrives"] is True
    assert calls[1]["fields"] == "nextPageToken, files(id,name,shortcutDetails(targetId))"
    assert calls[1]["orderBy"] == "name"


def test_list_files_raises_when_both_corpora_are_refused() -> None:
    client = _client([], [_http(403), _http(403)])
    with pytest.raises(DriveAccessError):
        client.list_files("trashed=false", "id", 10)
    # Other errors are not a refusal and are not retried.
    calls: list[dict] = []
    with pytest.raises(HttpError):
        _client(calls, [_http(500)]).list_files("trashed=false", "id", 10)
    assert len(calls) == 1


def test_download_asks_for_only_the_bytes_it_keeps() -> None:
    calls: list[dict] = []
    client = _client(calls, [b"abcdefgh", _http(416)])
    # A server that ignores the Range header is still cut to the limit.
    assert client.download("big", 4) == b"abcd"
    assert calls[0]["_request"].headers["Range"] == "bytes=0-3"
    assert calls[0]["fileId"] == "big"
    # 416 is what Drive returns for an empty file.
    assert client.download("empty", 4) == b""


def test_export_over_drives_limit_is_its_own_error() -> None:
    too_large = _http(403, b'{"error":{"errors":[{"reason":"exportSizeLimitExceeded"}]}}')
    client = _client([], [too_large, _http(403), b"text"])
    with pytest.raises(DriveExportTooLargeError):
        client.export("huge", "text/plain")
    with pytest.raises(HttpError):  # a plain 403 is not "too large"
        client.export("hidden", "text/plain")
    assert client.export("doc", "text/plain") == b"text"
