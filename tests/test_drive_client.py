"""Google Drive client behavior that the fake Drive does not exercise."""

import pytest
from googleapiclient.errors import HttpError

from scoped_drive_mcp.drive_client import (
    DriveAccessError,
    DriveNotFoundError,
    GoogleDriveClient,
    drive_field_mask,
)


class _Resp:
    def __init__(self, status: int):
        self.status = status
        self.reason = "no"


def _http(status: int) -> HttpError:
    return HttpError(_Resp(status), b'{"error":{"message":"Insufficient Permission"}}')


class _Files:
    def __init__(self, calls: list[dict], outcomes: list):
        self.calls = calls
        self.outcomes = outcomes

    def get(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)

        class _Req:
            def execute(self, num_retries=0):
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        return _Req()

    def list(self, **kwargs):
        return self.get(**kwargs)


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


def test_get_file_treats_drive_file_forbidden_as_missing() -> None:
    calls: list[dict] = []
    client = _client(calls, [_http(403)])
    with pytest.raises(DriveNotFoundError):
        client.get_file("doc-from-docs", "id,name")
    assert calls[0]["fields"] == "id,name"


def test_list_files_retries_without_all_drives_for_drive_file() -> None:
    calls: list[dict] = []
    client = _client(calls, [_http(403), {"files": [{"id": "itinerary"}]}])
    listed = client.list_files("'root' in parents", "id,name,shortcutDetails", 10)
    assert listed["files"] == [{"id": "itinerary"}]
    assert calls[0]["corpora"] == "allDrives"
    assert "corpora" not in calls[1]
    assert calls[0]["includeItemsFromAllDrives"] is True
    assert calls[1]["fields"] == "nextPageToken, files(id,name,shortcutDetails(targetId))"


def test_list_files_raises_when_both_corpora_are_refused() -> None:
    client = _client([], [_http(403), _http(403)])
    with pytest.raises(DriveAccessError):
        client.list_files("trashed=false", "id", 10)
