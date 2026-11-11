"""Pinned byte-custody bridge for Kaggle uploads and replay downloads.

The parent process exchanges payloads only through anonymous pipes.  No caller-
controlled pathname is opened after the parent has verified an archive, and no
downloaded replay is exposed through a mutable filesystem path before hashing
and parsing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from kaggle.api.kaggle_api_extended import KaggleApi
from kagglesdk.competitions.types.competition_api_service import (
    ApiCreateSubmissionRequest,
    ApiGetEpisodeReplayRequest,
    ApiStartSubmissionUploadRequest,
)


def _api() -> KaggleApi:
    api = KaggleApi()
    api.authenticate()
    return api


def _read_response_bytes(response: Any) -> bytes:
    if type(response).__name__ == "HTTPResponse":
        chunks = []
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    return b"".join(chunk for chunk in response.iter_content(1024 * 1024) if chunk)


def _upload(args: argparse.Namespace) -> int:
    payload = sys.stdin.buffer.read()
    actual_sha = hashlib.sha256(payload).hexdigest()
    if actual_sha != args.archive_sha256:
        raise ValueError("stdin archive bytes do not match the authorized SHA-256")
    if os.path.basename(args.archive_name) != args.archive_name:
        raise ValueError("archive_name must be a basename")

    api = _api()
    with api.build_kaggle_client() as kaggle:
        request = ApiStartSubmissionUploadRequest()
        request.competition_name = args.competition
        request.file_name = args.archive_name
        request.content_length = len(payload)
        request.last_modified_epoch_seconds = int(time.time())
        upload = kaggle.competitions.competition_api_client.start_submission_upload(request)

        session = requests.Session()
        retries = Retry(total=10, backoff_factor=0.5, allowed_methods=frozenset({"PUT"}))
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        response = session.put(
            upload.create_url,
            data=payload,
            headers={"Content-Length": str(len(payload))},
            timeout=300,
        )
        if response.status_code not in {200, 201}:
            raise RuntimeError(f"Kaggle byte upload failed with HTTP {response.status_code}")

        submit = ApiCreateSubmissionRequest()
        submit.competition_name = args.competition
        submit.blob_file_tokens = upload.token
        submit.submission_description = args.description
        created = kaggle.competitions.competition_api_client.create_submission(submit)

    result = {
        "archive_name": args.archive_name,
        "archive_sha256": actual_sha,
        "content_length": len(payload),
        "response_message": str(getattr(created, "message", "")),
    }
    sys.stdout.buffer.write(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    return 0


def _replay(args: argparse.Namespace) -> int:
    api = _api()
    with api.build_kaggle_client() as kaggle:
        request = ApiGetEpisodeReplayRequest()
        request.episode_id = int(args.episode_id)
        response = kaggle.competitions.competition_api_client.get_episode_replay(request)
        payload = _read_response_bytes(response)
    replay = json.loads(payload.decode("utf-8"))
    info = replay.get("info")
    bound_episode_id = info.get("EpisodeId", replay.get("id")) if isinstance(info, dict) else replay.get("id")
    if str(bound_episode_id) != str(args.episode_id):
        raise ValueError("authenticated replay ID mismatch")
    sys.stdout.buffer.write(payload)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    upload = subparsers.add_parser("upload")
    upload.add_argument("--competition", required=True)
    upload.add_argument("--archive-name", required=True)
    upload.add_argument("--archive-sha256", required=True)
    upload.add_argument("--description", required=True)
    replay = subparsers.add_parser("replay")
    replay.add_argument("--episode-id", required=True)
    args = parser.parse_args()
    if args.operation == "upload":
        return _upload(args)
    return _replay(args)


if __name__ == "__main__":
    raise SystemExit(main())
