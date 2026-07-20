#!/usr/bin/env python3
"""Verify that raw.githubusercontent.com serves the just-published distribution."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024


class RemoteVerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RemoteVerificationError(message)


def read_limited(response, label: str) -> bytes:
    payload = response.read(MAX_DOWNLOAD_BYTES + 1)
    require(len(payload) <= MAX_DOWNLOAD_BYTES, f"remote payload exceeds size limit: {label}")
    return payload


def remote_fetcher(raw_base: str, cache_token: str):
    base = raw_base.rstrip("/")

    def fetch(path: str) -> bytes:
        require(Path(path).as_posix() == path and ".." not in Path(path).parts, f"unsafe remote path: {path}")
        encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        url = f"{base}/{encoded_path}?cache-bust={urllib.parse.quote(cache_token, safe='')}"
        request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "newshub-distribution-admission/1"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                require(response.status == 200, f"HTTP {response.status} for {path}")
                return read_limited(response, path)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
            raise RemoteVerificationError(f"failed to fetch {path}: {error}") from error

    return fetch


def parse_json(payload: bytes, label: str):
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RemoteVerificationError(f"invalid remote {label}: {error}") from error


def verify_remote_once(local_root: Path, fetch) -> tuple[int, int]:
    local_index = parse_json((local_root / "index.json").read_bytes(), "local index.json")
    remote_index = parse_json(fetch("index.json"), "index.json")
    remote_min_index = parse_json(fetch("index.min.json"), "index.min.json")
    require(remote_index == local_index, "raw main/index.json does not match local GITHUB_SHA tree")
    require(remote_min_index == remote_index, "raw index.min.json is not equivalent to raw index.json")

    apk_count = 0
    icon_count = 0
    for entry in remote_index:
        apk_name = entry["apkName"]
        icon_name = entry["iconName"]
        require(Path(apk_name).name == apk_name, f"unsafe APK name: {apk_name}")
        require(Path(icon_name).name == icon_name, f"unsafe icon name: {icon_name}")

        remote_apk = fetch(f"apk/{apk_name}")
        local_apk = (local_root / "apk" / apk_name).read_bytes()
        remote_apk_sha = hashlib.sha256(remote_apk).hexdigest()
        require(remote_apk_sha == entry["sha256"], f"raw APK SHA-256 mismatch: {apk_name}")
        require(remote_apk_sha == hashlib.sha256(local_apk).hexdigest(), f"raw APK content mismatch: {apk_name}")
        apk_count += 1

        remote_icon = fetch(f"icon/{icon_name}")
        local_icon = (local_root / "icon" / icon_name).read_bytes()
        require(hashlib.sha256(remote_icon).digest() == hashlib.sha256(local_icon).digest(), f"raw icon content mismatch: {icon_name}")
        icon_count += 1
    return apk_count, icon_count


def verify_with_retries(local_root: Path, raw_base: str, sha: str, attempts: int, delay_seconds: float) -> tuple[int, int, int]:
    require(attempts > 0, "attempts must be positive")
    errors = []
    for attempt in range(1, attempts + 1):
        try:
            apk_count, icon_count = verify_remote_once(
                local_root,
                remote_fetcher(raw_base, f"{sha}-{attempt}"),
            )
            return apk_count, icon_count, attempt
        except (OSError, KeyError, RemoteVerificationError) as error:
            errors.append(f"attempt {attempt}: {error}")
            if attempt < attempts:
                time.sleep(delay_seconds)
    raise RemoteVerificationError("raw main did not converge after finite retries; " + " | ".join(errors))


def write_report(path: Path, *, success: bool, sha: str, detail: str) -> None:
    status = "passed" if success else "failed"
    path.write_text(
        "\n".join([
            "### Raw distribution verification",
            "",
            f"- Status: **{status}**",
            f"- Commit: `{sha}`",
            f"- Detail: {detail}",
            "",
        ]),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-root", required=True, type=Path)
    parser.add_argument("--raw-base", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument("--delay-seconds", type=float, default=10.0)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    try:
        apk_count, icon_count, attempt = verify_with_retries(
            args.local_root.resolve(),
            args.raw_base,
            args.sha,
            args.attempts,
            args.delay_seconds,
        )
        detail = f"raw main converged on attempt {attempt}; APKs={apk_count}, icons={icon_count}"
        write_report(args.report, success=True, sha=args.sha, detail=detail)
        print(detail)
        return 0
    except (OSError, KeyError, RemoteVerificationError) as error:
        write_report(args.report, success=False, sha=args.sha, detail=str(error))
        print(f"Post-publish verification rejected: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
