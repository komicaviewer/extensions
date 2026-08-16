#!/usr/bin/env python3
"""Destination-owned admission policy for the NewsHub extension distribution tree."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

from trusted_metadata import TrustedMetadataError, verify_repository


LEGACY_REGISTRY_ASSET = "assets/newshub-extension.json"
APK_NAME_PATTERN = re.compile(r"^newshub-([a-z0-9_-]+)-v(.+)\.apk$")
PACKAGE_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
INDEX_SOURCE_FIELDS = ("id", "name", "lang", "baseUrl")
POLICY_SOURCE_FIELDS = INDEX_SOURCE_FIELDS + ("service", "protocol", "policyHash")
MAX_APK_BYTES = 100 * 1024 * 1024
MAX_ICON_BYTES = 10 * 1024 * 1024
MAX_DEX_BYTES = 200 * 1024 * 1024


class AdmissionError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionError(message)


def load_json(path: Path, label: str):
    require(path.is_file() and not path.is_symlink(), f"{label} must be a regular file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError(f"invalid {label}: {error}") from error


def safe_child(root: Path, filename: str, label: str) -> Path:
    require(isinstance(filename, str) and filename, f"{label} filename must be non-empty")
    require(Path(filename).name == filename, f"{label} filename must not contain a path: {filename}")
    child = root / filename
    require(child.is_file() and not child.is_symlink(), f"missing regular {label}: {filename}")
    return child


def normalized_fingerprint(value: str) -> str:
    normalized = re.sub(r"[\s:]", "", value).lower()
    require(SHA256_PATTERN.fullmatch(normalized) is not None, "invalid SHA-256 signer fingerprint")
    return normalized


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_tool(command: list[str], label: str) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AdmissionError(f"{label} failed to run: {error}") from error
    require(result.returncode == 0, f"{label} failed: {result.stderr.strip()[:500]}")
    return result.stdout


def apk_badging(apk: Path, aapt: str) -> tuple[str, int, str]:
    output = run_tool([aapt, "dump", "badging", str(apk)], f"aapt for {apk.name}")
    match = re.search(
        r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']*)'",
        output,
        re.MULTILINE,
    )
    require(match is not None, f"aapt returned no package metadata for {apk.name}")
    return match.group(1), int(match.group(2)), match.group(3)


def apk_signing_fingerprints(apk: Path, apksigner: str) -> set[str]:
    output = run_tool(
        [apksigner, "verify", "--verbose", "--print-certs", str(apk)],
        f"apksigner for {apk.name}",
    )
    matches = re.findall(r"^Signer #\d+ certificate SHA-256 digest: (.+)$", output, re.MULTILINE)
    require(bool(matches), f"apksigner returned no SHA-256 certificate for {apk.name}")
    return {normalized_fingerprint(match) for match in matches}


def inspect_apk_payload(apk: Path) -> None:
    require(apk.stat().st_size <= MAX_APK_BYTES, f"APK exceeds size limit: {apk.name}")
    try:
        with zipfile.ZipFile(apk) as archive:
            names = {item.filename for item in archive.infolist()}
            require(
                LEGACY_REGISTRY_ASSET not in names,
                f"APK contains forbidden legacy registry {LEGACY_REGISTRY_ASSET}: {apk.name}",
            )
            dex_infos = [item for item in archive.infolist() if re.fullmatch(r"classes\d*\.dex", item.filename)]
            require(bool(dex_infos), f"APK contains no classes.dex: {apk.name}")
            dex_size = sum(item.file_size for item in dex_infos)
            require(dex_size <= MAX_DEX_BYTES, f"DEX payload exceeds size limit: {apk.name}")
    except (OSError, zipfile.BadZipFile) as error:
        raise AdmissionError(f"invalid APK payload for {apk.name}: {error}") from error


def validate_source_list(sources, label: str, fields=INDEX_SOURCE_FIELDS) -> dict[str, dict]:
    require(isinstance(sources, list) and sources, f"{label} sources must be a non-empty array")
    by_id = {}
    for source in sources:
        require(isinstance(source, dict), f"{label} source must be an object")
        for field in fields:
            if field == "protocol":
                require(source.get(field) == 2, f"{label} source protocol must equal 2")
            else:
                require(isinstance(source.get(field), str) and source[field].strip(), f"{label} source {field} missing")
        require(
            set(source) == set(fields),
            f"{label} source fields must be exactly {fields}: {source['id']}",
        )
        require(source["id"] not in by_id, f"duplicate Source id in {label}: {source['id']}")
        require(source["baseUrl"].startswith("https://"), f"Source baseUrl must use HTTPS: {source['id']}")
        if "policyHash" in fields:
            require(SHA256_PATTERN.fullmatch(source["policyHash"]) is not None, f"invalid policyHash: {source['id']}")
        by_id[source["id"]] = source
    return by_id


def validate_icon(icon: Path) -> None:
    require(icon.stat().st_size <= MAX_ICON_BYTES, f"icon exceeds size limit: {icon.name}")
    with icon.open("rb") as file:
        require(file.read(8) == b"\x89PNG\r\n\x1a\n", f"icon is not a PNG: {icon.name}")


def load_index(path: Path, label: str) -> list[dict]:
    index = load_json(path, label)
    require(isinstance(index, list), f"{label} root must be an array")
    require(all(isinstance(entry, dict) for entry in index), f"{label} entries must be objects")
    return index


def tree_snapshot(root: Path) -> dict[str, tuple]:
    """Hash a checkout without trusting candidate-controlled Git metadata."""
    snapshot = {}
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = [directory for directory in directories if directory != ".git"]

        for directory in list(directories):
            path = current_path / directory
            if path.is_symlink():
                relative = path.relative_to(root).as_posix()
                snapshot[relative] = ("symlink", os.readlink(path))
                directories.remove(directory)

        for filename in filenames:
            path = current_path / filename
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            if path.is_symlink():
                snapshot[relative] = ("symlink", mode, os.readlink(path))
            elif path.is_file():
                snapshot[relative] = ("file", mode, sha256_file(path))
            else:
                snapshot[relative] = ("other", mode)
    return snapshot


def is_allowed_distribution_path(path: str) -> bool:
    return (
        path in {"index.json", "index.min.json", "metadata/timestamp.json"}
        or re.fullmatch(r"(?:apk|icon)/[^/]+", path) is not None
        or re.fullmatch(r"targets/apk/[^/]+\.apk", path) is not None
        or re.fullmatch(r"metadata/[1-9][0-9]*\.(?:snapshot|targets)\.json", path) is not None
    )


def validate_trusted_target_bindings(targets_signed: dict, entries: dict[str, dict], releases: dict, pins: dict[str, set[str]]) -> None:
    targets = targets_signed.get("targets")
    require(isinstance(targets, dict), "trusted targets metadata missing")
    expected_paths = {f"apk/{entry['apkName']}" for entry in entries.values()}
    require(set(targets) == expected_paths, "trusted target set is not exact")
    for package, entry in entries.items():
        custom = targets[f"apk/{entry['apkName']}"]["custom"]
        require(custom["packageName"] == package, f"trusted target package mismatch: {package}")
        require(custom["versionCode"] == entry["versionCode"], f"trusted target versionCode mismatch: {package}")
        require(custom["versionName"] == entry["versionName"], f"trusted target versionName mismatch: {package}")
        require(custom["name"] == releases[package]["name"], f"trusted target name mismatch: {package}")
        require(custom["lang"] == entry["lang"], f"trusted target lang mismatch: {package}")
        require(set(custom["apkSignerPins"]) == pins[package], f"trusted target signer pins mismatch: {package}")
        target_sources = {
            source["id"]: source for source in custom["sources"]
            if isinstance(source, dict) and isinstance(source.get("id"), str)
        }
        expected_sources = [{
            "id": source["id"], "service": source["service"],
            "protocol": source["protocol"], "policyHash": source["policyHash"],
            "networkPolicy": target_sources.get(source["id"], {}).get("networkPolicy"),
            "name": source["name"], "lang": source["lang"], "baseUrl": source["baseUrl"],
        } for source in releases[package]["sources"]]
        require(custom["sources"] == expected_sources, f"trusted target Source binding mismatch: {package}")


def validate_changed_paths(candidate: Path, base: Path) -> None:
    candidate_snapshot = tree_snapshot(candidate)
    base_snapshot = tree_snapshot(base)
    changed_paths = sorted(
        path
        for path in set(candidate_snapshot).union(base_snapshot)
        if candidate_snapshot.get(path) != base_snapshot.get(path)
    )
    forbidden_paths = [path for path in changed_paths if not is_allowed_distribution_path(path)]
    require(not forbidden_paths, f"candidate changed forbidden paths: {forbidden_paths}")


def validate_distribution(
    candidate: Path, base: Path, policy_root: Path, aapt: str, apksigner: str,
    *, trusted_metadata_verifier=verify_repository,
) -> None:
    candidate = candidate.resolve()
    base = base.resolve()
    policy_root = policy_root.resolve()

    catalog = load_json(policy_root / "admission_policy.json", "admission policy")
    require(catalog.get("schemaVersion") == 2, "unsupported release catalog schemaVersion")
    releases = catalog.get("releases")
    require(isinstance(releases, dict) and releases, "release catalog must define releases")
    require(len(releases) == catalog.get("expectedReleaseCount"), "release catalog count is inconsistent")
    trust = catalog.get("trustedRepository")
    require(isinstance(trust, dict) and trust.get("provisioned") is True, "production repository trust is unprovisioned")

    policy_sources_by_package = {}
    signer_pins_by_package = {}
    for package, release in releases.items():
        policy_sources_by_package[package] = validate_source_list(
            release.get("sources"),
            f"admission policy {package}",
            POLICY_SOURCE_FIELDS,
        )
        pins = release.get("signerPins")
        require(isinstance(pins, list), f"signerPins must be an array for {package}")
        require(bool(pins), f"production signer pins are unprovisioned for {package}")
        normalized_pins = {normalized_fingerprint(pin) for pin in pins if isinstance(pin, str)}
        require(len(normalized_pins) == len(pins), f"invalid or duplicate signerPins for {package}")
        signer_pins_by_package[package] = normalized_pins

    expected_source_ids = {
        source_id
        for sources in policy_sources_by_package.values()
        for source_id in sources
    }
    source_id_count = sum(len(sources) for sources in policy_sources_by_package.values())
    require(len(expected_source_ids) == source_id_count, "release catalog contains duplicate Source ids")
    require(source_id_count == catalog.get("expectedSourceCount"), "release catalog Source count is inconsistent")

    validate_changed_paths(candidate, base)

    candidate_repo = load_json(candidate / "repo.json", "candidate repo.json")
    base_repo = load_json(base / "repo.json", "base repo.json")
    require(candidate_repo == base_repo, "repo.json changes are not authorized by the current base policy")
    index = load_index(candidate / "index.json", "candidate index.json")
    min_index = load_index(candidate / "index.min.json", "candidate index.min.json")
    require(index == min_index, "index.json and index.min.json are not semantically equivalent")

    packages = [entry.get("pkg") for entry in index]
    require(all(isinstance(package, str) and package for package in packages), "candidate package id missing")
    require(len(packages) == len(set(packages)), "candidate index contains duplicate packages")
    require(set(packages) == set(releases), f"candidate package set is not exact: {sorted(packages)}")
    entries = {entry["pkg"]: entry for entry in index}

    base_entries = {entry.get("pkg"): entry for entry in load_index(base / "index.json", "base index.json")}
    removed = set(base_entries) - set(entries)
    allowed_removals = set(catalog.get("allowedPackageRemovals", []))
    unauthorized_removals = removed - allowed_removals
    require(not unauthorized_removals, f"unauthorized package removals: {sorted(unauthorized_removals)}")

    apk_dir = candidate / "apk"
    icon_dir = candidate / "icon"
    require(apk_dir.is_dir() and not apk_dir.is_symlink(), "candidate apk directory missing")
    require(icon_dir.is_dir() and not icon_dir.is_symlink(), "candidate icon directory missing")
    actual_apks = {path.name for path in apk_dir.iterdir() if path.name != ".gitkeep"}
    actual_icons = {path.name for path in icon_dir.iterdir() if path.name != ".gitkeep"}
    referenced_apks = {entry.get("apkName") for entry in index}
    referenced_icons = {entry.get("iconName") for entry in index}
    require(actual_apks == referenced_apks, f"APK directory does not match index: {sorted(actual_apks)}")
    require(actual_icons == referenced_icons, f"icon directory does not match index: {sorted(actual_icons)}")

    seen_source_ids = set()
    for package, expected in releases.items():
        entry = entries[package]
        require(PACKAGE_PATTERN.fullmatch(package) is not None, f"invalid package name: {package}")
        require(entry.get("name") == expected["name"], f"unexpected extension name for {package}")
        require(isinstance(entry.get("versionCode"), int) and not isinstance(entry["versionCode"], bool), f"invalid versionCode for {package}")
        require(entry["versionCode"] > 0, f"versionCode must be positive for {package}")
        require(isinstance(entry.get("versionName"), str) and entry["versionName"], f"invalid versionName for {package}")
        require(isinstance(entry.get("lang"), str), f"invalid lang for {package}")

        expected_apk_name = f"newshub-{expected['module']}-v{entry['versionName']}.apk"
        require(entry.get("apkName") == expected_apk_name, f"unexpected APK filename for {package}")
        require(entry.get("iconName") == expected["iconName"], f"unexpected icon filename for {package}")

        apk = safe_child(apk_dir, entry["apkName"], "APK")
        icon = safe_child(icon_dir, entry["iconName"], "icon")
        validate_icon(icon)

        declared_sha = entry.get("sha256")
        require(isinstance(declared_sha, str) and SHA256_PATTERN.fullmatch(declared_sha) is not None, f"invalid SHA-256 for {package}")
        require(sha256_file(apk) == declared_sha, f"APK SHA-256 mismatch for {package}")

        actual_package, actual_version_code, actual_version_name = apk_badging(apk, aapt)
        require(actual_package == package, f"APK package mismatch for {package}: {actual_package}")
        require(actual_version_code == entry["versionCode"], f"APK versionCode mismatch for {package}")
        require(actual_version_name == entry["versionName"], f"APK versionName mismatch for {package}")
        actual_signers = apk_signing_fingerprints(apk, apksigner)
        require(
            actual_signers.issubset(signer_pins_by_package[package]),
            f"APK signer mismatch for {package}: {sorted(actual_signers)}",
        )

        index_sources = validate_source_list(entry.get("sources"), f"index {package}")
        inspect_apk_payload(apk)
        expected_sources = policy_sources_by_package[package]
        expected_ids = set(expected_sources)
        require(set(index_sources) == expected_ids, f"unexpected index Source set for {package}")

        for source_id in expected_ids:
            require(source_id not in seen_source_ids, f"Source belongs to multiple APKs: {source_id}")
            seen_source_ids.add(source_id)
            index_source = index_sources[source_id]
            expected_source = expected_sources[source_id]
            for field in INDEX_SOURCE_FIELDS:
                require(
                    index_source[field] == expected_source[field],
                    f"Source {field} differs from destination policy: {source_id}",
                )

        languages = {source["lang"] for source in index_sources.values()}
        expected_lang = next(iter(languages)) if len(languages) == 1 else ""
        require(entry["lang"] == expected_lang, f"extension lang mismatch for {package}")

        previous = base_entries.get(package)
        if previous is not None:
            previous_code = previous.get("versionCode")
            require(isinstance(previous_code, int), f"base versionCode invalid for {package}")
            require(entry["versionCode"] >= previous_code, f"versionCode downgrade for {package}")
            if entry["versionCode"] == previous_code:
                require(entry["sha256"] == previous.get("sha256"), f"APK changed without versionCode bump for {package}")

    require(seen_source_ids == expected_source_ids, "candidate Source set is incomplete")
    try:
        trusted_targets = trusted_metadata_verifier(
            policy_root / trust["rootPath"], candidate / "metadata", candidate / "targets",
        )
    except (KeyError, TypeError, TrustedMetadataError) as error:
        raise AdmissionError(f"trusted repository metadata rejected: {error}") from error
    validate_trusted_target_bindings(trusted_targets, entries, releases, signer_pins_by_package)
    print(
        "Distribution admission passed: "
        f"APKs={len(entries)}, Sources={len(seen_source_ids)}, signerPolicy=per-package",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--policy-root", required=True, type=Path)
    parser.add_argument("--aapt", required=True)
    parser.add_argument("--apksigner", required=True)
    args = parser.parse_args(argv)
    try:
        validate_distribution(args.candidate, args.base, args.policy_root, args.aapt, args.apksigner)
    except AdmissionError as error:
        print(f"Distribution admission rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
