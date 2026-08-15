#!/usr/bin/env python3
"""Small fail-closed TUF-style repository metadata verifier.

The wire contract intentionally uses only primitives available on Android API 29:
ECDSA P-256/SHA-256, X.509 SPKI public keys and DER encoded signatures.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


EXACT_HOST = re.compile(
    r"^(?=.{1,253}$)(?![0-9.]+$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
KNOWN_CAPABILITIES = {
    "external_link",
    "eyny_challenge_proof",
    "ptt_adult_consent_status",
    "resource_read",
}


class TrustedMetadataError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _parse_expiry(value: object) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TrustedMetadataError("metadata expiry must be UTC RFC3339")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TrustedMetadataError("invalid metadata expiry") from error
    return parsed


def _load(path: Path, label: str) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrustedMetadataError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict) or set(value) != {"signed", "signatures"}:
        raise TrustedMetadataError(f"invalid {label} envelope")
    if not isinstance(value["signed"], dict) or not isinstance(value["signatures"], list):
        raise TrustedMetadataError(f"invalid {label} envelope values")
    return value, raw


def _verify_ecdsa(spki: bytes, signature: bytes, payload: bytes, openssl: str) -> bool:
    if not _is_p256_spki(spki, openssl):
        return False
    with tempfile.TemporaryDirectory(prefix="newshub-tuf-verify-") as directory:
        root = Path(directory)
        public_der = root / "public.der"
        public_pem = root / "public.pem"
        signature_file = root / "signature.der"
        payload_file = root / "payload.json"
        public_der.write_bytes(spki)
        signature_file.write_bytes(signature)
        payload_file.write_bytes(payload)
        converted = subprocess.run(
            [openssl, "pkey", "-pubin", "-inform", "DER", "-in", str(public_der), "-out", str(public_pem)],
            capture_output=True,
            timeout=20,
        )
        if converted.returncode != 0:
            return False
        verified = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(public_pem), "-signature", str(signature_file), str(payload_file)],
            capture_output=True,
            timeout=20,
        )
        return verified.returncode == 0


def _is_p256_spki(spki: bytes, openssl: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="newshub-tuf-key-") as directory:
        public_der = Path(directory) / "public.der"
        public_der.write_bytes(spki)
        inspected = subprocess.run(
            [openssl, "pkey", "-pubin", "-inform", "DER", "-in", str(public_der), "-text_pub", "-noout"],
            capture_output=True,
            timeout=20,
        )
        return inspected.returncode == 0 and b"ASN1 OID: prime256v1" in inspected.stdout


def _key_bytes(root_signed: dict, keyid: str) -> bytes:
    key = root_signed.get("keys", {}).get(keyid)
    if not isinstance(key, dict) or key.get("keytype") != "ecdsa" or key.get("scheme") != "ecdsa-sha2-nistp256":
        raise TrustedMetadataError(f"unsupported or missing key: {keyid}")
    try:
        spki = base64.b64decode(key["keyval"]["public"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise TrustedMetadataError(f"invalid public key: {keyid}") from error
    if sha256_bytes(spki) != keyid:
        raise TrustedMetadataError(f"public key id mismatch: {keyid}")
    return spki


def _verify_role(envelope: dict, role: str, root_signed: dict, openssl: str) -> None:
    role_policy = root_signed.get("roles", {}).get(role)
    if not isinstance(role_policy, dict):
        raise TrustedMetadataError(f"missing role policy: {role}")
    keyids = role_policy.get("keyids")
    threshold = role_policy.get("threshold")
    if not isinstance(keyids, list) or len(keyids) != len(set(keyids)) or not isinstance(threshold, int):
        raise TrustedMetadataError(f"invalid role policy: {role}")
    if threshold < 1 or threshold > len(keyids):
        raise TrustedMetadataError(f"unprovisioned role threshold: {role}")
    payload = canonical_json(envelope["signed"])
    valid: set[str] = set()
    for item in envelope["signatures"]:
        if not isinstance(item, dict) or set(item) != {"keyid", "sig"}:
            raise TrustedMetadataError(f"invalid signature entry for {role}")
        keyid = item["keyid"]
        if keyid not in keyids or keyid in valid:
            continue
        try:
            signature = base64.b64decode(item["sig"], validate=True)
        except (TypeError, ValueError) as error:
            raise TrustedMetadataError(f"invalid signature encoding for {role}") from error
        if _verify_ecdsa(_key_bytes(root_signed, keyid), signature, payload, openssl):
            valid.add(keyid)
    if len(valid) < threshold:
        raise TrustedMetadataError(f"signature threshold not met for {role}")


def _check_common(envelope: dict, expected_type: str, now: dt.datetime) -> None:
    signed = envelope["signed"]
    if signed.get("_type") != expected_type or signed.get("specVersion") != "1.0":
        raise TrustedMetadataError(f"unexpected metadata type/spec: {expected_type}")
    version = signed.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise TrustedMetadataError(f"invalid metadata version: {expected_type}")
    if _parse_expiry(signed.get("expires")) <= now:
        raise TrustedMetadataError(f"expired metadata: {expected_type}")


def _check_root_shape(root_signed: dict) -> None:
    required = {
        "_type", "specVersion", "version", "expires", "consistentSnapshot",
        "keys", "roles",
    }
    if set(root_signed) != required:
        raise TrustedMetadataError("root metadata fields are not exact")
    keys = root_signed.get("keys")
    roles = root_signed.get("roles")
    if not isinstance(keys, dict) or not keys:
        raise TrustedMetadataError("root keys must be provisioned")
    if not isinstance(roles, dict) or set(roles) != {"root", "targets", "snapshot", "timestamp"}:
        raise TrustedMetadataError("root roles are not exact")


def _check_root_key_material(root_signed: dict, openssl: str) -> None:
    for keyid in root_signed["keys"]:
        if not _is_p256_spki(_key_bytes(root_signed, keyid), openssl):
            raise TrustedMetadataError(f"root key must use P-256: {keyid}")


def _exact_hosts(value: object, relative: str, scope: str, *, allow_empty: bool) -> list[str]:
    minimum = 0 if allow_empty else 1
    if (
        not isinstance(value, list) or len(value) not in range(minimum, 33)
        or value != sorted(set(value))
        or any(not isinstance(host, str) or EXACT_HOST.fullmatch(host) is None for host in value)
    ):
        raise TrustedMetadataError(f"invalid target Source {scope} exact hosts: {relative}")
    return value


def _check_network_operation(operation: object, relative: str) -> None:
    if not isinstance(operation, dict) or set(operation) != {
        "name", "methods", "pathPrefixes", "credentialed",
    }:
        raise TrustedMetadataError(f"invalid target Source operations: {relative}")
    methods = operation["methods"]
    prefixes = operation["pathPrefixes"]
    if (
        operation["name"] != "source_read"
        or not isinstance(methods, list) or not methods or len(methods) > 2
        or methods != sorted(set(methods)) or any(method not in {"GET", "HEAD"} for method in methods)
        or not isinstance(prefixes, list) or not prefixes or len(prefixes) > 32
        or prefixes != sorted(set(prefixes))
        or any(
            not isinstance(prefix, str) or not prefix.startswith("/") or len(prefix) > 256
            or any(ord(character) < 0x20 or ord(character) == 0x7f for character in prefix)
            for prefix in prefixes
        )
        or not isinstance(operation["credentialed"], bool)
    ):
        raise TrustedMetadataError(f"invalid target Source operations: {relative}")


def _check_source_network_policy(source: dict, relative: str) -> None:
    policy = source.get("networkPolicy")
    if not isinstance(policy, dict):
        raise TrustedMetadataError(f"invalid target Source networkPolicy: {relative}")
    if "schemaVersion" not in policy:
        if set(policy) != {"exactHosts", "operations", "namedCapabilities"}:
            raise TrustedMetadataError(f"invalid target Source networkPolicy: {relative}")
        hosts = _exact_hosts(policy["exactHosts"], relative, "request", allow_empty=False)
        operations = policy["operations"]
        if not isinstance(operations, list) or len(operations) != 1:
            raise TrustedMetadataError(f"invalid target Source operations: {relative}")
        _check_network_operation(operations[0], relative)
        expected_operation = {
            "name": "source_read",
            "methods": ["GET", "HEAD"],
            "pathPrefixes": ["/"],
            "credentialed": True,
        }
        if operations != [expected_operation]:
            raise TrustedMetadataError(f"invalid target Source operations: {relative}")
        all_hosts = set(hosts)
    else:
        if set(policy) != {
            "schemaVersion", "request", "resource", "external", "auth", "namedCapabilities",
        } or policy["schemaVersion"] != 2 or isinstance(policy["schemaVersion"], bool):
            raise TrustedMetadataError(f"invalid target Source networkPolicy: {relative}")
        for scope in ("request", "resource", "external", "auth"):
            value = policy[scope]
            expected = {"rules"} if scope == "request" else {"exactHosts"}
            if not isinstance(value, dict) or set(value) != expected:
                raise TrustedMetadataError(f"invalid target Source {scope} policy: {relative}")
        rules = policy["request"]["rules"]
        if not isinstance(rules, list) or len(rules) not in range(1, 33):
            raise TrustedMetadataError(f"invalid target Source request rules: {relative}")
        request_hosts: set[str] = set()
        canonical_rules: set[bytes] = set()
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {"exactHosts", "operation"}:
                raise TrustedMetadataError(f"invalid target Source request rule: {relative}")
            rule_hosts = _exact_hosts(rule["exactHosts"], relative, "request", allow_empty=False)
            _check_network_operation(rule["operation"], relative)
            encoded_rule = canonical_json(rule)
            if encoded_rule in canonical_rules:
                raise TrustedMetadataError(f"duplicate target Source request rule: {relative}")
            canonical_rules.add(encoded_rule)
            request_hosts.update(rule_hosts)
        scoped_hosts = {
            scope: _exact_hosts(policy[scope]["exactHosts"], relative, scope, allow_empty=True)
            for scope in ("resource", "external", "auth")
        }
        all_hosts = request_hosts.union(*(set(hosts) for hosts in scoped_hosts.values()))
        if len(all_hosts) > 32:
            raise TrustedMetadataError(f"target Source exact hosts exceed Host limit: {relative}")
    base = urlsplit(source["baseUrl"])
    try:
        base_port = base.port
    except ValueError as error:
        raise TrustedMetadataError(f"invalid target Source baseUrl port: {relative}") from error
    if (
        base.scheme != "https" or not base.hostname or base.username is not None
        or base.password is not None or base_port not in (None, 443)
        or base.hostname.lower() not in all_hosts
    ):
        raise TrustedMetadataError(f"target Source baseUrl is outside exact hosts: {relative}")
    capabilities = policy["namedCapabilities"]
    if (
        not isinstance(capabilities, list) or not capabilities or len(capabilities) > 16
        or capabilities != sorted(set(capabilities))
        or any(value not in KNOWN_CAPABILITIES for value in capabilities)
    ):
        raise TrustedMetadataError(f"invalid target Source capabilities: {relative}")
    if sha256_bytes(canonical_json(policy)) != source["policyHash"]:
        raise TrustedMetadataError(f"target Source networkPolicy hash mismatch: {relative}")


def _check_target_custom(custom: object, relative: str) -> None:
    required = {
        "packageName", "versionCode", "versionName", "name", "lang", "lineageRootSha256",
        "apkSignerPins", "sources",
    }
    if not isinstance(custom, dict) or set(custom) != required:
        raise TrustedMetadataError(f"invalid target custom metadata: {relative}")
    if not isinstance(custom["packageName"], str) or not custom["packageName"]:
        raise TrustedMetadataError(f"invalid target packageName: {relative}")
    if not isinstance(custom["versionCode"], int) or isinstance(custom["versionCode"], bool) or custom["versionCode"] < 1:
        raise TrustedMetadataError(f"invalid target versionCode: {relative}")
    if not isinstance(custom["versionName"], str) or not custom["versionName"]:
        raise TrustedMetadataError(f"invalid target versionName: {relative}")
    if not isinstance(custom["name"], str) or not custom["name"] or not isinstance(custom["lang"], str):
        raise TrustedMetadataError(f"invalid target display metadata: {relative}")
    pins = custom["apkSignerPins"]
    if (
        not isinstance(pins, list) or not pins or len(pins) != len(set(pins))
        or any(not isinstance(pin, str) or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin) for pin in pins)
    ):
        raise TrustedMetadataError(f"invalid target signer pins: {relative}")
    lineage_root = custom["lineageRootSha256"]
    if not isinstance(lineage_root, str) or len(lineage_root) != 64 or any(c not in "0123456789abcdef" for c in lineage_root):
        raise TrustedMetadataError(f"invalid target lineage root: {relative}")
    sources = custom["sources"]
    if not isinstance(sources, list) or not sources:
        raise TrustedMetadataError(f"invalid target sources: {relative}")
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "id", "service", "protocol", "policyHash", "networkPolicy", "name", "lang", "baseUrl",
        }:
            raise TrustedMetadataError(f"invalid target Source metadata: {relative}")
        source_id = source.get("id")
        if not isinstance(source_id, str) or not source_id or source_id in seen:
            raise TrustedMetadataError(f"invalid or duplicate target Source id: {relative}")
        if not isinstance(source.get("service"), str) or not source["service"]:
            raise TrustedMetadataError(f"invalid target Source service: {relative}")
        if source.get("protocol") != 1:
            raise TrustedMetadataError(f"unsupported target Source protocol: {relative}")
        policy_hash = source.get("policyHash")
        if not isinstance(policy_hash, str) or len(policy_hash) != 64 or any(c not in "0123456789abcdef" for c in policy_hash):
            raise TrustedMetadataError(f"invalid target Source policyHash: {relative}")
        if (
            not isinstance(source.get("name"), str) or not source["name"]
            or not isinstance(source.get("lang"), str)
            or not isinstance(source.get("baseUrl"), str) or not source["baseUrl"].startswith("https://")
        ):
            raise TrustedMetadataError(f"invalid target Source display metadata: {relative}")
        _check_source_network_policy(source, relative)
        seen.add(source_id)


def _verify_meta(expected: object, actual: bytes, actual_version: object, label: str) -> None:
    if not isinstance(expected, dict) or set(expected) != {"version", "length", "hashes"}:
        raise TrustedMetadataError(f"invalid meta descriptor: {label}")
    if expected["version"] != actual_version:
        raise TrustedMetadataError(f"metadata version mix-match: {label}")
    if expected["length"] != len(actual):
        raise TrustedMetadataError(f"metadata length mix-match: {label}")
    hashes = expected["hashes"]
    if not isinstance(hashes, dict) or hashes.get("sha256") != sha256_bytes(actual):
        raise TrustedMetadataError(f"metadata hash mix-match: {label}")


def _versions(metadata_root: Path) -> dict[str, int]:
    versions: dict[str, int] = {}
    timestamp_path = metadata_root / "timestamp.json"
    if not timestamp_path.is_file():
        return versions
    timestamp, _ = _load(timestamp_path, "timestamp")
    timestamp_version = timestamp["signed"].get("version")
    if isinstance(timestamp_version, int) and not isinstance(timestamp_version, bool):
        versions["timestamp"] = timestamp_version
    snapshot_version = timestamp["signed"].get("meta", {}).get("snapshot.json", {}).get("version")
    if not isinstance(snapshot_version, int) or isinstance(snapshot_version, bool):
        return versions
    snapshot, _ = _load(metadata_root / f"{snapshot_version}.snapshot.json", "snapshot")
    versions["snapshot"] = snapshot["signed"].get("version")
    targets_version = snapshot["signed"].get("meta", {}).get("targets.json", {}).get("version")
    if isinstance(targets_version, int) and not isinstance(targets_version, bool):
        targets, _ = _load(metadata_root / f"{targets_version}.targets.json", "targets")
        versions["targets"] = targets["signed"].get("version")
    return versions


def _role_bytes(metadata_root: Path, role: str, versions: dict[str, int]) -> bytes | None:
    if role not in versions:
        return None
    path = metadata_root / ("timestamp.json" if role == "timestamp" else f"{versions[role]}.{role}.json")
    try:
        return path.read_bytes()
    except OSError as error:
        raise TrustedMetadataError(f"missing previous metadata: {role}") from error


def verify_repository(
    trusted_root_path: Path,
    metadata_root: Path,
    target_root: Path,
    *,
    previous_metadata_root: Path | None = None,
    now: dt.datetime | None = None,
    openssl: str = "openssl",
) -> dict:
    """Verify root, timestamp -> snapshot -> targets and every target byte-for-byte."""
    now = now or dt.datetime.now(dt.timezone.utc)
    root, _ = _load(trusted_root_path, "root")
    root_signed = root["signed"]
    _check_common(root, "root", now)
    _check_root_shape(root_signed)
    _check_root_key_material(root_signed, openssl)
    if root_signed.get("consistentSnapshot") is not True:
        raise TrustedMetadataError("consistentSnapshot must be true")
    _verify_role(root, "root", root_signed, openssl)

    loaded = {}
    raw = {}
    loaded["timestamp"], raw["timestamp"] = _load(metadata_root / "timestamp.json", "timestamp")
    _check_common(loaded["timestamp"], "timestamp", now)
    _verify_role(loaded["timestamp"], "timestamp", root_signed, openssl)

    snapshot_meta = loaded["timestamp"]["signed"].get("meta", {}).get("snapshot.json")
    if not isinstance(snapshot_meta, dict) or not isinstance(snapshot_meta.get("version"), int):
        raise TrustedMetadataError("invalid timestamp snapshot descriptor")
    snapshot_path = metadata_root / f"{snapshot_meta['version']}.snapshot.json"
    loaded["snapshot"], raw["snapshot"] = _load(snapshot_path, "snapshot")
    _check_common(loaded["snapshot"], "snapshot", now)
    _verify_role(loaded["snapshot"], "snapshot", root_signed, openssl)

    targets_meta = loaded["snapshot"]["signed"].get("meta", {}).get("targets.json")
    if not isinstance(targets_meta, dict) or not isinstance(targets_meta.get("version"), int):
        raise TrustedMetadataError("invalid snapshot targets descriptor")
    targets_path = metadata_root / f"{targets_meta['version']}.targets.json"
    loaded["targets"], raw["targets"] = _load(targets_path, "targets")
    _check_common(loaded["targets"], "targets", now)
    _verify_role(loaded["targets"], "targets", root_signed, openssl)
    repository = loaded["targets"]["signed"].get("custom", {}).get("repository")
    if not isinstance(repository, dict) or set(repository) != {"name", "description", "iconUrl", "website"}:
        raise TrustedMetadataError("invalid signed repository display metadata")
    if any(not isinstance(value, str) or not value for value in repository.values()):
        raise TrustedMetadataError("empty signed repository display metadata")
    if not repository["iconUrl"].startswith("https://") or not repository["website"].startswith("https://"):
        raise TrustedMetadataError("repository display URLs must use HTTPS")

    _verify_meta(
        snapshot_meta,
        raw["snapshot"],
        loaded["snapshot"]["signed"].get("version"),
        "snapshot.json",
    )
    _verify_meta(
        targets_meta,
        raw["targets"],
        loaded["targets"]["signed"].get("version"),
        "targets.json",
    )

    if previous_metadata_root is not None:
        old = _versions(previous_metadata_root)
        for role, envelope in loaded.items():
            if role in old and envelope["signed"]["version"] < old[role]:
                raise TrustedMetadataError(f"metadata rollback: {role}")
            if role in old and envelope["signed"]["version"] == old[role]:
                previous_raw = _role_bytes(previous_metadata_root, role, old)
                if previous_raw is not None and not hmac.compare_digest(raw[role], previous_raw):
                    raise TrustedMetadataError(f"metadata changed without version increment: {role}")

    targets = loaded["targets"]["signed"].get("targets")
    if not isinstance(targets, dict) or not targets:
        raise TrustedMetadataError("targets metadata must not be empty")
    for relative, descriptor in targets.items():
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise TrustedMetadataError(f"unsafe target path: {relative}")
        if not isinstance(descriptor, dict) or set(descriptor) != {"length", "hashes", "custom"}:
            raise TrustedMetadataError(f"invalid target descriptor: {relative}")
        if not relative.startswith("apk/") or not relative.endswith(".apk"):
            raise TrustedMetadataError(f"target path must be apk/*.apk: {relative}")
        _check_target_custom(descriptor["custom"], relative)
        target = target_root / relative
        try:
            value = target.read_bytes()
        except OSError as error:
            raise TrustedMetadataError(f"missing target: {relative}") from error
        if descriptor["length"] != len(value) or descriptor["hashes"].get("sha256") != sha256_bytes(value):
            raise TrustedMetadataError(f"target mix-match: {relative}")
    return loaded["targets"]["signed"]
