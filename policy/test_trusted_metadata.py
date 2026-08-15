#!/usr/bin/env python3
import base64
import copy
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from trusted_metadata import TrustedMetadataError, canonical_json, verify_repository


NOW = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)


class TrustedMetadataFixture:
    def __init__(self, root: Path):
        self.root = root
        self.metadata = root / "metadata"
        self.targets = root / "targets"
        self.keys = root / "keys"
        self.metadata.mkdir()
        self.targets.mkdir()
        self.keys.mkdir()
        self.keyids = {role: [self._key(f"{role}-{index}") for index in range(count)] for role, count in {
            "root": 2, "targets": 2, "snapshot": 1, "timestamp": 1,
        }.items()}
        (self.targets / "apk").mkdir()
        (self.targets / "apk" / "fixture.apk").write_bytes(b"fixture apk")
        self.write_chain()

    def _key(self, name: str, curve: str = "prime256v1") -> str:
        private = self.keys / f"{name}.pem"
        public = self.keys / f"{name}.der"
        subprocess.run(
            ["openssl", "ecparam", "-name", curve, "-genkey", "-noout", "-out", str(private)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER", "-out", str(public)],
            check=True, capture_output=True,
        )
        return hashlib.sha256(public.read_bytes()).hexdigest()

    def _key_record(self, keyid: str) -> dict:
        public = next(path for path in self.keys.glob("*.der") if hashlib.sha256(path.read_bytes()).hexdigest() == keyid)
        return {
            "keytype": "ecdsa",
            "scheme": "ecdsa-sha2-nistp256",
            "keyval": {"public": base64.b64encode(public.read_bytes()).decode("ascii")},
        }

    def _private(self, keyid: str) -> Path:
        public = next(path for path in self.keys.glob("*.der") if hashlib.sha256(path.read_bytes()).hexdigest() == keyid)
        return public.with_suffix(".pem")

    def envelope(self, signed: dict, role: str, signatures: int | None = None) -> dict:
        payload = self.root / "payload.json"
        payload.write_bytes(canonical_json(signed))
        selected = self.keyids[role][:signatures]
        values = []
        for keyid in selected:
            signature = self.root / "signature.der"
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(self._private(keyid)), "-out", str(signature), str(payload)],
                check=True, capture_output=True,
            )
            values.append({"keyid": keyid, "sig": base64.b64encode(signature.read_bytes()).decode("ascii")})
        return {"signed": signed, "signatures": values}

    @staticmethod
    def descriptor(raw: bytes) -> dict:
        return {"version": 1, "length": len(raw), "hashes": {"sha256": hashlib.sha256(raw).hexdigest()}}

    def write(self, name: str, envelope: dict) -> bytes:
        raw = canonical_json(envelope)
        version = envelope["signed"]["version"]
        filename = "timestamp.json" if name == "timestamp" else f"{version}.{name}.json"
        (self.metadata / filename).write_bytes(raw)
        return raw

    def write_chain(
        self,
        *,
        timestamp_expiry: str = "2031-01-01T00:00:00Z",
        network_policy: dict | None = None,
        base_url: str = "https://api.example.test/v1/",
    ) -> None:
        all_keyids = [keyid for ids in self.keyids.values() for keyid in ids]
        root_signed = {
            "_type": "root", "specVersion": "1.0", "version": 1,
            "expires": "2035-01-01T00:00:00Z", "consistentSnapshot": True,
            "keys": {keyid: self._key_record(keyid) for keyid in all_keyids},
            "roles": {
                role: {"keyids": ids, "threshold": 2 if role in {"root", "targets"} else 1}
                for role, ids in self.keyids.items()
            },
        }
        root_envelope = self.envelope(root_signed, "root")
        self.root_path = self.root / "root.json"
        self.root_path.write_bytes(canonical_json(root_envelope))

        target_value = (self.targets / "apk" / "fixture.apk").read_bytes()
        if network_policy is None:
            network_policy = {
                "schemaVersion": 2,
                "request": {"rules": [{
                    "exactHosts": ["api.example.test"],
                    "operation": {
                        "name": "source_read", "methods": ["GET"],
                        "pathPrefixes": ["/v1/"], "credentialed": False,
                    },
                }]},
                "resource": {"exactHosts": ["images.example.test"]},
                "external": {"exactHosts": ["www.example.test"]},
                "auth": {"exactHosts": ["login.example.test"]},
                "namedCapabilities": ["external_link", "resource_read"],
            }
        targets_signed = {
            "_type": "targets", "specVersion": "1.0", "version": 1,
            "expires": "2031-01-01T00:00:00Z",
            "targets": {
                "apk/fixture.apk": {
                    "length": len(target_value),
                    "hashes": {"sha256": hashlib.sha256(target_value).hexdigest()},
                    "custom": {
                        "packageName": "tw.example.bundle", "versionCode": 1, "versionName": "1.0",
                        "name": "Fixture", "lang": "en",
                        "lineageRootSha256": "1" * 64,
                        "apkSignerPins": ["1" * 64],
                        "sources": [{
                            "id": "tw.example.source", "service": "tw.example.SourceService",
                            "protocol": 1,
                            "policyHash": hashlib.sha256(canonical_json(network_policy)).hexdigest(),
                            "networkPolicy": network_policy,
                            "name": "Fixture Source", "lang": "en", "baseUrl": base_url,
                        }],
                    },
                },
            },
            "custom": {"repository": {
                "name": "Fixture", "description": "Fixture repository",
                "iconUrl": "https://example.test/icon.png", "website": "https://example.test",
            }},
        }
        targets_raw = self.write("targets", self.envelope(targets_signed, "targets"))
        snapshot_signed = {
            "_type": "snapshot", "specVersion": "1.0", "version": 1,
            "expires": "2031-01-01T00:00:00Z",
            "meta": {"targets.json": self.descriptor(targets_raw)},
        }
        snapshot_raw = self.write("snapshot", self.envelope(snapshot_signed, "snapshot"))
        timestamp_signed = {
            "_type": "timestamp", "specVersion": "1.0", "version": 1,
            "expires": timestamp_expiry,
            "meta": {"snapshot.json": self.descriptor(snapshot_raw)},
        }
        self.write("timestamp", self.envelope(timestamp_signed, "timestamp"))


class TrustedMetadataTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = TrustedMetadataFixture(Path(self.temp.name))

    def verify(self, **kwargs):
        return verify_repository(
            self.fixture.root_path,
            self.fixture.metadata,
            self.fixture.targets,
            now=NOW,
            **kwargs,
        )

    def _rewrite_snapshot_for_targets(self, targets_raw: bytes) -> None:
        snapshot_path = self.fixture.metadata / "1.snapshot.json"
        snapshot = json.loads(snapshot_path.read_text())
        snapshot["signed"]["meta"]["targets.json"] = self.fixture.descriptor(targets_raw)
        snapshot_raw = self.fixture.write(
            "snapshot", self.fixture.envelope(snapshot["signed"], "snapshot")
        )
        timestamp_path = self.fixture.metadata / "timestamp.json"
        timestamp = json.loads(timestamp_path.read_text())
        timestamp["signed"]["meta"]["snapshot.json"] = self.fixture.descriptor(snapshot_raw)
        self.fixture.write("timestamp", self.fixture.envelope(timestamp["signed"], "timestamp"))

    def test_accepts_threshold_signed_chain_and_bound_target(self):
        result = self.verify()
        self.assertEqual("tw.example.bundle", result["targets"]["apk/fixture.apk"]["custom"]["packageName"])

    def test_accepts_legacy_v1_network_policy(self):
        legacy_policy = {
            "exactHosts": ["example.test"],
            "operations": [{
                "name": "source_read", "methods": ["GET", "HEAD"],
                "pathPrefixes": ["/"], "credentialed": True,
            }],
            "namedCapabilities": ["resource_read"],
        }
        self.fixture.write_chain(network_policy=legacy_policy, base_url="https://example.test")
        self.assertEqual("tw.example.bundle", self.verify()["targets"]["apk/fixture.apk"]["custom"]["packageName"])

    def test_rejects_wrong_or_insufficient_targets_signer(self):
        envelope = json.loads((self.fixture.metadata / "1.targets.json").read_text())
        envelope["signatures"] = envelope["signatures"][:1]
        (self.fixture.metadata / "1.targets.json").write_bytes(canonical_json(envelope))
        with self.assertRaisesRegex(TrustedMetadataError, "threshold not met"):
            self.verify()

    def test_rejects_non_p256_root_key_material(self):
        keyid = self.fixture._key("untrusted-p384", "secp384r1")
        root = json.loads(self.fixture.root_path.read_text())
        root["signed"]["keys"][keyid] = self.fixture._key_record(keyid)
        self.fixture.root_path.write_bytes(
            canonical_json(self.fixture.envelope(root["signed"], "root")),
        )
        with self.assertRaisesRegex(TrustedMetadataError, "root key must use P-256"):
            self.verify()

    def test_rejects_signature_from_wrong_role(self):
        path = self.fixture.metadata / "1.targets.json"
        envelope = json.loads(path.read_text())
        envelope["signatures"] = self.fixture.envelope(envelope["signed"], "snapshot")["signatures"]
        path.write_bytes(canonical_json(envelope))
        with self.assertRaisesRegex(TrustedMetadataError, "threshold not met"):
            self.verify()

    def test_rejects_freeze_or_expired_timestamp(self):
        self.fixture.write_chain(timestamp_expiry="2029-12-31T23:59:59Z")
        with self.assertRaisesRegex(TrustedMetadataError, "expired metadata: timestamp"):
            self.verify()

    def test_rejects_target_mix_match(self):
        (self.fixture.targets / "apk" / "fixture.apk").write_bytes(b"tampered")
        with self.assertRaisesRegex(TrustedMetadataError, "target mix-match"):
            self.verify()

    def test_rejects_network_policy_hash_mismatch(self):
        path = self.fixture.metadata / "1.targets.json"
        envelope = json.loads(path.read_text())
        source = next(iter(envelope["signed"]["targets"].values()))["custom"]["sources"][0]
        source["networkPolicy"]["resource"]["exactHosts"].append("other.example.test")
        source["networkPolicy"]["resource"]["exactHosts"].sort()
        path.write_bytes(canonical_json(self.fixture.envelope(envelope["signed"], "targets")))
        self._rewrite_snapshot_for_targets(path.read_bytes())
        with self.assertRaisesRegex(TrustedMetadataError, "networkPolicy hash mismatch"):
            self.verify()

    def test_rejects_wildcard_post_and_unknown_capability(self):
        mutations = (
            lambda policy: policy["request"]["rules"][0].__setitem__("exactHosts", ["*.example.test"]),
            lambda policy: policy["request"]["rules"][0]["operation"].__setitem__("methods", ["POST"]),
            lambda policy: policy.__setitem__("namedCapabilities", ["unknown"]),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.fixture.write_chain()
                path = self.fixture.metadata / "1.targets.json"
                envelope = json.loads(path.read_text())
                source = next(iter(envelope["signed"]["targets"].values()))["custom"]["sources"][0]
                mutate(source["networkPolicy"])
                source["policyHash"] = hashlib.sha256(
                    canonical_json(source["networkPolicy"])
                ).hexdigest()
                path.write_bytes(canonical_json(self.fixture.envelope(envelope["signed"], "targets")))
                self._rewrite_snapshot_for_targets(path.read_bytes())
                with self.assertRaisesRegex(TrustedMetadataError, "(exact hosts|operations|capabilities)"):
                    self.verify()

    def test_rejects_snapshot_targets_mix_match(self):
        envelope = json.loads((self.fixture.metadata / "1.targets.json").read_text())
        envelope["signed"]["expires"] = "2032-01-01T00:00:00Z"
        (self.fixture.metadata / "1.targets.json").write_bytes(canonical_json(self.fixture.envelope(envelope["signed"], "targets")))
        with self.assertRaisesRegex(TrustedMetadataError, "metadata (length|hash) mix-match"):
            self.verify()

    def test_rejects_metadata_rollback(self):
        previous = Path(self.temp.name) / "previous"
        previous.mkdir()
        for role in ("targets", "snapshot", "timestamp"):
            source_name = "timestamp.json" if role == "timestamp" else f"1.{role}.json"
            envelope = json.loads((self.fixture.metadata / source_name).read_text())
            envelope["signed"]["version"] = 2
            destination = "timestamp.json" if role == "timestamp" else f"2.{role}.json"
            (previous / destination).write_bytes(canonical_json(envelope))
        timestamp = json.loads((previous / "timestamp.json").read_text())
        timestamp["signed"]["meta"]["snapshot.json"]["version"] = 2
        (previous / "timestamp.json").write_bytes(canonical_json(timestamp))
        snapshot = json.loads((previous / "2.snapshot.json").read_text())
        snapshot["signed"]["meta"]["targets.json"]["version"] = 2
        (previous / "2.snapshot.json").write_bytes(canonical_json(snapshot))
        with self.assertRaisesRegex(TrustedMetadataError, "metadata rollback"):
            self.verify(previous_metadata_root=previous)

    def test_rejects_same_version_metadata_replacement(self):
        previous = Path(self.temp.name) / "previous"
        shutil.copytree(self.fixture.metadata, previous)

        # ECDSA signatures are randomized, so regenerating the chain replaces
        # immutable versioned metadata even when the signed fields are equal.
        self.fixture.write_chain()
        with self.assertRaisesRegex(TrustedMetadataError, "changed without version increment"):
            self.verify(previous_metadata_root=previous)


if __name__ == "__main__":
    unittest.main()
