#!/usr/bin/env python3
import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from admission_gate import AdmissionError, validate_distribution


POLICY_ROOT = Path(__file__).resolve().parent
CATALOG = json.loads((POLICY_ROOT / "admission_policy.json").read_text(encoding="utf-8"))
FINGERPRINT = "3df4717435423d5ba7adfed43a22a6e18bbeadc8d509d0bea94d82c7b0f2998d"
VERSIONS = {
    "gamer": (3, "0.0.3"),
    "komica": (3, "0.3.0"),
    "komica2": (4, "0.4.0"),
}


class AdmissionGateTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.base = root / "base"
        self.candidate = root / "candidate"
        self.base.mkdir()
        self.candidate.mkdir()
        (self.candidate / "apk").mkdir()
        (self.candidate / "icon").mkdir()
        self.aapt = self.write_aapt(root / "aapt", wrong_package=False)
        self.wrong_aapt = self.write_aapt(root / "wrong-aapt", wrong_package=True)
        self.apksigner = self.write_apksigner(root / "apksigner", FINGERPRINT)
        self.wrong_apksigner = self.write_apksigner(root / "wrong-apksigner", "0" * 64)

        repo = {
            "name": "NewsHub Extensions",
            "baseUrl": "https://raw.githubusercontent.com/komicaviewer/extensions/main",
            "signingKeyFingerprint": FINGERPRINT,
        }
        self.write_json(self.base / "repo.json", repo)
        self.write_json(self.candidate / "repo.json", repo)
        self.entries = self.create_candidate_release()
        self.write_candidate_indexes()
        self.write_json(self.base / "index.json", copy.deepcopy(self.entries))

    def write_json(self, path, value, compact=False):
        path.write_text(
            json.dumps(value, ensure_ascii=False, separators=(",", ":") if compact else None),
            encoding="utf-8",
        )

    def write_executable(self, path, content):
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def write_aapt(self, path, wrong_package):
        wrong_literal = "True" if wrong_package else "False"
        return self.write_executable(
            path,
            f"""#!{sys.executable}
import os, re, sys
packages = {{
    'gamer': 'tw.kevinzhang.newshub.extension.gamer',
    'komica': 'tw.kevinzhang.newshub.extension.komica',
    'komica2': 'tw.kevinzhang.newshub.extension.komica2',
}}
versions = {{'gamer': 3, 'komica': 3, 'komica2': 4}}
match = re.fullmatch(r'newshub-(gamer|komica|komica2)-v(.+)\\.apk', os.path.basename(sys.argv[-1]))
module, version_name = match.groups()
package = packages[module] + ('.wrong' if {wrong_literal} and module == 'gamer' else '')
print(f"package: name='{{package}}' versionCode='{{versions[module]}}' versionName='{{version_name}}'")
""",
        )

    def write_apksigner(self, path, fingerprint):
        return self.write_executable(
            path,
            f"""#!{sys.executable}
print('Signer #1 certificate SHA-256 digest: {fingerprint}')
""",
        )

    def registry_source(self, source_id):
        class_name = "example." + source_id.replace(".", "_") + ".Source"
        return {
            "className": class_name,
            "id": source_id,
            "name": source_id,
            "lang": "zh-TW",
            "baseUrl": "https://example.com/" + source_id,
        }

    def write_apk(self, package, registry=None, include_classes=True):
        release = CATALOG["releases"][package]
        version_code, version_name = VERSIONS[release["module"]]
        apk_name = f"newshub-{release['module']}-v{version_name}.apk"
        apk_path = self.candidate / "apk" / apk_name
        sources = [self.registry_source(source_id) for source_id in release["sourceIds"]]
        registry = registry or {
            "schemaVersion": 1,
            "name": release["name"],
            "sources": sources,
        }
        class_markers = b"\n".join(
            source["className"].replace(".", "/").encode("utf-8")
            for source in registry["sources"]
        )
        with zipfile.ZipFile(apk_path, "w") as apk:
            apk.writestr("assets/newshub-extension.json", json.dumps(registry))
            apk.writestr("classes.dex", class_markers if include_classes else b"dex without Source classes")
        return apk_name, apk_path, version_code, version_name, registry

    def create_candidate_release(self):
        entries = []
        for package, release in CATALOG["releases"].items():
            apk_name, apk_path, version_code, version_name, registry = self.write_apk(package)
            icon_path = self.candidate / "icon" / release["iconName"]
            icon_path.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
            entries.append({
                "pkg": package,
                "name": release["name"],
                "versionCode": version_code,
                "versionName": version_name,
                "lang": "zh-TW",
                "apkName": apk_name,
                "iconName": release["iconName"],
                "sha256": hashlib.sha256(apk_path.read_bytes()).hexdigest(),
                "sources": [
                    {field: source[field] for field in ("id", "name", "lang", "baseUrl")}
                    for source in registry["sources"]
                ],
            })
        return entries

    def write_candidate_indexes(self):
        self.write_json(self.candidate / "index.json", self.entries)
        self.write_json(self.candidate / "index.min.json", self.entries, compact=True)

    def entry(self, package):
        return next(entry for entry in self.entries if entry["pkg"] == package)

    def validate(self, aapt=None, apksigner=None):
        validate_distribution(
            self.candidate,
            self.base,
            POLICY_ROOT,
            aapt or self.aapt,
            apksigner or self.apksigner,
        )

    def test_accepts_exact_three_apk_nine_source_distribution(self):
        self.validate()

    def test_rejects_missing_gamer(self):
        gamer = "tw.kevinzhang.newshub.extension.gamer"
        entry = self.entry(gamer)
        self.entries.remove(entry)
        (self.candidate / "apk" / entry["apkName"]).unlink()
        (self.candidate / "icon" / entry["iconName"]).unlink()
        self.write_candidate_indexes()

        with self.assertRaisesRegex(AdmissionError, "candidate package set is not exact"):
            self.validate()

    def test_rejects_index_min_mismatch(self):
        self.write_json(self.candidate / "index.min.json", self.entries[:-1], compact=True)
        with self.assertRaisesRegex(AdmissionError, "not semantically equivalent"):
            self.validate()

    def test_rejects_missing_icon(self):
        (self.candidate / "icon" / self.entries[0]["iconName"]).unlink()
        with self.assertRaisesRegex(AdmissionError, "icon directory does not match index"):
            self.validate()

    def test_rejects_sha_mismatch(self):
        self.entries[0]["sha256"] = "0" * 64
        self.write_candidate_indexes()
        with self.assertRaisesRegex(AdmissionError, "APK SHA-256 mismatch"):
            self.validate()

    def test_rejects_package_mismatch(self):
        with self.assertRaisesRegex(AdmissionError, "APK package mismatch"):
            self.validate(aapt=self.wrong_aapt)

    def test_rejects_signer_mismatch(self):
        with self.assertRaisesRegex(AdmissionError, "APK signer mismatch"):
            self.validate(apksigner=self.wrong_apksigner)

    def test_rejects_version_downgrade(self):
        gamer = "tw.kevinzhang.newshub.extension.gamer"
        base_index = copy.deepcopy(self.entries)
        next(entry for entry in base_index if entry["pkg"] == gamer)["versionCode"] = 4
        self.write_json(self.base / "index.json", base_index)
        with self.assertRaisesRegex(AdmissionError, "versionCode downgrade"):
            self.validate()

    def test_rejects_changed_apk_without_version_bump(self):
        base_index = copy.deepcopy(self.entries)
        base_index[0]["sha256"] = "0" * 64
        self.write_json(self.base / "index.json", base_index)
        with self.assertRaisesRegex(AdmissionError, "changed without versionCode bump"):
            self.validate()

    def test_rejects_unauthorized_package_deletion(self):
        base_index = copy.deepcopy(self.entries)
        base_index.append({"pkg": "tw.example.legacy", "versionCode": 1, "sha256": "0" * 64})
        self.write_json(self.base / "index.json", base_index)
        with self.assertRaisesRegex(AdmissionError, "unauthorized package removals"):
            self.validate()

    def test_rejects_registry_source_set_mismatch(self):
        package = "tw.kevinzhang.newshub.extension.komica"
        release = CATALOG["releases"][package]
        registry = {
            "schemaVersion": 1,
            "name": release["name"],
            "sources": [self.registry_source(source_id) for source_id in release["sourceIds"][:-1]],
        }
        _, apk_path, _, _, _ = self.write_apk(package, registry=registry)
        self.entry(package)["sha256"] = hashlib.sha256(apk_path.read_bytes()).hexdigest()
        self.entry(package)["sources"] = [
            {field: source[field] for field in ("id", "name", "lang", "baseUrl")}
            for source in registry["sources"]
        ]
        self.write_candidate_indexes()
        with self.assertRaisesRegex(AdmissionError, "unexpected index Source set"):
            self.validate()

    def test_rejects_registry_class_missing_from_dex(self):
        package = "tw.kevinzhang.newshub.extension.komica2"
        _, apk_path, _, _, _ = self.write_apk(package, include_classes=False)
        self.entry(package)["sha256"] = hashlib.sha256(apk_path.read_bytes()).hexdigest()
        self.write_candidate_indexes()
        with self.assertRaisesRegex(AdmissionError, "registry Source class missing from DEX"):
            self.validate()

    def test_rejects_candidate_repo_trust_anchor_change(self):
        repo = json.loads((self.candidate / "repo.json").read_text(encoding="utf-8"))
        repo["signingKeyFingerprint"] = "0" * 64
        self.write_json(self.candidate / "repo.json", repo)
        with self.assertRaisesRegex(AdmissionError, "candidate changed forbidden paths:.*repo.json"):
            self.validate()

    def test_rejects_candidate_workflow_change(self):
        workflow = self.candidate / ".github" / "workflows" / "bypass.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("permissions: write-all\n", encoding="utf-8")
        with self.assertRaisesRegex(AdmissionError, "candidate changed forbidden paths:.*bypass.yml"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
