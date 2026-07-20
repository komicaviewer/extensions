#!/usr/bin/env python3
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raw_publish_verify import RemoteVerificationError, verify_remote_once, verify_with_retries


class RawPublishVerifyTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "apk").mkdir()
        (self.root / "icon").mkdir()
        self.apk = b"apk bytes"
        self.icon = b"icon bytes"
        self.entry = {
            "pkg": "tw.example.extension",
            "apkName": "extension.apk",
            "iconName": "extension.png",
            "sha256": hashlib.sha256(self.apk).hexdigest(),
        }
        self.index = [self.entry]
        (self.root / "index.json").write_text(json.dumps(self.index), encoding="utf-8")
        (self.root / "apk" / "extension.apk").write_bytes(self.apk)
        (self.root / "icon" / "extension.png").write_bytes(self.icon)

    def fetch(self, path):
        return {
            "index.json": json.dumps(self.index).encode(),
            "index.min.json": json.dumps(self.index).encode(),
            "apk/extension.apk": self.apk,
            "icon/extension.png": self.icon,
        }[path]

    def test_accepts_remote_tree_equal_to_local(self):
        self.assertEqual((1, 1), verify_remote_once(self.root, self.fetch))

    def test_rejects_remote_index_mismatch(self):
        def fetch(path):
            if path == "index.json":
                return b"[]"
            return self.fetch(path)

        with self.assertRaisesRegex(RemoteVerificationError, "index.json does not match"):
            verify_remote_once(self.root, fetch)

    def test_rejects_remote_apk_content_mismatch(self):
        def fetch(path):
            if path == "apk/extension.apk":
                return b"wrong"
            return self.fetch(path)

        with self.assertRaisesRegex(RemoteVerificationError, "APK SHA-256 mismatch"):
            verify_remote_once(self.root, fetch)

    def test_rejects_remote_icon_content_mismatch(self):
        def fetch(path):
            if path == "icon/extension.png":
                return b"wrong"
            return self.fetch(path)

        with self.assertRaisesRegex(RemoteVerificationError, "icon content mismatch"):
            verify_remote_once(self.root, fetch)

    def test_retry_is_finite_and_can_converge(self):
        calls = []

        def fetcher(_raw_base, token):
            calls.append(token)
            if len(calls) < 3:
                return lambda _path: (_ for _ in ()).throw(RemoteVerificationError("stale"))
            return self.fetch

        with patch("raw_publish_verify.remote_fetcher", side_effect=fetcher):
            with patch("raw_publish_verify.time.sleep"):
                result = verify_with_retries(self.root, "https://example.test/main", "abc", 3, 0)

        self.assertEqual((1, 1, 3), result)
        self.assertEqual(["abc-1", "abc-2", "abc-3"], calls)

    def test_retry_fails_after_configured_attempts(self):
        def fetcher(_raw_base, _token):
            return lambda _path: (_ for _ in ()).throw(RemoteVerificationError("stale"))

        with patch("raw_publish_verify.remote_fetcher", side_effect=fetcher):
            with patch("raw_publish_verify.time.sleep"):
                with self.assertRaisesRegex(RemoteVerificationError, "after finite retries"):
                    verify_with_retries(self.root, "https://example.test/main", "abc", 2, 0)


if __name__ == "__main__":
    unittest.main()
