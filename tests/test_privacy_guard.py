import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools import privacy_guard


class PrivacyGuardTests(unittest.TestCase):
    def test_redacts_common_secrets(self):
        openai_key = "sk-" + ("abcd1234" * 4)
        github_token = "ghp_" + ("abcd1234" * 4)
        email = "person" + "@example.com"
        openai_var = "OPENAI" + "_API" + "_KEY"
        github_var = "GITHUB" + "_TOKEN"
        line = (
            f"{openai_var}={openai_key} "
            f"{github_var}={github_token} "
            f"email={email}"
        )

        redacted = privacy_guard.redact(line)

        self.assertIn("<OPENAI_API_KEY_REDACTED>", redacted)
        self.assertIn("<GITHUB_TOKEN_REDACTED>", redacted)
        self.assertIn("<EMAIL_REDACTED>", redacted)
        self.assertNotIn(openai_key, redacted)
        self.assertNotIn(github_token, redacted)
        self.assertNotIn(email, redacted)

    def test_scans_secret_assignments_without_raw_secret_preview(self):
        findings = privacy_guard.scan_text(
            "settings.env",
            ("DATABASE" + "_PASSWORD") + "=" + ("correct" + "horse" + "battery" + "staple") + "\n",
        )

        self.assertTrue(any(f.kind == "password_assignment" for f in findings))
        self.assertTrue(all("correcthorsebatterystaple" not in f.preview for f in findings))

    def test_sensitive_filenames_are_critical(self):
        findings = privacy_guard.filename_findings(".env.production")

        self.assertEqual(1, len(findings))
        self.assertEqual("critical", findings[0].severity)
        self.assertEqual("env_file", findings[0].kind)

    def test_private_data_patterns_are_detected(self):
        email = "alice" + "@example.com"
        home_path = "/Users/" + "alice/project"
        private_ip = "192.168." + "1.10"
        findings = privacy_guard.scan_text(
            "log.txt",
            f"user={home_path} host={private_ip} contact={email}\n",
        )
        kinds = {f.kind for f in findings}

        self.assertIn("home_path", kinds)
        self.assertIn("private_ipv4", kinds)
        self.assertIn("email", kinds)

    def test_worktree_scan_skips_symlink_targets(self):
        with TemporaryDirectory() as repo_dir, TemporaryDirectory() as outside_dir:
            root = Path(repo_dir)
            outside = Path(outside_dir) / "external.txt"
            outside_secret = "outside" + "-repo" + "-secret"
            outside.write_text(("LOCAL" + "_PASSWORD") + f"={outside_secret}\n", encoding="utf-8")
            (root / "linked_config.txt").symlink_to(outside)

            findings = privacy_guard.scan_files(root, ["linked_config.txt"], staged=False, max_bytes=2_000_000)

            self.assertEqual(1, len(findings))
            self.assertEqual("symlink_file_skipped", findings[0].kind)
            self.assertNotIn(outside_secret, findings[0].preview)


if __name__ == "__main__":
    unittest.main()
