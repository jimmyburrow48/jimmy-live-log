"""tests for the jimmy live log privacy filter (milestone 1).

every PLANTED item is a fake secret, fake phone number, fake path or fake marker.
none of them may appear anywhere in the public output.
run: python -m unittest -v test_privacy_filter
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import privacy_filter as pf

FIX = Path(__file__).parent / "fixtures"

PLANTED = [
    "ghp_FAKEPLANTEDTOKEN",  # fake github token
    "sk-plantedfakekey",  # fake openai style key
    "FAKEPLANTEDTOKEN",  # fragment of the same token
    "Qx7mZp2LkW9bR4tY",  # first half of a token split over two journal lines
    "8sVd3HcF6jA1eE0rT2",  # second half of the same split token
    "555-010-0199",  # fake phone number (555-01xx is reserved for fiction)
    "fixture.person@example.com",  # fake email
    "fixturehamster",  # fake windows user name inside a path
    "C:\\Users",  # local path
    "planted-pass-123",  # fake password
    "Charles",  # my user's name
    "Locked Agent",  # the other agent
    "LockedAgent",
    "UNTIMED-MARKER",  # untimed heading must not be published
    "LATER-MARKER",  # untimed heading must not be published
    "6746",  # sms code copied into an activity line
    "planted words here",  # recovery phrase
    "September 1, 1999",  # birthday-style date
    "hamster-river-moon",  # passphrase
    "Emma",  # other person's name, given through --names
]


class PrivacyFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pf.set_private_names(["Emma"])
        cls.public = pf.build(
            [FIX / "journal" / "2026-10-30.md"],
            FIX / "activity" / "planted-activity.jsonl",
        )
        cls.blob = json.dumps(cls.public, ensure_ascii=False)

    @classmethod
    def tearDownClass(cls):
        pf.set_private_names([])

    def test_no_planted_secret_survives(self):
        for item in PLANTED:
            self.assertNotIn(item, self.blob, f"leaked: {item}")

    def test_safe_sentence_survives(self):
        self.assertIn("Normal sentences like this one should survive the filter.", self.blob)

    def test_name_replaced_and_quoting_line_dropped(self):
        self.assertIn("my user said the filter must never leak anything.", self.blob)
        self.assertNotIn("keep the good parts", self.blob)

    def test_only_clean_timed_sections_are_published(self):
        # 09:20-09:50 each hold a planted secret, so the whole line (and then the section) is withheld
        times = [s["time"] for s in self.public["days"][0]["sections"]]
        self.assertEqual(times, ["09:00", "09:10", "09:55"])

    def test_private_name_replaced_with_someone(self):
        self.assertIn("someone said the plan works.", self.blob)

    def test_blocked_publish_keeps_previous_output(self):
        # a failed gate must leave the last published file exactly as it was
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public-log.json"
            out.write_text("previous public version", encoding="utf-8")
            with mock.patch.object(pf, "leak_reason", return_value="forced leak"):
                with self.assertRaises(pf.PublishBlocked):
                    pf.main([
                        "--journal", str(FIX / "journal"),
                        "--activity", str(FIX / "activity" / "planted-activity.jsonl"),
                        "--out", str(out),
                    ])
            self.assertEqual(out.read_text(encoding="utf-8"), "previous public version")
            self.assertFalse((Path(tmp) / "public-log.json.tmp").exists())

    def test_split_token_section_is_dropped(self):
        self.assertGreaterEqual(self.public["stats"]["sections_dropped"], 1)
        self.assertNotIn("09:45", [s["time"] for s in self.public["days"][0]["sections"]])

    def test_activity_keeps_only_safe_action_text(self):
        activity = self.public["activity"]
        self.assertEqual(
            [a["text"] for a in activity],
            [
                None,  # raw tool call
                "asked chatgpt about the filter design",
                None,  # password word
                "wrote the milestone note",
                None,  # telegram kind: private chat, never published
                None,  # journal kind: copies the journal, which has its own filter
                "remembered (lesson): keep notes free of one-time values",  # memory kind, clean text
            ],
        )
        self.assertEqual(activity[0]["location"], "desk")
        self.assertEqual(activity[3]["location"], "other")
        self.assertEqual(self.public["stats"]["activity_skipped"], 1)

    def test_zero_width_and_fullwidth_tricks_are_caught(self):
        self.assertEqual(pf.leak_reason("ghp\u200b_FAKEPLANTEDTOKEN00000000000000"), "secret-shaped token")
        self.assertEqual(pf.leak_reason("\uff47\uff48\uff50_FAKEPLANTEDTOKEN00000000000"), "secret-shaped token")

    def test_gate_blocks_a_leak(self):
        with self.assertRaises(pf.PublishBlocked):
            pf.gate({"days": [{"text": "key ghp_FAKEPLANTEDTOKEN00000000000000000000"}]})
        with self.assertRaises(pf.PublishBlocked):
            pf.gate({"days": [{"text": "Charles was here"}]})

    def test_one_time_codes_are_dropped(self):
        # from the real journal: an sms code and an email code in parentheses
        self.assertEqual(pf.leak_reason("my user sent the Vercel SMS code 6746."), "secret word")
        self.assertEqual(pf.leak_reason("Code came by email from my inbox (315707), entered it."), "code-like number")
        self.assertIsNone(pf.leak_reason("tiny biome lab ran at 19:20 on 2026-10-28, version 1.2"))

    def test_key_blocks_signed_urls_and_street_addresses_are_caught(self):
        # chatgpt review (LEAKY): pem and ssh key material, signed url parameters, street addresses
        self.assertEqual(pf.leak_reason("-----BEGIN OPENSSH PRIVATE KEY-----"), "secret-shaped token")
        self.assertEqual(pf.leak_reason("ssh-ed25519 AAAAC3NzaFAKEKEYFAKEKEY0000000000 jimmy"), "secret-shaped token")
        self.assertEqual(pf.leak_reason("see https://files.example.com/a.zip?X-Amz-Credential=FAKEPLANTED"), "secret-shaped token")
        self.assertEqual(pf.leak_reason("a signed link ?sig=FAKEPLANTED for the file"), "secret-shaped token")
        self.assertEqual(pf.leak_reason("he lives at 42 Maple Street now"), "street address")
        self.assertIsNone(pf.leak_reason("a normal link https://ghost-map-kappa.vercel.app for the tool"))
        self.assertIsNone(pf.leak_reason("ran 3 tests in 0.2 seconds on the wheel"))

    def test_gate_passes_clean_output(self):
        pf.gate({"days": [{"text": "a clean line about the burrow"}]})

    def test_dates_are_real_dates(self):
        self.assertEqual(self.public["days"][0]["date"], "2026-10-30")


def good_public():
    """a public file that matches the strict schema exactly"""
    return {
        "days": [{"date": "2026-10-28", "sections": [{"time": "23:35", "mood": "busy", "title": "night tick", "text": "a clean line"}]}],
        "activity": [
            {"ts": "2026-10-28T16:01:37-05:00", "location": "desk", "text": "a clean action"},
            {"ts": "2026-10-28T16:01:39-05:00", "location": "wheel", "text": None},
        ],
        "stats": {"lines_withheld": 0, "sections_dropped": 0, "files_skipped": 0, "activity_skipped": 0},
    }


class StrictSchemaTests(unittest.TestCase):
    """milestone 3: the public file has an exact shape. a record with an extra key, a bad format or the wrong type blocks the publish."""

    def test_good_file_passes(self):
        pf.validate_public(good_public())

    def test_extra_key_on_activity_blocks(self):
        bad = good_public()
        bad["activity"][0]["kind"] = "telegram"  # a field that was never on the allow-list
        with self.assertRaises(pf.PublishBlocked):
            pf.validate_public(bad)

    def test_missing_key_blocks(self):
        bad = good_public()
        del bad["stats"]["files_skipped"]
        with self.assertRaises(pf.PublishBlocked):
            pf.validate_public(bad)

    def test_bad_timestamp_blocks(self):
        bad = good_public()
        bad["activity"][0]["ts"] = "yesterday"
        with self.assertRaises(pf.PublishBlocked):
            pf.validate_public(bad)

    def test_location_must_be_a_plain_word(self):
        bad = good_public()
        bad["activity"][0]["location"] = "C:\\Users"
        with self.assertRaises(pf.PublishBlocked):
            pf.validate_public(bad)

    def test_text_must_be_text_or_null(self):
        bad = good_public()
        bad["activity"][0]["text"] = 5
        with self.assertRaises(pf.PublishBlocked):
            pf.validate_public(bad)

    def test_stats_must_be_counts(self):
        bad = good_public()
        bad["stats"]["lines_withheld"] = True
        with self.assertRaises(pf.PublishBlocked):
            pf.validate_public(bad)

    def test_section_fields_must_be_text(self):
        bad = good_public()
        bad["days"][0]["sections"][0]["mood"] = None
        with self.assertRaises(pf.PublishBlocked):
            pf.validate_public(bad)


if __name__ == "__main__":
    unittest.main()
