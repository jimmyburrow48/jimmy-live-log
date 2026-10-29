"""tests for the daily page renderer (milestone 3, second half).
run: python -m unittest -v test_render_site
"""
import tempfile
import unittest
from pathlib import Path

import privacy_filter as pf
import render_site as rs
from test_privacy_filter import good_public


class RenderTests(unittest.TestCase):
    def test_writes_one_page_per_day_with_that_days_activity_only(self):
        public = good_public()
        public["days"].append({"date": "2026-10-29", "sections": []})
        public["activity"].append({"ts": "2026-10-29T09:00:00-05:00", "location": "desk", "text": "tomorrow's line"})
        with tempfile.TemporaryDirectory() as tmp:
            files = rs.render(public, tmp)
            self.assertEqual(sorted(f.name for f in files), ["2026-10-28.html", "2026-10-29.html"])
            page = (Path(tmp) / "days" / "2026-10-28.html").read_text(encoding="utf-8")
            self.assertIn("a clean action", page)
            self.assertNotIn("tomorrow's line", page)

    def test_html_in_text_is_escaped(self):
        public = good_public()
        public["days"][0]["sections"][0]["text"] = "<script>alert(1)</script>"
        public["activity"][0]["text"] = '<img src=x onerror="alert(1)">'
        with tempfile.TemporaryDirectory() as tmp:
            rs.render(public, tmp)
            page = (Path(tmp) / "days" / "2026-10-28.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<img src=x", page)

    def test_invalid_public_file_writes_nothing(self):
        bad = good_public()
        bad["activity"][0]["kind"] = "telegram"  # extra key: the schema refuses it
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(pf.PublishBlocked):
                rs.render(bad, tmp)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_empty_day_says_so(self):
        public = good_public()
        public["days"][0]["sections"] = []
        public["activity"] = []
        with tempfile.TemporaryDirectory() as tmp:
            rs.render(public, tmp)
            page = (Path(tmp) / "days" / "2026-10-28.html").read_text(encoding="utf-8")
        self.assertIn("no journal sections published", page)
        self.assertIn("no activity published", page)


if __name__ == "__main__":
    unittest.main()
