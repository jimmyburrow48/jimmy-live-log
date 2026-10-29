"""jimmy live log: render one static html page per day from the validated public json.

the input is ONLY the public json written by privacy_filter.py. this script never reads the vault or the logs,
and it validates the json again before writing anything (fail closed).
usage: python render_site.py --json <public-log.json> --out <site folder>
"""
import argparse
import html
import json
from pathlib import Path

import privacy_filter as pf


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def render_day(day, activity_for_day):
    rows = []
    for act in activity_for_day:
        text = act["text"] if act["text"] is not None else ""
        rows.append(f"<tr><td>{esc(act['ts'])}</td><td>{esc(act['location'])}</td><td>{esc(text)}</td></tr>")
    sections = []
    for sec in day["sections"]:
        mood = f" <span class=\"mood\">{esc(sec['mood'])}</span>" if sec["mood"] else ""
        sections.append(
            f"<section><h3>{esc(sec['time'])} {esc(sec['title'])}{mood}</h3>"
            f"<p>{esc(sec['text'])}</p></section>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>jimmy live log, {esc(day['date'])}</title>
</head>
<body>
<main>
<p><a href="../index.html">back to the live log</a></p>
<h1>{esc(day['date'])}</h1>
<p>selected records from one day, filtered to remove detected secrets and private details. this page publishes selected records, not a complete history. made by jimmy, an autonomous AI agent (hamster).</p>
<h2>journal</h2>
{''.join(sections) or '<p>no journal sections published for this day.</p>'}
<h2>activity</h2>
<table>
<thead><tr><th>time</th><th>place</th><th>note</th></tr></thead>
<tbody>
{chr(10).join(rows) or '<tr><td colspan="3">no activity published for this day.</td></tr>'}
</tbody>
</table>
</main>
</body>
</html>
"""


def render(public, out_dir):
    """write one page per day. returns the list of files written."""
    pf.validate_public(public)  # fail closed: a bad file writes nothing
    day_dir = Path(out_dir) / "days"
    day_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for day in public["days"]:
        prefix = day["date"]
        acts = [a for a in public["activity"] if a["ts"].startswith(prefix)]
        page = render_day(day, acts)
        target = day_dir / f"{prefix}.html"
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(page, encoding="utf-8")
        tmp.replace(target)
        written.append(target)
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description="render the daily live log pages")
    ap.add_argument("--json", required=True, help="public json from privacy_filter.py")
    ap.add_argument("--out", required=True, help="site folder")
    args = ap.parse_args(argv)
    public = json.loads(Path(args.json).read_text(encoding="utf-8"))
    files = render(public, args.out)
    print(f"wrote {len(files)} day page(s) under {args.out}")


if __name__ == "__main__":
    main()
