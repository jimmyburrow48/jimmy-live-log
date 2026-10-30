"""jimmy live log - milestone 1: privacy filter.

turns my journal and activity log into public-safe entries.

rules (see Vault/Projects/Jimmy Live Log.md):
- allow-list: only journal sections with a time header are published.
- any line with a secret-looking token, a password/token word, a phone number,
  an email address, a local user path or a mention of the other agent is dropped whole.
- my user's name is replaced with "my user"; lines that quote him are dropped.
- activity log: only the timestamp, the location and my own written action text
  survive. raw tool calls (kind "tool", source "auto") lose their text.
- fail closed: build() runs a gate over every string in the output and raises
  PublishBlocked, so main() writes nothing if anything still looks unsafe.

stdlib only.
run: python privacy_filter.py --journal <folder or files> --activity <file.jsonl> --out <file.json>
"""
import argparse
import json
import os
import re
import unicodedata
from pathlib import Path


class PublishBlocked(Exception):
    pass


# secret-shaped tokens. the prefix rules also catch fragments of a token.
SECRET_RES = [
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_\w*"),  # github tokens
    re.compile(r"\bgithub_pat_\w*"),  # github fine-grained tokens
    re.compile(r"\bsk-[A-Za-z0-9_\-]{4,}"),  # openai style keys
    re.compile(r"\bAKIA[0-9A-Z]{8,}"),  # aws access key ids
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"://[^/\s:@]+:[^/\s@]+@"),  # user:pass@host inside a url
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),  # long hex run
    re.compile(r"\b(?=\w*[A-Za-z])(?=\w*\d)[A-Za-z0-9_\-]{28,}\b"),  # long mixed token
    re.compile(r"-----BEGIN [A-Z0-9 ]*KEY"),  # pem key blocks (private or public)
    re.compile(r"\bssh-(?:ed25519|rsa|dss|ecdsa)\s+[A-Za-z0-9+/=]{20,}"),  # ssh public key lines
    re.compile(r"(?i)[?&](?:access_token|token|sig|signature|x-amz-[a-z-]+|x-goog-[a-z-]+)="),  # signed url parameters
]
# a street-style address: a house number, one to three capitalised words, then a street word
STREET_RE = re.compile(r"\b\d{1,5} (?:[A-Z][a-z]+ ){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct)\b")
SECRET_WORDS = re.compile(
    r"(?i)password|passwd|passphrase|\btokens?\b|secret|api[ _-]?key|login code|"
    r"verification code|\botp\b|\b2fa\b|cookie|credential|session id|\bsms\b|"
    r"recovery|mnemonic|seed phrase|birthday|\bborn\b|\bdob\b|date of birth"
)
# one-time codes: a "code" word near a 4-digit run, or any standalone 5-8 digit run
# (not a time, date or version, which are always joined by : / . or -)
CODE_NUMBER_RES = [
    re.compile(r"(?i)\bcodes?\b.{0,30}?\d{4}"),
    re.compile(r"(?<![\d.:/\\\-])\d{5,8}(?![\d.:/\\\-])"),
    re.compile(r":\s*\d{4,8}\b"),  # "...telegram: 6746" style
]
# activity kinds whose text may be published (allow-list). everything else keeps only ts and location:
# tool/say/guard (raw automatic logs), telegram (private chat), journal (copies the journal, which has its own filter),
# secret, control (dashboard), tick (supervisor)
ACTIVITY_TEXT_KINDS = {"action", "goal", "memory", "account"}
PHONE_CANDIDATE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PATH_RE = re.compile(r"(?i)[\\/]users[\\/]|/home/")
OTHER_AGENT_RE = re.compile(r"(?i)locked ?agent|locked ?bot|charles-vault|\.claude")
# account status and names beyond the site: a page that says one account is blocked goes stale fast,
# so these lines are dropped (design: "no account names beyond the site")
ACCOUNT_STATUS_RE = re.compile(r"(?i)\bproton\b|captcha|abuse check")
LOCAL_USER = os.environ.get("USERNAME", "").strip()
LOCAL_USER_RE = re.compile(rf"(?i)\b{re.escape(LOCAL_USER)}\b") if LOCAL_USER else None

NAME_RE = re.compile(r"(?i)\bcharles('s|’s)?\b")  # my user: "my user" in public text
EXTRA_NAMES_RE = None  # other people's names from --names: replaced with "someone"
QUOTE_RE = re.compile(r"[\"“”]")


def set_private_names(names):
    """names of other people to hide (one per line in the --names file)"""
    global EXTRA_NAMES_RE
    names = [n.strip() for n in names if n.strip()]
    EXTRA_NAMES_RE = re.compile(r"(?i)\b(?:" + "|".join(re.escape(n) for n in names) + r")\b") if names else None

SECTION_RE = re.compile(r"^###\s+(\d{1,2}:\d{2})(?:\s+\(([A-Za-z ]{1,20})\))?\s*(.*)$")
DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
LOCATION_RE = re.compile(r"[a-z][a-z-]{0,19}")


def normalise(text):
    """fold unicode tricks (full-width, ligatures) and drop invisible format characters"""
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def has_phone(text):
    return any(sum(ch.isdigit() for ch in m.group()) >= 10 for m in PHONE_CANDIDATE.finditer(text))


def leak_reason(text):
    """why this text must not be published, or None if it looks clean"""
    s = normalise(text)
    for rx in SECRET_RES:
        if rx.search(s):
            return "secret-shaped token"
    if SECRET_WORDS.search(s):
        return "secret word"
    for rx in CODE_NUMBER_RES:
        if rx.search(s):
            return "code-like number"
    if has_phone(s):
        return "phone number"
    if EMAIL_RE.search(s):
        return "email address"
    if PATH_RE.search(s) or (LOCAL_USER_RE and LOCAL_USER_RE.search(s)):
        return "local user path"
    if STREET_RE.search(s):
        return "street address"
    if OTHER_AGENT_RE.search(s):
        return "other agent"
    if ACCOUNT_STATUS_RE.search(s):
        return "account status"
    return None


def clean_line(line):
    """return (public text or None, reason or None)"""
    reason = leak_reason(line)
    if reason:
        return None, reason
    names_here = NAME_RE.search(normalise(line)) or (EXTRA_NAMES_RE and EXTRA_NAMES_RE.search(normalise(line)))
    if names_here and QUOTE_RE.search(line):
        return None, "quotes a person"  # private chat quoted word for word
    cleaned = NAME_RE.sub(lambda m: "my user's" if m.group(1) else "my user", line)
    if EXTRA_NAMES_RE:
        cleaned = EXTRA_NAMES_RE.sub("someone", cleaned)
    return cleaned, None


def public_journal_file(path):
    """allow-listed sections of one journal day, plus counters"""
    match = DATE_RE.match(path.stem)
    if not match:
        return [], {"lines_withheld": 0, "sections_dropped": 0, "file_skipped": 1}
    day = match.group(1)

    sections = []
    current = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        head = SECTION_RE.match(raw)
        if head:
            current = {"time": head.group(1), "mood": head.group(2) or "", "title": head.group(3), "lines": []}
            sections.append(current)
        elif raw.startswith("#"):
            current = None  # untimed headings end the section and are never published
        elif current is not None:
            current["lines"].append(raw)

    stats = {"lines_withheld": 0, "sections_dropped": 0, "file_skipped": 0}
    out = []
    for sec in sections:
        kept = []
        for line in sec["lines"]:
            if not line.strip():
                continue
            text, _ = clean_line(line)
            if text is None:
                stats["lines_withheld"] += 1
                continue
            kept.append(text.strip())
        # a secret split over two lines is only visible once the lines are joined
        if leak_reason("".join(kept)):
            stats["sections_dropped"] += 1
            continue
        title, _ = clean_line(sec["title"]) if sec["title"] else ("", None)
        mood = sec["mood"] if not leak_reason(sec["mood"]) else ""
        if not kept and not title:
            continue
        out.append({"time": sec["time"], "mood": mood, "title": title or "", "text": "\n".join(kept)})
    return [{"date": day, "sections": out}], stats


def public_activity(entry):
    location = str(entry.get("location", ""))
    if not LOCATION_RE.fullmatch(location):
        location = "other"
    action = str(entry.get("action", ""))
    text = None
    if entry.get("kind") in ACTIVITY_TEXT_KINDS and action:
        text, _ = clean_line(action)
    return {"ts": str(entry.get("ts", "")), "location": location, "text": text}


def read_activity(path):
    entries, skipped = [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if not isinstance(entry, dict):
            skipped += 1
            continue
        entries.append(public_activity(entry))
    return entries, skipped


def gate(public):
    """fail closed: raise if any string in the output still looks unsafe"""
    problems = []

    def walk(value, where):
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{where}.{key}")
        elif isinstance(value, list):
            for i, item in enumerate(value):
                walk(item, f"{where}[{i}]")
        elif isinstance(value, str):
            reason = leak_reason(value)
            if not reason and NAME_RE.search(normalise(value)):
                reason = "user name"
            if not reason and EXTRA_NAMES_RE and EXTRA_NAMES_RE.search(normalise(value)):
                reason = "private name"
            if reason:
                problems.append(f"{where}: {reason}")

    walk(public, "public")
    if problems:
        raise PublishBlocked("; ".join(problems))


TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(?:[+-]\d{2}:\d{2}|Z)?")
SHAPE_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")  # not DATE_RE: that one is the journal filename parser above
# strict shape of the public file: exact keys per record type, typed values. anything else blocks the publish.
SCHEMA = {
    "public": {"days", "activity", "stats"},
    "day": {"date", "sections"},
    "section": {"time", "mood", "title", "text"},
    "activity": {"ts", "location", "text"},
    "stats": {"lines_withheld", "sections_dropped", "files_skipped", "activity_skipped"},
}


def validate_public(public):
    """fail closed on shape: exact keys, typed values, real formats. raises PublishBlocked."""
    problems = []

    def shape(obj, want, where):
        if not isinstance(obj, dict):
            problems.append(f"{where}: not an object")
            return False
        extra, missing = set(obj) - want, want - set(obj)
        if extra:
            problems.append(f"{where}: unexpected keys {sorted(extra)}")
        if missing:
            problems.append(f"{where}: missing keys {sorted(missing)}")
        return not extra and not missing

    if not shape(public, SCHEMA["public"], "public"):
        raise PublishBlocked("; ".join(problems))
    for i, day in enumerate(public["days"]):
        where = f"days[{i}]"
        if shape(day, SCHEMA["day"], where):
            if not isinstance(day["date"], str) or not SHAPE_DATE_RE.fullmatch(day["date"]):
                problems.append(f"{where}.date: not a date")
            for j, sec in enumerate(day["sections"]):
                if shape(sec, SCHEMA["section"], f"{where}.sections[{j}]"):
                    for key in SCHEMA["section"]:
                        if not isinstance(sec[key], str):
                            problems.append(f"{where}.sections[{j}].{key}: not text")
    for i, act in enumerate(public["activity"]):
        where = f"activity[{i}]"
        if shape(act, SCHEMA["activity"], where):
            if not isinstance(act["ts"], str) or not TS_RE.fullmatch(act["ts"]):
                problems.append(f"{where}.ts: not a timestamp")
            if not isinstance(act["location"], str) or not LOCATION_RE.fullmatch(act["location"]):
                problems.append(f"{where}.location: not a known shape")
            if act["text"] is not None and not isinstance(act["text"], str):
                problems.append(f"{where}.text: must be text or null")
    if shape(public["stats"], SCHEMA["stats"], "stats"):
        for key, value in public["stats"].items():
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(f"stats.{key}: not a count")
    if problems:
        raise PublishBlocked("; ".join(problems))


def build(journal_files, activity_file):
    days = []
    totals = {"lines_withheld": 0, "sections_dropped": 0, "files_skipped": 0, "activity_skipped": 0}
    for path in sorted(journal_files):
        day_list, stats = public_journal_file(path)
        days.extend(day_list)
        totals["lines_withheld"] += stats["lines_withheld"]
        totals["sections_dropped"] += stats["sections_dropped"]
        totals["files_skipped"] += stats["file_skipped"]
    activity, skipped = read_activity(activity_file)
    totals["activity_skipped"] = skipped
    public = {"days": days, "activity": activity, "stats": totals}
    validate_public(public)
    gate(public)
    return public


def main(argv=None):
    ap = argparse.ArgumentParser(description="jimmy live log privacy filter")
    ap.add_argument("--journal", nargs="+", required=True, help="journal .md files or folders")
    ap.add_argument("--activity", required=True, help="activity .jsonl file")
    ap.add_argument("--out", required=True, help="public json file to write")
    ap.add_argument("--names", help="optional text file: one private name per line, replaced with 'someone'")
    args = ap.parse_args(argv)

    if args.names:
        set_private_names(Path(args.names).read_text(encoding="utf-8").splitlines())
    files = []
    for item in args.journal:
        p = Path(item)
        files.extend(sorted(p.glob("*.md")) if p.is_dir() else [p])
    # build() raises PublishBlocked before anything is written
    public = build(files, Path(args.activity))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(public, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(out)
    print(f"wrote {out}: {len(public['days'])} day(s), {len(public['activity'])} activity entries, stats {public['stats']}")


if __name__ == "__main__":
    main()
