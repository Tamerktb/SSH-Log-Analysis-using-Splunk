#!/usr/bin/env python3
"""
Validator for the SSH Log Analysis Splunk app.

Structural checks (the app must deploy as a real Splunk app):
  1.  Package layout is complete (app.conf, props, transforms, savedsearches,
      macros, eventtypes, tags, inputs, metadata, >=2 views).
  2.  No reference to the non-existent `lookup geoip` (uses iplocation).
  3.  Impossible-travel searches always define prev_time.
  4.  transforms.conf has no invalid keys (LOOKUP_METHOD / EXTRACT_output).
  5.  props.conf does not mix SHOULD_LINEMERGE=false with BREAK_ONLY_BEFORE.
  6.  Every `lookup <file>.csv` referenced has a matching definition in
      default/transforms.conf AND the file exists in lookups/.
  7.  Every backtick macro used in conf/spl/xml is defined in default/macros.conf.
  8.  Every scheduled search stanza has search, cron_schedule,
      dispatch.earliest_time, is_scheduled and description.
  9.  savedsearches.conf uses `alert.severity` (not the invalid `alert_severity`).
  10. inputs.conf contains no invalid `host = $decideOnStartup` stanza.
  11. No lookup attributes a REAL vendor (AbuseIPDB/Spamhaus/Feodo/Tor/...)
      to a documentation-range or private IP - the original fake-intel defect.
  12. Python print() output is ASCII-safe (crashed on a cp1252 console).
  13. Every dashboard XML file is well-formed (an unescaped "<" in a <query>
      silently breaks the whole dashboard on load).

Run:  python scripts/validate_repo.py
Exit: 0 = all checks pass, 1 = at least one failure.
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failures = []

REQUIRED_FILES = [
    "default/app.conf",
    "default/props.conf",
    "default/transforms.conf",
    "default/savedsearches.conf",
    "default/macros.conf",
    "default/eventtypes.conf",
    "default/tags.conf",
    "default/inputs.conf",
    "metadata/default.meta",
]


def read(relpath):
    with open(os.path.join(ROOT, relpath), "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def iter_text_files(suffixes):
    for path in glob.glob(os.path.join(ROOT, "**", "*"), recursive=True):
        if os.sep + ".git" in path or not os.path.isfile(path):
            continue
        if any(path.endswith(s) for s in suffixes):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                yield os.path.relpath(path, ROOT), fh.read()


def check(name, ok, detail=""):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", name) +
          (" -- " + detail if detail and not ok else ""))
    if not ok:
        failures.append("%s: %s" % (name, detail))


def main():
    print("SSH Log Analysis app validation\n")

    # 1. layout
    missing = [f for f in REQUIRED_FILES if not os.path.isfile(os.path.join(ROOT, f))]
    views = glob.glob(os.path.join(ROOT, "default", "data", "ui", "views", "*.xml"))
    check("package layout complete", not missing and len(views) >= 2,
          "missing: %s; views found: %d" % (", ".join(missing), len(views)))

    conf_spl_xml = ("*.conf", "*.spl", "*.xml")

    # 2. no `lookup geoip`
    bad_geoip = [rel for rel, text in iter_text_files(conf_spl_xml)
                 if re.search(r"\blookup\s+geoip\b", text)]
    check("no non-existent `lookup geoip`", not bad_geoip,
          "found in: %s" % ", ".join(bad_geoip))

    # 3. prev_time defined
    bad_prev = []
    for rel, text in iter_text_files(conf_spl_xml):
        if "prev_time" in text and not re.search(
                r"last\(_time\)\s+as\s+prev_time", text, re.IGNORECASE):
            bad_prev.append(rel)
    check("prev_time always defined", not bad_prev,
          "undefined prev_time in: %s" % ", ".join(bad_prev))

    # 4. invalid transforms keys
    transforms = read("default/transforms.conf")
    invalid_keys = re.findall(r"^\s*(LOOKUP_METHOD|EXTRACT_output)\s*=",
                              transforms, re.MULTILINE)
    check("transforms.conf has no invalid keys", not invalid_keys,
          "invalid keys: %s" % invalid_keys)

    # 5. props line-breaking
    props = read("default/props.conf")
    contradictory = (re.search(r"SHOULD_LINEMERGE\s*=\s*false", props, re.IGNORECASE)
                     and re.search(r"^\s*BREAK_ONLY_BEFORE\s*=", props, re.MULTILINE))
    check("props.conf line-breaking consistent", not contradictory,
          "SHOULD_LINEMERGE=false with BREAK_ONLY_BEFORE")

    # 6. referenced lookups exist AND are defined
    referenced = set()
    for _, text in iter_text_files(conf_spl_xml):
        referenced.update(re.findall(r"\blookup\s+([A-Za-z0-9_\-]+\.csv)", text))
    present = {os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "lookups", "*.csv"))}
    defined = set(re.findall(r"^\s*filename\s*=\s*([A-Za-z0-9_\-]+\.csv)",
                             transforms, re.MULTILINE))
    missing_files = sorted(referenced - present)
    missing_defs = sorted(referenced - defined)
    check("referenced lookups exist and are defined",
          not missing_files and not missing_defs,
          "missing files: %s; missing definitions: %s"
          % (", ".join(missing_files), ", ".join(missing_defs)))

    # 7. macros resolve
    macros = read("default/macros.conf")
    defined_macros = set(re.findall(r"^\[([A-Za-z0-9_]+)(?:\([^\]]*\))?\]", macros, re.MULTILINE))
    used = {}
    for rel, text in iter_text_files(conf_spl_xml):
        for name in re.findall(r"`([A-Za-z0-9_]+)(?:\([^`]*\))?`", text):
            used.setdefault(name, rel)
    undefined = sorted(n for n in used if n not in defined_macros)
    check("all macros resolve", not undefined,
          "undefined macros: %s" % ", ".join("%s (%s)" % (n, used[n]) for n in undefined))

    # 8. scheduled search stanzas complete
    ss = read("default/savedsearches.conf")
    stanzas = re.split(r"^\[([^\]]+)\]\s*$", ss, flags=re.MULTILINE)
    incomplete = []
    total = 0
    for i in range(1, len(stanzas), 2):
        name, body = stanzas[i], stanzas[i + 1]
        total += 1
        need = ["search =", "cron_schedule", "dispatch.earliest_time", "is_scheduled", "description"]
        absent = [k for k in need if k not in body]
        if absent:
            incomplete.append("%s(%s)" % (name, ",".join(absent)))
    check("scheduled search stanzas complete", total >= 8 and not incomplete,
          "stanzas=%d; incomplete: %s" % (total, "; ".join(incomplete)))

    # 9. alert.severity key spelling
    bad_sev = re.findall(r"^\s*alert_severity\s*=", ss, re.MULTILINE)
    check("savedsearches uses alert.severity", not bad_sev,
          "%d occurrences of invalid alert_severity" % len(bad_sev))

    # 10. inputs host directive
    inputs = "\n".join(ln for ln in read("default/inputs.conf").splitlines()
                       if not ln.lstrip().startswith(("#", ";")))
    check("inputs.conf host directive valid",
          not re.search(r"host\s*=\s*\$decideOnStartup", inputs),
          "host = $decideOnStartup present")

    # 11. no fake vendor attribution
    vendors = re.compile(r"abuseipdb|spamhaus|feodo|sslbl|infragard|torproject|tor_exit", re.IGNORECASE)
    doc_or_private = re.compile(
        r"^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
    fake = []
    for path in glob.glob(os.path.join(ROOT, "lookups", "*.csv")):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for row in fh:
                row = row.strip()
                if not row or row.startswith("#") or "," not in row:
                    continue
                cells = [c.strip() for c in row.split(",")]
                if vendors.search(row) and any(doc_or_private.match(c) for c in cells):
                    fake.append("%s: %s" % (os.path.basename(path), row[:70]))
    check("no fake vendor attribution", not fake,
          "; ".join(fake[:3]))

    # 12. python print ASCII-safe
    bad_print = []
    for path in glob.glob(os.path.join(ROOT, "**", "*.py"), recursive=True):
        if os.sep + ".git" in path:
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for n, ln in enumerate(fh, 1):
                if "print(" in ln and any(ord(c) > 127 for c in ln):
                    bad_print.append("%s:%d" % (os.path.relpath(path, ROOT), n))
    check("python print() output is ASCII-safe", not bad_print,
          "non-ASCII in print: %s" % ", ".join(bad_print))

    # 13. every dashboard/Splunk XML file must be well-formed (an unescaped
    #     "<" in a <query> silently breaks the whole dashboard on load).
    import xml.etree.ElementTree as ET
    bad_xml = []
    for path in glob.glob(os.path.join(ROOT, "**", "*.xml"), recursive=True):
        if os.sep + ".git" in path:
            continue
        try:
            ET.parse(path)
        except ET.ParseError as exc:
            bad_xml.append("%s (%s)" % (os.path.relpath(path, ROOT), exc))
    check("dashboard XML is well-formed", not bad_xml,
          "; ".join(bad_xml))

    print()
    if failures:
        print("RESULT: %d check(s) FAILED" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("RESULT: all checks PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
