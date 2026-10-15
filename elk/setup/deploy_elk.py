#!/usr/bin/env python3
"""
deploy_elk.py - SSHLogAnalysis ELK port: one-shot, idempotent deployment.

  1. (re)create the feed indices, incl. the ip_range mapping Spamhaus needs
  2. load lookups/*.csv into them
  3. create + execute the ES enrich policies
  4. PUT the ssh-auth-enrich and ssh-auth-pipeline ingest pipelines
  5. optionally replay the pipeline over already-indexed documents

Usage:
  python3 deploy_elk.py --lookups ../lookups --pipelines ../elasticsearch
  python3 deploy_elk.py --es http://localhost:9200 --no-backfill
"""
import argparse, csv, json, os, sys, time, urllib.error, urllib.request

# csv file -> index / mapping / column renames. key = enrich match field.
FEEDS = {
    "tor_exit_nodes.csv": {
        "index": "ssh-ti-tor",
        "mapping": {"src_ip": {"type": "keyword"}, "tor_node_source": {"type": "keyword"}, "last_seen": {"type": "keyword"}},
    },
    "c2_blocklist.csv": {
        "index": "ssh-ti-c2",
        "mapping": {"src_ip": {"type": "keyword"}, "c2_source": {"type": "keyword"}, "last_seen": {"type": "keyword"}},
    },
    "spamhaus_drop.csv": {
        "index": "ssh-ti-spamhaus",
        "mapping": {"cidr": {"type": "ip_range"}, "sbl_reference": {"type": "keyword"}, "last_seen": {"type": "keyword"}},
        "rename": {"src_ip": "cidr"},
    },
    "ssh_allowlist.csv": {
        "index": "ssh-allowlist-src",
        "mapping": {"src_ip": {"type": "keyword"}, "allow_reason": {"type": "keyword"}, "owner": {"type": "keyword"}, "added": {"type": "keyword"}},
    },
    "known_attackers.csv": {
        "index": "ssh-watchlist-src",
        "mapping": {"src_ip": {"type": "keyword"}, "threat_type": {"type": "keyword"}, "ti_confidence": {"type": "integer"}, "ti_source": {"type": "keyword"}},
        "rename": {"confidence": "ti_confidence", "source": "ti_source"},
        "ints": ["ti_confidence"],
    },
}

POLICIES = {
    "ssh-allowlist": {"match": {"indices": "ssh-allowlist-src", "match_field": "src_ip", "enrich_fields": ["allow_reason", "owner"]}},
    "ssh-tor":       {"match": {"indices": "ssh-ti-tor",        "match_field": "src_ip", "enrich_fields": ["tor_node_source"]}},
    "ssh-c2":        {"match": {"indices": "ssh-ti-c2",         "match_field": "src_ip", "enrich_fields": ["c2_source"]}},
    "ssh-spamhaus":  {"range": {"indices": "ssh-ti-spamhaus",   "match_field": "cidr",   "enrich_fields": ["sbl_reference"]}},
    "ssh-watchlist": {"match": {"indices": "ssh-watchlist-src", "match_field": "src_ip", "enrich_fields": ["threat_type", "ti_confidence", "ti_source"]}},
}

# Pipelines published to Elasticsearch.
#  ssh-auth-pipeline : the ONE pipeline Filebeat points at. The parse and enrich
#                      halves are CONCATENATED into it, because a nested
#                      `pipeline` processor silently skips the enrich processors
#                      (enrich does not run inside a nested pipeline - verified).
#  ssh-auth-enrich   : enrich half on its own, so enrichment can be replayed
#                      independently with ?pipeline=ssh-auth-enrich.
PIPELINES = {
    "ssh-auth-enrich": ["pipeline-ssh-auth-enrich.json"],
    "ssh-auth-pipeline": ["pipeline-ssh-auth.json", "pipeline-ssh-auth-enrich.json"],
}


def call(es, method, path, body=None, raw=None, soft=False):
    data = raw.encode() if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(es + path, data=data, method=method,
                               headers={"Content-Type": "application/x-ndjson" if raw is not None else "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            txt = resp.read().decode()
    except urllib.error.HTTPError as e:
        txt = e.read().decode()
        if soft:
            return {"_error": e.code, "_body": txt}
        raise SystemExit("!! HTTP %s on %s %s\n%s" % (e.code, method, path, txt))
    return json.loads(txt) if txt.strip() else {}


def log(msg):
    print("  " + msg, flush=True)


def load_feed(es, lookups, fname, spec):
    path = os.path.join(lookups, fname)
    if not os.path.exists(path):
        raise SystemExit("!! missing feed file: " + path)
    idx = spec["index"]
    if _exists(es, idx):
        call(es, "DELETE", "/" + idx)
    call(es, "PUT", "/" + idx, {"mappings": {"properties": spec["mapping"]}})
    rows, skipped = [], 0
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            doc = {}
            for k, v in row.items():
                if k is None or v is None:
                    continue
                v = v.strip()
                if v == "":
                    continue
                key = spec.get("rename", {}).get(k, k)
                if key in spec.get("ints", []):
                    try:
                        v = int(v)
                    except ValueError:
                        continue
                doc[key] = v
            if not doc:
                skipped += 1
                continue
            rows.append(doc)
    body = ""
    for d in rows:
        body += json.dumps({"index": {"_index": idx}}) + "\n" + json.dumps(d) + "\n"
    if body:
        res = call(es, "POST", "/_bulk?refresh=true", raw=body)
        if res.get("errors"):
            raise SystemExit("!! bulk load errors for " + fname)
    log("%-22s -> %-20s %5d docs%s" % (fname, idx, len(rows), (" (%d blank skipped)" % skipped) if skipped else ""))


def _exists(es, idx):
    try:
        urllib.request.urlopen(es + "/" + idx, timeout=30)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--es", default="http://localhost:9200")
    ap.add_argument("--lookups", required=True)
    ap.add_argument("--pipelines", required=True)
    ap.add_argument("--datastream", default="filebeat-8.15.0")
    ap.add_argument("--backfill", default="1")
    a = ap.parse_args()

    print("[1/5] feed indices + lookups/*.csv  (%s)" % a.lookups)
    for fname, spec in FEEDS.items():
        load_feed(a.es, a.lookups, fname, spec)

    print("[2/5] enrich policies")
    # An enrich policy CANNOT be deleted while an ingest pipeline still references
    # it (DELETE returns resource_already_exist / "policy is in use"), so the
    # pipelines are torn down first and re-published in step [3/5].
    for name in PIPELINES:
        call(a.es, "DELETE", "/_ingest/pipeline/" + name, soft=True)
    for name, pol in POLICIES.items():
        # idempotent: drop the policy and its generated index (wildcards are not
        # allowed in index deletes here, so resolve the concrete names first).
        res = call(a.es, "DELETE", "/_enrich/policy/" + name, soft=True)
        if res.get("_error") not in (None, 404):
            raise SystemExit("!! cannot delete enrich policy %s: %s" % (name, res["_body"][:300]))
        for old in (call(a.es, "GET", "/_cat/indices/.enrich-%s-*?h=index&format=json" % name) or []):
            call(a.es, "DELETE", "/" + old["index"], soft=True)
        call(a.es, "PUT", "/_enrich/policy/" + name, pol)
        call(a.es, "POST", "/_enrich/policy/%s/_execute" % name)
        log("created " + name)
    # NOTE: there is no GET /_enrich/policy/<name>/_status endpoint (400 "no handler found").
    # Execution is async: it is done when the policy is absent from _enrich/_stats
    # executing_policies AND its generated .enrich-<policy>-<epoch> index exists.
    for name in POLICIES:
        phase = "TIMEOUT"
        for _ in range(60):
            st = call(a.es, "GET", "/_enrich/_stats")
            running = [(p.get("policy") or p.get("name")) for p in st.get("executing_policies") or []]
            have = call(a.es, "GET", "/_cat/indices/.enrich-%s-*?h=index&format=json" % name)
            if name not in running and have:
                phase = "COMPLETE"
                break
            time.sleep(1)
        if phase != "COMPLETE":
            raise SystemExit("!! enrich execution did not complete for " + name + " (still running)")
        log("executed %s -> %s (%s)" % (name, phase, have[0]["index"]))

    print("[3/5] ingest pipelines")
    for name, files in PIPELINES.items():
        procs = []
        for f in files:
            with open(os.path.join(a.pipelines, f), encoding="utf-8") as fh:
                procs += json.load(fh)["processors"]
        call(a.es, "PUT", "/_ingest/pipeline/" + name,
             {"description": "SSHLogAnalysis (ELK port) - " + " + ".join(files), "processors": procs})
        log("PUT %-22s %d processors" % (name, len(procs)))

    print("[4/5] backfill")

    if a.backfill == "1":
        res = call(a.es, "POST", "/%s/_update_by_query?pipeline=ssh-auth-pipeline&refresh=true&conflicts=proceed" % a.datastream,
                   {"query": {"match_all": {}}})
        log("replayed over %s: updated=%s failures=%s (%ss)" % (a.datastream, res.get("updated"), len(res.get("failures") or []), res.get("took", 0) / 1000.0))
        for f in (res.get("failures") or [])[:3]:
            log("  failure: " + json.dumps(f)[:300])
    else:
        log("skipped (--backfill 0)")

    print("[5/5] enrichment coverage")
    # source.geo.* is filled by the geoip processor (GeoLite2 from the ES downloader)
    # and is what the ElastAlert2 Impossible Travel rule consumes.
    for fld in ("event.action", "source.ip", "threat_intel", "source.geo.country_iso_code", "allow_reason"):
        c = call(a.es, "POST", "/%s/_count" % a.datastream, {"query": {"exists": {"field": fld}}})
        log("%-18s docs with field: %s" % (fld, c.get("count")))
    print("done.")


if __name__ == "__main__":
    main()
