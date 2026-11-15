#!/usr/bin/env python3
"""
SCRAPEWARD — catch the harvesters in your logs.

A single-file, dependency-free detector for the kind of mass social-media /
directory scraping that bulk "parse every user's phone + email" tools do. Point
it at your web access log; it scores each client on the behaviours that separate
a human browser from a harvester and prints a ranked report + an optional block
list. Read-only: it never touches your server, it just reads the log.

  python3 scrapeward.py /var/log/nginx/access.log
  python3 scrapeward.py access.log --since 60 --min-score 50 --block > deny.conf
  tail -f access.log | python3 scrapeward.py -            # live

Signals (each contributes to a 0-100 score; see --explain):
  rate        requests/min well above human browsing
  enumerate   many DISTINCT profile/listing URLs walked in order (harvest sweep)
  idwalk      sequential numeric IDs in the path (/user/1001, /user/1002, …)
  noassets    hammers HTML/API but never pulls css/js/images (bots skip them)
  ua          missing / generic / known-scraper / rotating User-Agent from one IP
  errors      bursts of 401/403/429 (hitting walls) or 404 (probing)

MIT licensed. Defensive use. WITNESS ME.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

# ---- log parsing -----------------------------------------------------------
# Combined Log Format:
#   IP - - [10/Oct/2026:13:55:36 +0000] "GET /path HTTP/1.1" 200 1234 "ref" "UA"
_CLF = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

_ASSET = re.compile(r'\.(?:css|js|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|map|mp4|webm)(?:\?|$)', re.I)
# "a profile/listing to harvest": tune to your app; these are common shapes.
_PROFILE = re.compile(r'/(?:users?|profile|members?|accounts?|u|@|people|id)/|/(?:posts?|listing|item|ad|catalog)/', re.I)
_NUMID = re.compile(r'/(\d{2,})(?:/|$|\?)')
_SCRAPER_UA = re.compile(
    r'(?:python-requests|scrapy|httpx|aiohttp|curl|wget|go-http|okhttp|java/|libwww|'
    r'phantomjs|headless|puppeteer|playwright|selenium|bot|spider|crawl|harvest|parse)', re.I)
_GENERIC_UA = re.compile(r'^(?:-|mozilla/\d\.0)?$', re.I)


class Client:
    __slots__ = ("ip", "n", "paths", "profile_paths", "ids", "assets", "nonassets",
                 "uas", "errors", "probes", "first", "last")

    def __init__(self, ip: str):
        self.ip = ip
        self.n = 0
        self.paths: list[str] = []
        self.profile_paths = 0
        self.ids: list[int] = []
        self.assets = 0
        self.nonassets = 0
        self.uas: set[str] = set()
        self.errors = 0          # 401/403/429
        self.probes = 0          # 404
        self.first: datetime | None = None
        self.last: datetime | None = None

    def add(self, path, status, ua, ts):
        self.n += 1
        if len(self.paths) < 4000:
            self.paths.append(path)
        if _ASSET.search(path):
            self.assets += 1
        else:
            self.nonassets += 1
        if _PROFILE.search(path):
            self.profile_paths += 1
        m = _NUMID.search(path)
        if m:
            try:
                self.ids.append(int(m.group(1)))
            except ValueError:
                pass
        self.uas.add((ua or "").strip())
        if status in (401, 403, 429):
            self.errors += 1
        elif status == 404:
            self.probes += 1
        if ts:
            if self.first is None or ts < self.first:
                self.first = ts
            if self.last is None or ts > self.last:
                self.last = ts

    # ---- scoring -----------------------------------------------------------
    def span_min(self) -> float:
        if self.first and self.last and self.last > self.first:
            return (self.last - self.first).total_seconds() / 60.0
        return 0.0

    def rate(self) -> float:
        s = self.span_min()
        return self.n / s if s > 0 else float(self.n)  # single-burst => count

    def idwalk_frac(self) -> float:
        if len(self.ids) < 5:
            return 0.0
        seq = sorted(self.ids)
        steps = sum(1 for a, b in zip(seq, seq[1:]) if 0 < (b - a) <= 3)
        return steps / max(1, len(seq) - 1)

    def score(self) -> tuple[int, dict]:
        ev = {}
        s = 0.0
        r = self.rate()
        if r >= 600: ev["rate"] = f"{r:.0f}/min"; s += 30
        elif r >= 120: ev["rate"] = f"{r:.0f}/min"; s += 18
        elif r >= 40: ev["rate"] = f"{r:.0f}/min"; s += 8
        uniq_prof = len(set(p for p in self.paths if _PROFILE.search(p)))
        if uniq_prof >= 200: ev["enumerate"] = f"{uniq_prof} distinct profiles"; s += 28
        elif uniq_prof >= 40: ev["enumerate"] = f"{uniq_prof} distinct profiles"; s += 16
        elif uniq_prof >= 12: ev["enumerate"] = f"{uniq_prof} distinct profiles"; s += 7
        iw = self.idwalk_frac()
        if iw >= 0.5 and len(self.ids) >= 10: ev["idwalk"] = f"{iw*100:.0f}% sequential ids"; s += 18
        tot = self.assets + self.nonassets
        if tot >= 30 and self.assets == 0: ev["noassets"] = "0 assets loaded"; s += 16
        elif tot >= 60 and self.assets / tot < 0.05: ev["noassets"] = f"{self.assets/tot*100:.0f}% assets"; s += 9
        real = [u for u in self.uas if u and u != "-"]
        if not real or all(_GENERIC_UA.match(u) for u in real): ev["ua"] = "missing/generic UA"; s += 14
        elif any(_SCRAPER_UA.search(u) for u in real): ev["ua"] = "scraper-lib UA"; s += 20
        elif len(real) >= 6: ev["ua"] = f"{len(real)} rotating UAs"; s += 12
        if self.errors >= 20: ev["errors"] = f"{self.errors} 401/403/429"; s += 10
        if self.probes >= 40: ev["probes"] = f"{self.probes} 404 probes"; s += 6
        return min(100, int(round(s))), ev


def parse_line(line: str):
    m = _CLF.match(line)
    if not m:
        return None
    try:
        status = int(m.group("status"))
    except ValueError:
        return None
    ts = None
    try:
        ts = datetime.strptime(m.group("ts"), _TS_FMT)
    except (ValueError, TypeError):
        pass
    return m.group("ip"), m.group("path"), status, m.group("ua"), ts


def run(lines, since_min=None, min_score=40):
    clients: dict[str, Client] = {}
    cutoff = None
    if since_min:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_min)
    total = 0
    for line in lines:
        rec = parse_line(line)
        if not rec:
            continue
        ip, path, status, ua, ts = rec
        if cutoff and ts and ts < cutoff:
            continue
        total += 1
        c = clients.get(ip)
        if c is None:
            c = clients[ip] = Client(ip)
        c.add(path, status, ua, ts)
    scored = []
    for c in clients.values():
        sc, ev = c.score()
        if sc >= min_score:
            scored.append((sc, c, ev))
    scored.sort(key=lambda t: (-t[0], -t[1].n))
    return total, len(clients), scored


def main():
    ap = argparse.ArgumentParser(description="SCRAPEWARD — detect scrapers in your access log")
    ap.add_argument("logfile", help="access log path, or - for stdin")
    ap.add_argument("--since", type=int, default=None, metavar="MIN", help="only the last N minutes")
    ap.add_argument("--min-score", type=int, default=40, help="report clients at/above this score (0-100)")
    ap.add_argument("--block", action="store_true", help="emit an nginx deny list for the flagged IPs")
    ap.add_argument("--explain", action="store_true", help="print the signal reference and exit")
    args = ap.parse_args()

    if args.explain:
        print(__doc__)
        return

    src = sys.stdin if args.logfile == "-" else open(args.logfile, "r", errors="replace")
    total, n_clients, scored = run(src, args.since, args.min_score)
    if src is not sys.stdin:
        src.close()

    if args.block:
        print("# SCRAPEWARD deny list — review before applying")
        for sc, c, ev in scored:
            print(f"deny {c.ip};  # score {sc}: {', '.join(ev)}")
        return

    print(f"SCRAPEWARD — {total} requests, {n_clients} clients, {len(scored)} flagged "
          f"(>= {args.min_score})\n")
    if not scored:
        print("  no scrapers above threshold. Lower --min-score to see borderline clients.")
        return
    for sc, c, ev in scored:
        bar = "#" * (sc // 5)
        print(f"  [{sc:3d}] {bar:<20} {c.ip}  ({c.n} req, {c.rate():.0f}/min)")
        for k, v in ev.items():
            print(f"        - {k}: {v}")
    print("\n  Re-run with --block to emit a deny list. Tune _PROFILE/_NUMID in the "
          "source to your app's URL shapes.")


if __name__ == "__main__":
    main()
