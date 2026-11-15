# SCRAPEWARD

*Catch the harvesters in your logs.*

There's a whole industry of tools that scrape social platforms, directories and
member pages to harvest **every user's phone number, email and profile** in bulk —
"without limits." SCRAPEWARD is the defender's side of that: point it at your web
access log and it tells you **which clients are harvesting you**, with the evidence,
and hands you a block list.

Single file, **zero dependencies**, read-only (it never touches your server — it just
reads the log). Free.

```bash
python3 scrapeward.py /var/log/nginx/access.log          # ranked report
python3 scrapeward.py access.log --since 60              # last hour only
python3 scrapeward.py access.log --block > deny.conf     # nginx deny list
tail -f access.log | python3 scrapeward.py -             # live
```

## What it looks for

A human with a browser and a harvester script look completely different in your log.
SCRAPEWARD scores each client 0–100 across the behaviours that separate them:

| signal | what it catches |
| --- | --- |
| **rate** | requests/min far above human browsing |
| **enumerate** | many *distinct* profile/listing URLs walked in one session (a sweep) |
| **idwalk** | sequential numeric IDs in the path — `/user/1001`, `/user/1002`, … |
| **noassets** | hammers HTML/API but never loads css/js/images (bots skip them) |
| **ua** | missing / generic / known scraper-library / rotating User-Agents from one IP |
| **errors** | bursts of 401/403/429 (hitting walls) or 404 (probing) |

Example on a log with one real visitor and one harvester sweeping `/user/<id>`:

```
SCRAPEWARD — 340 requests, 2 clients, 1 flagged (>= 40)

  [100] #################### 198.51.100.7  (300 req, 243/min)
        - rate: 243/min
        - enumerate: 300 distinct profiles
        - idwalk: 100% sequential ids
        - noassets: 0 assets loaded
        - ua: scraper-lib UA
```

The real visitor never shows up — that's the point.

## Tuning

Out of the box it recognises common profile/listing URL shapes
(`/user/…`, `/profile/…`, `/members/…`, `/posts/…`, `@handle`, numeric IDs). Open the
source and adjust the two regexes near the top — `_PROFILE` and `_NUMID` — to match
your app's URLs. Everything is one readable file; there's nothing hidden.

`python3 scrapeward.py --explain` prints the full signal reference.

## Why free

Harvesting people's contact data at scale is somebody else's product. Detecting it
shouldn't cost you anything. Take it, read it, run it, fork it.

## License

MIT — see [LICENSE](LICENSE).

**WITNESS ME. FURY ROAD.**
