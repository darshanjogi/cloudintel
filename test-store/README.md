# CloudIntel demo store

Two Python scripts that let you exercise all 40 CloudIntel fingerprints locally, without
touching real cloud services or the internet.

- **`server.py`** — a tiny HTTP server that produces synthetic responses reproducing the
  real signals each fingerprint looks for (headers, error XML bodies, cookies). It routes on
  the request's `Host:` header, so the extension sees real cloud hostnames.
- **`drive.py`** — a one-shot driver that fires two requests per scenario through Burp's
  proxy, satisfying `require_distinct_indicators >= 2` for every service.

## Prereqs

- Python 3.10+ (only stdlib is used).
- Burp Suite running with CloudIntel loaded.

## Quick start

```bash
# terminal A: start the demo store
python3 server.py                       # http://127.0.0.1:8787

# terminal B: drive it through Burp (Burp default proxy 127.0.0.1:8080)
python3 drive.py --burp-proxy 127.0.0.1:8080
```

Open the **CloudIntel** tab in Burp. You should see 40 findings — every service present in
the tree. Every finding should also appear under **Target → Issues**.

If you want to hit the store *without* Burp (e.g. to sanity-check the server):

```bash
python3 drive.py --burp-proxy ''
```

## How the routing works

- The scripts send requests to `http://127.0.0.1:8787/…` with a real cloud host in the
  `Host:` header (e.g. `Host: company-assets.s3.amazonaws.com`).
- Burp records the request as sent to the real hostname and forwards the connection to the
  local server.
- The server dispatches on the `Host:` header and replies with a synthetic response carrying
  that provider's real signals.
- CloudIntel observes the request+response as if it were the real cloud service and fires
  the matching fingerprint.

## Adding a scenario

Adding a new fingerprint? Add a corresponding scenario:

1. In `server.py`, add a `@scenario(host_regex)` handler that returns
   `(status, headers, body)` reproducing the real service's signals — headers, cookies,
   error XML, whatever the fingerprint's indicators match on.
2. In `drive.py`, add one tuple to `SCENARIOS` with the fingerprint id, the cloud host to
   send in `Host:`, and a path.
3. Rerun `drive.py`.

Keep responses minimal — just enough signal to trip the fingerprint. Don't paste real cloud
tokens or IDs.

## Caveats

- This exercises **detection**, not real attack surface. It won't help you validate
  attack-vector text or wordlist accuracy.
- Some fingerprints require rare responses (e.g. specific error codes on specific paths).
  Adjust the demo server's handler if your fingerprint needs a particular status code.
- Cloudflare is emitted only on demand via a fallback handler; production Cloudflare
  responses are usually front-of-something-else. Add a Host regex if you need it.
