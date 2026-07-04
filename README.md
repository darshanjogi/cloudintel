# CloudIntel

**Passive cloud attack-surface discovery for Burp Suite.**

CloudIntel watches proxy traffic and identifies the cloud services a target application
uses — reporting each concrete asset (bucket, distribution, function, endpoint, host) with
weighted-evidence confidence and a curated knowledge base of realistic, human-driven attack
vectors and verification steps.

CloudIntel **never sends its own traffic**. It pre-fills Burp Repeater and provides
checklists; every request is fired by the tester.

<!-- Add screenshots here for the BApp store submission (docs/img/) -->
<!-- ![Dashboard](docs/img/dashboard.png) -->
<!-- ![Evidence viewer](docs/img/evidence.png) -->

---

## Why CloudIntel

Existing extensions typically say _"AWS was detected."_ CloudIntel says:

> **Amazon S3 · Very High · score 160**
> Asset: `company-assets` (bucket)
> Why detected: `s3-host` + `x-amz-request-id` + `x-amz-id-2` + `<Code>NoSuchBucket</Code>`
> Attack surface: bucket ACL · public listing · versioning · CORS · signed URLs …

Every finding is an actionable target with a knowledge base, not a technology tag.

## Supported services (40 across 16 providers)

| Provider | Services |
| --- | --- |
| **AWS** (12) | S3, CloudFront, API Gateway, Lambda URL, Cognito, Elastic Beanstalk, ELB, EC2, ECR, SNS, SQS, Route53 |
| **Azure** (7) | Blob Storage, Functions, CDN, Cosmos DB, Storage Queue, Files, Key Vault |
| **Google Cloud** (7) | Cloud Storage, Cloud Functions, Firebase, App Engine, Cloud Run, BigQuery, Pub/Sub |
| **DigitalOcean** (2) | Spaces, App Platform |
| **CDNs / edge** | Cloudflare, Fastly, Akamai, BunnyCDN |
| **Platforms** | Vercel, Netlify, GitHub Pages, Heroku |
| **Object storage** | Oracle OCI, Alibaba OSS, Wasabi, Backblaze B2 |

Full spec: [`docs/specs/2026-07-04-cloud-artifact-discovery-design.md`](docs/specs/2026-07-04-cloud-artifact-discovery-design.md).
Add a service without touching Java: [`docs/FINGERPRINT-GUIDE.md`](docs/FINGERPRINT-GUIDE.md).

## Install

**From release JAR (recommended):**

1. Download `cloudintel-all.jar` from the [releases page](https://github.com/YOUR_USER/cloudintel/releases).
2. Burp → **Extensions → Add → Extension type: Java** → select the JAR.
3. A **CloudIntel** tab appears in the top bar.

**From source:**

```bash
git clone https://github.com/YOUR_USER/cloudintel.git
cd cloudintel
mvn package
# Loadable JAR: target/cloudintel-1.0.0-all.jar
```

Requires JDK 17+ and Maven. No other dependencies — SnakeYAML is shaded into the jar.

## Use

1. Proxy some traffic through Burp as usual.
2. Open the **CloudIntel** tab. Detected assets appear in the tree:
   `Provider → Service → Asset [band · score]`.
3. Select an asset to see its knowledge base and the exact request/response that evidenced
   each firing indicator. Matched text is highlighted; **Send to Repeater** forwards the
   triggering request so you can verify manually.
4. Findings also appear in Burp's **Target → Issues** tab, attached to the real host that
   evidenced them.
5. Right-click on any request/response → **CloudIntel** → send the fingerprint's canonical
   verification request to Repeater.

## Detection model

- Indicators are **weighted** and **sum**.
- A finding reports only when it has **≥ 2 distinct signals** AND its score **exceeds** the
  per-service `report_threshold`.
- Score maps to a band: **Medium / High / Very High**.
- **No hostname-only findings** — weights are tuned so no single indicator can clear its
  threshold on its own.
- Evidence accumulates across requests and is deduplicated (a signal seen 50× counts once).
- Issues (re)emit only on threshold-cross or band-upgrade.

## Extending: add a service

Fingerprints are YAML — no Java changes needed. Drop a file into
`src/main/resources/fingerprints/` (or, at runtime, `~/.cloudintel/fingerprints/`). See
[`docs/FINGERPRINT-GUIDE.md`](docs/FINGERPRINT-GUIDE.md) for the full schema, weight
philosophy, and worked examples.

## Local test harness

A tiny standalone server (`test-store/`) serves synthetic responses reproducing every
service's real signals. Proxy it through Burp with CloudIntel loaded to exercise all 40
fingerprints locally — no real cloud traffic needed.

```bash
python3 test-store/server.py    # http://127.0.0.1:8787
# Browse each /<service>/... path through your Burp proxy
```

Details: [`test-store/README.md`](test-store/README.md).

## Contributing

- [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) — how to propose changes.
- [`docs/FINGERPRINT-GUIDE.md`](docs/FINGERPRINT-GUIDE.md) — schema, weighting, single-signal
  guard, and pitfalls to avoid.
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — common issues at load or runtime.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes.

## Threat model & scope

- **Strictly passive.** CloudIntel does not send any HTTP traffic on its own.
- Response bodies are treated as untrusted (per PortSwigger BApp guidance): all
  fingerprint-derived text is HTML-escaped before being placed in issue detail and the UI.
- Detection runs on a bounded background worker; Burp's proxy/response threads and the UI
  event thread are never blocked by CloudIntel.



## Thank You
 
Feedback, ideas, and improvements are always welcome.

If you find this project useful, feel free to ⭐ the repository or contribute.
