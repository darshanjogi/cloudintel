# Cloud Artifact Discovery (CAD) — Design

**Date:** 2026-07-04
**Status:** Approved design (pre-implementation)
**Type:** Burp Suite extension (BApp)

## Objective

A Burp Suite extension that **passively** inspects proxy HTTP traffic and detects
evidence of the cloud services a target application uses. The value is not "detect
cloud" (many extensions fingerprint technologies) — it is surfacing **actionable
cloud attack surface**: each detected concrete asset (a specific bucket,
distribution, function, endpoint, or host) is reported with weighted-evidence
confidence and a knowledge base of realistic, human-driven attack vectors and
verification steps.

CAD is **strictly passive**. It never originates traffic. Verification is guided:
it pre-fills Burp Repeater and provides checklists, but the tester fires every
request.

## Core Workflow

```
Burp passive hook (HttpResponseReceived)
        │  wrap into HttpObservation
        ▼
ArtifactExtractor        (one normalized bag of candidate strings)
        ▼
FingerprintMatcher       (run each fingerprint's indicators vs. the bag)
        ▼
EvidenceCorrelator       (accumulate weighted evidence per asset, stateful)
        ▼
ConfidenceScorer         (score vs. per-service threshold → named band)
        ▼
FindingStore             (dedup + upsert; emit AuditIssue on threshold-cross / band-upgrade)
        ▼
Burp UI (CAD dashboard) + native Issues tab
```

## Locked Decisions

1. **Language & API:** Java 17 + Montoya API (the current, supported Burp
   extension API; path to the BApp Store). Build with Gradle + the shadow plugin
   to produce a single fat JAR loadable via "Extensions → Add".
2. **Registry-first (data-driven):** The Java engine has **zero** hardcoded cloud
   knowledge. Every provider, service, indicator weight, and attack-KB entry lives
   in bundled YAML fingerprint files. Adding a service = adding data, never code.
3. **Finding identity = (provider + service + concrete asset).** Each distinct
   asset (e.g. S3 bucket `company-assets`, a CloudFront distribution, an API
   Gateway id) is its own finding. Header-only evidence (no extractable asset)
   attaches to a host-level asset so nothing is lost — it becomes a lower-confidence
   "service present" finding. Dashboard counts are **distinct assets**.
4. **Confidence = raw weighted score + named bands.** Indicators sum; the total is
   compared to a per-service `report_threshold`. Because the report threshold gates
   at the `medium` cutoff, every *reported* finding is at least **Medium**, and maps
   to **Medium / High / Very High** by the `bands` cutoffs. Accumulating evidence
   that has not yet cleared the threshold is held sub-threshold (conceptually "Low")
   and is *not* reported until it crosses. We store the raw score and the threshold
   it cleared. No fabricated percentages.
5. **Strictly passive; human verifies.** No traffic originates from CAD. Attack
   vectors and a pre-filled Repeater request are provided; the tester fires them.
   An opt-in one-click active confirmation probe is noted as a possible future
   extension, explicitly out of scope for v1.

## Scope Amendments (from review)

- **No automated tests.** No JUnit suite, no test corpora, no `src/test/`.
  Regex-safety and schema validation still happen — but **at runtime in
  `RegistryLoader`** (reject malformed/uncompilable fingerprints on load and log
  which file/service failed), not as build-time tests. A single documented manual
  smoke test is included as guidance (below).
- **Single self-contained tree.** All project files — build, source, resources,
  docs — live under `cloudintel/`.

## Architecture & Module Layout

Two clean seams make the engine understandable, isolated, and independent of Burp:

- **Burp ↔ Engine seam:** the engine consumes a plain `HttpObservation`
  (method, url, host, request/response headers, body, mime, source tool) and never
  touches Montoya types directly. The full pipeline can run on synthetic traffic.
- **Engine ↔ Knowledge seam:** the engine holds no cloud facts. All
  provider/service/weight/attack knowledge is bundled YAML data. A new service
  never touches Java.

```
cloudintel/
├── build.gradle.kts
├── settings.gradle.kts
├── src/main/
│   ├── java/com/cloudintel/cad/
│   │   ├── CadExtension.java           # entry point: registers handlers + UI
│   │   ├── engine/
│   │   │   ├── HttpObservation.java    # normalized view of one req/resp pair
│   │   │   ├── ArtifactExtractor.java  # pulls candidate strings from all sources
│   │   │   ├── FingerprintMatcher.java # runs one fingerprint's indicators
│   │   │   ├── EvidenceCorrelator.java # accumulates evidence per asset (stateful)
│   │   │   ├── ConfidenceScorer.java   # score → band vs. threshold
│   │   │   └── AssetKey.java           # (provider, service, assetId) identity
│   │   ├── registry/
│   │   │   ├── Fingerprint.java        # POJO mirroring the YAML schema
│   │   │   ├── RegistryLoader.java     # bundled + user-dir YAML → validated objects
│   │   │   └── model/                  # Indicator, Extractor, AttackVector, KnowledgeBase POJOs
│   │   ├── report/
│   │   │   ├── FindingStore.java       # dedup + live model behind the UI
│   │   │   ├── IssueReporter.java      # emits Montoya AuditIssue
│   │   │   └── AssetExporter.java      # JSON/CSV export
│   │   └── ui/
│   │       ├── DashboardPanel.java     # provider→service→asset tree + counts
│   │       ├── FindingDetailPanel.java # KB view for the selected finding
│   │       └── ContextMenu.java        # Send to Repeater / Copy / Export / Checklist
│   └── resources/fingerprints/*.yaml   # bundled signatures, one file per provider
└── docs/specs/2026-07-04-cloud-artifact-discovery-design.md
```

**Threading:** passive handling runs on Burp's scan threads; `EvidenceCorrelator`
and `FindingStore` are concurrency-safe (concurrent maps / single lock). UI updates
are marshalled to the Swing EDT.

## Fingerprint Registry Schema

One YAML file per provider; a file has a `provider` and a `services` list. Each
service, illustrated with S3:

```yaml
provider: AWS
services:
  - id: aws-s3
    name: Amazon S3
    category: object-storage           # object-storage|cdn|compute|serverless|api|auth|database|messaging|dns|platform|secrets|analytics
    severity: information              # default issue severity (passive tool)
    report_threshold: 70               # raw score must EXCEED this to report
    bands: { medium: 70, high: 110, very_high: 150 }
    require_distinct_indicators: 2     # ≥N different indicator ids must fire (structural no-single-signal rule)

    asset:                             # defines the concrete asset identity (the finding)
      extractors:                      # first match wins
        - from: host                   # host | url | header:<name> | body
          regex: '([a-z0-9.\-]+)\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com'
          asset_id: '$1'
          label: 'S3 bucket: $1'
        - from: url
          regex: 's3[.-]([a-z0-9-]+\.)?amazonaws\.com/([a-z0-9.\-]+)'
          asset_id: '$2'
      host_level_fallback: true        # header-only evidence attaches to the host as a low-conf asset

    indicators:                        # weighted, independent signals; they SUM
      - { id: host-s3,           source: host,        match: regex,    pattern: '\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com', weight: 40 }
      - { id: hdr-amz-request-id, source: header-name, match: iequals, pattern: 'x-amz-request-id',                       weight: 30 }
      - { id: hdr-amz-id-2,       source: header-name, match: iequals, pattern: 'x-amz-id-2',                             weight: 20 }
      - { id: body-nosuchbucket,  source: body,        match: contains, pattern: 'NoSuchBucket',                          weight: 60 }
      - { id: xml-s3-ns,          source: xml,         match: contains, pattern: 'http://s3.amazonaws.com/doc',           weight: 40 }

    deny:                              # optional false-positive guards
      hosts: ['*.internal.example']

    knowledge_base:
      description: 'AWS S3 object storage bucket referenced by the target.'
      why_detected: 'Auto-filled from the specific indicators that fired.'
      attack_vectors:
        - { name: 'Public bucket / listing', check: 'GET https://{assetId}.s3.amazonaws.com/?list-type=2' }
        - { name: 'ACL misconfiguration',    check: 'GET https://{assetId}.s3.amazonaws.com/?acl' }
        - { name: 'Versioning enabled',      check: 'GET https://{assetId}.s3.amazonaws.com/?versions' }
        - { name: 'CORS policy',             check: 'GET https://{assetId}.s3.amazonaws.com/?cors' }
        - { name: 'Backup / old objects',    wordlist: 's3-backup-names.txt' }
      verification_steps:
        - 'Confirm bucket exists (200/403 vs 404 NoSuchBucket).'
        - 'Attempt anonymous list-objects-v2.'
      repeater_template:
        method: GET
        url: 'https://{assetId}.s3.amazonaws.com/?list-type=2'
        headers: []
      wordlists: ['s3-common-prefixes.txt', 's3-backup-names.txt']
      references:
        - 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html'
```

**Schema semantics:**

- **`source` types** cover every extraction surface: `host`, `url`, `header`
  (value), `header-name` (presence), `body`, `xml`, `mime`, `cookie`, `redirect`
  (Location). `ArtifactExtractor` produces one normalized bag; indicators match the
  relevant slice.
- **`match` modes:** `regex` | `contains` | `equals` | `iequals` (default `regex`).
- **`require_distinct_indicators` (≥2)** structurally enforces "never on a single
  signal." Weights are chosen so no single broad indicator alone can exceed
  `report_threshold` — no hostname-only findings.
- **`{assetId}` interpolation** flows the extracted identity into attack checks, the
  Repeater template, and the finding label — this is what makes findings actionable
  against a real target.
- **Runtime validation:** `RegistryLoader` rejects malformed fingerprints (bad/
  uncompilable regex, missing keys, non-ascending bands, `require_distinct_indicators
  < 2`) and logs which file/service failed, so one bad community signature can't
  silently break the engine or crash the load of the rest.
- **User-extensible:** bundled files load from resources; a user directory
  (e.g. `~/.cloudintel/fingerprints/`) is also scanned and merged, so anyone drops
  in a YAML file without rebuilding.

## Detection Pipeline in Motion (S3 example)

```
ArtifactExtractor → bag { hosts, urls, headerNames, headerValues, bodyText, xmlText, mime, cookies, redirectTargets }
For each Fingerprint:
   FingerprintMatcher → Hits {indicatorId, weight, matchedText}
   asset extractors   → AssetKey (bucket name, or host-level fallback)
EvidenceCorrelator (keyed by AssetKey):
   merge Hits, dedup by (indicatorId + matchedText)
   running score = Σ distinct indicator weights
ConfidenceScorer:
   if distinctIndicatorCount ≥ require_distinct_indicators AND score > report_threshold → band
FindingStore:
   upsert; emit AuditIssue only on threshold-cross OR band-upgrade
```

Key behaviors:

- **Accumulation across requests.** host + `x-amz-request-id` = 70 (distinct ≥2 ✓,
  but 70 does not *exceed* threshold 70 → not yet reported). A later `NoSuchBucket`
  (+60 = 130) crosses into **High** and the issue is then emitted. Evidence builds
  over a session.
- **Dedup.** Seeing `x-amz-request-id` on 50 responses counts once. Score reflects
  distinct signals, not traffic volume.
- **No double-emit.** Issues (re)emit only on threshold-cross or band-upgrade — the
  Issues tab is not spammed.
- **URL normalization.** Lowercase host, strip default ports, drop query for asset
  identity (signed-URL/token params captured separately as artifacts), so
  `bucket.s3.amazonaws.com` and `bucket.s3.us-east-1.amazonaws.com` resolve to the
  same bucket asset.
- **`why_detected` is auto-composed** from actual hits (e.g. "Matched host
  `.s3.amazonaws.com` (+40), header `x-amz-request-id` (+30), body `NoSuchBucket`
  (+60)"), replacing the KB's literal placeholder.

## Burp UI & Context Actions

A single custom tab **"Cloud Artifact Discovery"**, plus native Issues integration.

**Dashboard (left):** provider → service → asset tree with live distinct-asset
counts; each asset shows its band and raw score.

```
Cloud Artifact Discovery
├─ AWS
│   ├─ S3 (4)
│   │   ├─ company-assets   [Very High · 150]
│   │   └─ static-uploads   [High · 110]
│   └─ CloudFront (2)
├─ Azure
│   └─ Blob Storage (1)
└─ GCP
    └─ Firebase (3)
```

**Finding detail (right):** renders the KB for the selected asset — name,
band + raw score (+ threshold cleared), why-detected (actual firing evidence with
weights), related URLs seen, attack-vector checklist, manual verification steps,
wordlists, references, suggested severity.

**Context menu** (from the CAD tree and from Proxy/Target/Repeater via
`registerContextMenuItemsProvider`):

- **Send to Repeater** — builds a request from the fingerprint's `repeater_template`
  with `{assetId}` interpolated and hands it to `montoya.repeater().sendToRepeater(...)`.
  (Passive: it populates Repeater; the tester fires it.)
- **Copy endpoint** — asset URL to clipboard.
- **Open attack checklist** — focuses the detail pane's checklist for that asset.
- **Export assets** — `AssetExporter` writes JSON + CSV of all discovered assets
  (host, service, assetId, band, score, evidence, related URLs).

**Native Issues tab:** each reported asset also emits a Montoya `AuditIssue`
(name `Cloud artifact: <service> — <assetId>`, chosen severity, confidence mapped
from band, detail = evidence + attack vectors + verification). Findings live both
in CAD's dashboard and Burp's standard Issues view.

## False-Positive Reduction (summary)

- Weighted scoring with per-service thresholds.
- `require_distinct_indicators ≥ 2` — multiple independent signals required.
- No hostname-only findings (weights tuned so a single broad indicator can't clear
  threshold).
- URL normalization + dedup (distinct signals, not traffic volume).
- Per-service `deny` host globs.
- Anchored host regexes (provider domain) to reject look-alikes such as
  `s3.amazonaws.com.evil.com`.

## Supported Providers & Services (v1)

- **AWS:** S3, CloudFront, API Gateway, Lambda, Cognito, Elastic Beanstalk, ELB,
  EC2, ECR, SNS, SQS, Route53
- **Azure:** Blob Storage, Azure Functions, Azure CDN, Cosmos DB, Storage Queue,
  Azure Files, Key Vault
- **Google Cloud:** Cloud Storage, Cloud Functions, Firebase, App Engine, Cloud Run,
  BigQuery, Pub/Sub
- **Other:** DigitalOcean (Spaces, App Platform), Cloudflare, Fastly, Akamai,
  Vercel, Netlify, GitHub Pages, Heroku, Oracle Cloud (Object Storage), Alibaba OSS,
  Wasabi, Backblaze B2, BunnyCDN

Each service ships a full knowledge base: description, why-detected, attack vectors,
manual verification steps, Repeater template, wordlists, references, suggested
severity — all authored against real, verified cloud signals (adversarially checked
for fabricated headers/hosts, regex safety, and the single-signal guard).

**Authoring status (2026-07-04):** all **40 services** across **16 provider files**
are authored, adversarially verified, and validated on disk under
`src/main/resources/fingerprints/`. Every fingerprint passes a schema/consistency
sweep: required keys present, category from the allowed set, ascending bands,
`report_threshold ≤ medium` cutoff, ≥2 indicators, the single-signal guard (no
indicator weight exceeds its service threshold), and all regex/patterns compile.
File → service counts: `aws.yaml` (12), `azure.yaml` (7), `gcp.yaml` (7),
`digitalocean.yaml` (2), and 12 single-service files (`cloudflare`, `fastly`,
`akamai`, `vercel`, `netlify`, `github-pages`, `heroku`, `oracle-cloud`,
`alibaba-oss`, `wasabi`, `backblaze-b2`, `bunnycdn`).

## Deliverables & Packaging

The build produces two artifacts (one Gradle step + one packaging task), both under
`cloudintel/build/`:

- **`cloudintel-cad-all.jar`** — the loadable Burp extension (fat JAR via the shadow
  plugin). All fingerprint YAMLs are bundled inside it as resources, so it is fully
  self-contained: no external files needed to run. **This is what you load and test
  in Burp.**
- **`cloudintel-cad-src.zip`** — the entire project tree (build files, `src/`,
  `resources/fingerprints/`, `docs/`) for sending/sharing the source. A convenience
  `packageZip` Gradle task (or a documented `zip` command) produces it.

**Important — how Burp loads it:** Burp does *not* load a zip. In
**Extensions → Add**, set **Extension type: Java** and select the
`cloudintel-cad-all.jar`. The zip is only for transferring the project to another
machine/person, where they rebuild the JAR.

Build commands (documented in the project README):

```
cd cloudintel
mvn package             # -> target/cloudintel-cad-<version>-all.jar   (load THIS in Burp)
                        #    also copied to dist/cloudintel-cad-all.jar
```

> **Build tooling note:** the implementation uses **Maven + the maven-shade-plugin** (not
> Gradle as originally sketched), because Maven was the JVM build tool available in the build
> environment. The shade plugin produces the self-contained fat JAR and relocates SnakeYAML to
> `com.cloudintel.cad.shaded.snakeyaml`. The source zip for sharing is produced with a plain
> `zip -r cloudintel.zip cloudintel`.

## Manual Smoke Test (documented guidance, not automated)

1. `./gradlew shadowJar` → load `build/libs/cloudintel-cad-all.jar` via
   Burp → Extensions → Add (Extension type: **Java**).
2. Proxy a few known cloud-backed sites through Burp.
3. Confirm the CAD tab's tree populates with provider → service → asset nodes and
   that a corresponding entry appears in Burp's native Issues tab.

## Out of Scope (v1)

- Automated test suite (removed by decision).
- Any active/originated traffic, including opt-in confirmation probes (noted as a
  possible future extension only).
- Background asset enumeration / active scanning.
