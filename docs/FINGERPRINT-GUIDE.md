# Fingerprint authoring guide

CloudIntel's Java engine has **zero hardcoded cloud knowledge**. Every service, its signals,
its knowledge base, and its attack vectors live in YAML files under
`src/main/resources/fingerprints/`. Users can also drop fingerprints into
`~/.cloudintel/fingerprints/` at runtime — the loader merges bundled + user files.

Adding a new service is: **write one YAML entry, rebuild, done.**

---

## 1. Where fingerprints live

- **Bundled:** `src/main/resources/fingerprints/*.yaml` — one file per **provider**
  (e.g. `aws.yaml`, `azure.yaml`, `cloudflare.yaml`).
- **Index:** `src/main/resources/fingerprints/index.txt` — a plain list of YAML file names
  that ship inside the jar. **New files must be added here** (JAR resource enumeration is
  not reliable across all JVMs, so we list them explicitly).
- **User overrides:** `~/.cloudintel/fingerprints/*.yaml` — anything dropped here is
  automatically merged at load. Great for private/company signatures without rebuilding.

## 2. File shape (per provider)

```yaml
provider: AWS                # top-level; used as the dashboard grouping
services:
  - id: aws-s3               # kebab-case, globally unique
    name: 'Amazon S3'        # display name
    ...
  - id: aws-cloudfront
    ...
```

## 3. Per-service schema

```yaml
- id: aws-s3
  name: 'Amazon S3'
  category: object-storage          # see allowed set below
  severity: information             # information | low | medium | high
  report_threshold: 60              # score must EXCEED this to report
  bands:                            # ascending; medium must be >= report_threshold
    medium: 60
    high: 90
    very_high: 120
  require_distinct_indicators: 2    # >= 2 (structural no-single-signal rule)

  asset:                            # how to identify the concrete asset
    extractors:
      - from: host                  # host | url | body | header:<name>
        regex: '(?i)^([a-z0-9.\-]+)\.s3[.\-]([a-z0-9\-]+\.)?amazonaws\.com$'
        asset_id: '$1'
        label: 'S3 bucket $1'
    host_level_fallback: true       # header-only evidence attaches to the host

  indicators:                       # weighted, independent signals; they sum
    - { id: s3-host,       source: host,        match: regex,   pattern: '\.s3[.\-]([a-z0-9\-]+\.)?amazonaws\.com$', weight: 40 }
    - { id: s3-req-id,     source: header-name, match: iequals, pattern: 'x-amz-request-id', weight: 20 }
    - { id: s3-id-2,       source: header-name, match: iequals, pattern: 'x-amz-id-2',       weight: 25 }
    - { id: s3-server,     source: header,      match: regex,   pattern: '(?i)^server:\s*amazons3\s*$', weight: 30 }
    - { id: s3-error-xml,  source: xml,         match: regex,   pattern: '<Code>(NoSuchBucket|PermanentRedirect|AccessDenied)</Code>', weight: 45 }

  deny:
    hosts: []                       # optional: globs never fingerprinted, e.g. '*.internal'

  knowledge_base:                   # shown verbatim in the finding detail
    description: 'AWS S3 object storage bucket referenced by the target.'
    why_detected: 'Auto-filled from the specific indicators that fired.'  # keep this literal
    attack_vectors:
      - { name: 'Public bucket / listing', check: 'GET https://{assetId}.s3.amazonaws.com/?list-type=2' }
      - { name: 'Backup files',            wordlist: 's3-backup-names.txt' }
    verification_steps:
      - 'Confirm bucket exists (200/403 vs 404 NoSuchBucket).'
    repeater_template:              # prefilled request the tester fires
      method: GET
      url: 'https://{assetId}.s3.amazonaws.com/?list-type=2'
      headers: []
    wordlists: ['s3-common-prefixes.txt']
    references:
      - 'https://docs.aws.amazon.com/AmazonS3/...'
```

### Allowed values

| Field | Allowed |
|---|---|
| `category` | `object-storage`, `cdn`, `compute`, `serverless`, `api`, `auth`, `database`, `messaging`, `dns`, `platform`, `secrets`, `analytics` |
| `severity` | `information`, `low`, `medium`, `high` |
| `indicator.source` | `host`, `url`, `header`, `header-name`, `body`, `xml`, `mime`, `cookie`, `redirect` |
| `indicator.match` | `regex` (default), `contains`, `equals`, `iequals` |
| `extractor.from` | `host`, `url`, `body`, `header:<name>` |

### The `{assetId}` placeholder

`{assetId}` in `attack_vectors[*].check`, `verification_steps`, and `repeater_template.url`
is interpolated with the extracted asset id at display/send time.

## 4. Weight philosophy

CloudIntel's core value is **actionable findings with no false positives**. Weights matter.

- **Host suffix alone:** typically **40**. Broad, cheap, but common in typos/typosquats.
- **Distinctive response header presence** (e.g. `x-amz-cf-id`): **20–30**. High evidence
  value; specific vendors mostly.
- **Server banner / product string** (e.g. `Server: AmazonS3`): **30–35**.
- **Provider-specific error body / XML namespace** (e.g. `NoSuchBucket`): **40–60**. Very
  hard to fake accidentally.
- **Stickiness / provider cookies** (e.g. `AWSALB=`): **30–40**.
- **Path shape / URL structure** (e.g. `/[account]/[queue]`): **20–30** — often ambiguous.

## 5. The single-signal guard

**Rule:** no single indicator's weight may exceed `report_threshold`.

The validator enforces this at load time. It exists because a lone hostname match is not
enough to open an issue: anyone can put `s3.amazonaws.com` in a header for spoofing. Multiple
independent signals are always required.

If a strong signal exceeds threshold on its own, either **raise `report_threshold`** or
**split the signal** into a broader-but-lower-weight indicator plus a narrower confirmatory
one.

## 6. Runtime validation (the loader's checklist)

The `RegistryLoader` will drop a fingerprint at load if any of these fail — details are
logged to Burp's extension error stream:

1. `provider` present and non-blank.
2. Each service has: `id`, `name`, valid `category`, `severity`, `report_threshold`, `bands`,
   `indicators` (≥ 2), `knowledge_base`.
3. `require_distinct_indicators >= 2`.
4. `bands.medium <= bands.high <= bands.very_high`.
5. `bands.medium >= report_threshold` (i.e. the reportable range starts at the medium band).
6. Every indicator has: `id`, valid `source`, valid `match`, non-blank `pattern`.
7. All regex patterns compile as Java regex.
8. **Single-signal guard**: `max(indicator.weight) <= report_threshold`.
9. No duplicate service `id` across the entire registry.

A single bad fingerprint never breaks the load of the rest — it's skipped with a specific
error message, and the other services still load.

## 7. Do & don't

**Do:**

- Base every signal on **real** headers, hostnames, or error bodies emitted by the provider.
  When in doubt, capture an actual response.
- Escape hostname dots in regexes (`\.s3\.amazonaws\.com`).
- Anchor host regexes to the provider domain (`$` at the end) to reject look-alikes.
- Use `(?i)` for case-insensitive host matching.
- Prefer `header-name` over `header` for presence-only checks — it's cheaper.
- Keep the `knowledge_base.description` short and factual.

**Don't:**

- Fabricate header names or hostnames you haven't verified.
- Use nested quantifiers (e.g. `(a+)+`) — regex denial-of-service risk.
- Rely on a single indicator, even a very specific one — pair it with something.
- Put payloads or destructive requests in `attack_vectors`. This is a **passive** tool.

## 8. Adding a service — step by step

1. Pick or create the provider file (e.g. `src/main/resources/fingerprints/newcloud.yaml`).
   If new, also add its filename to `index.txt`.
2. Write the service entry using the schema in §3. Start with the most specific indicators
   you can find (error bodies, distinctive headers).
3. Test locally against real traffic (or against the demo store in `test-store/`).
4. Run `mvn package`, load the new jar in Burp, confirm your fingerprint fires with the
   right band and produces no false positives on unrelated hosts.
5. If contributing back, open a PR — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 9. Auto-composed `why_detected`

The literal string `'Auto-filled from the specific indicators that fired.'` in the KB is
replaced at runtime with the actual firing evidence, e.g.:

```
s3-host 'company-assets.s3.amazonaws.com' (+40),
s3-req-id-header 'x-amz-request-id' (+20),
s3-id-2-header 'x-amz-id-2' (+25),
s3-server-header 'Server: AmazonS3' (+30)
```

You don't need to write this by hand — leave the literal string as a marker.
