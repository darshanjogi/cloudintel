# Changelog

All notable changes to CloudIntel are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Semantic versioning.

## [Unreleased]

## [1.0.0] — 2026-07-04

Initial release. Passive cloud attack-surface discovery for Burp Suite via the Montoya API.

### Added

- Weighted-evidence detection engine with per-service confidence bands
  (Medium / High / Very High) and structural single-signal guard.
- Registry-first architecture — Java engine has zero hardcoded cloud knowledge; all
  fingerprints ship as bundled YAML. User-drop directory
  `~/.cloudintel/fingerprints/` is auto-merged.
- **40 service fingerprints across 16 providers:** AWS (12: S3, CloudFront, API Gateway,
  Lambda URL, Cognito, Elastic Beanstalk, ELB, EC2, ECR, SNS, SQS, Route53),
  Azure (7), Google Cloud (7), DigitalOcean (2), Cloudflare, Fastly, Akamai, BunnyCDN,
  Vercel, Netlify, GitHub Pages, Heroku, Oracle OCI, Alibaba OSS, Wasabi, Backblaze B2.
- **Evidence viewer** in the CloudIntel tab: for each firing indicator, view the exact
  request/response that triggered it, with the matched text highlighted, and forward it to
  Repeater with one click.
- **Target → Issues integration:** every reported asset also appears as a native Burp
  `AuditIssue`, anchored to the real host that evidenced it.
- **Context menu** actions on any request/response: Send fingerprint's canonical
  verification request to Repeater, Copy endpoint.
- **JSON + CSV asset export** from the dashboard.
- **BApp store compliance:** clean unloading (`ExtensionUnloadingHandler` deregisters all
  handlers and stops the worker), bounded background worker to keep detection off Burp's
  response and Swing EDT threads, wrapped exception handling with logging to the extension
  error stream, dialogs parented to Burp's suite frame.

### Security posture

- Strictly passive: CloudIntel never originates HTTP traffic.
- All fingerprint-derived text is HTML-escaped before display or embedding in issue detail.
- Response body scanning is bounded at 512 KB per response to bound worst-case latency and
  memory.
- Retained request/response sources per finding are capped at 8 to bound memory over long
  sessions.
