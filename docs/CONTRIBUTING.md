# Contributing to CloudIntel

Thanks for helping expand cloud coverage. Contributions fall into three tracks; pick the one
that matches your change.

## 1. New fingerprint / new service

The most common contribution. **No Java changes needed.** Follow
[`FINGERPRINT-GUIDE.md`](FINGERPRINT-GUIDE.md).

- Add the YAML entry to the relevant provider file, or create a new provider file (and add
  it to `src/main/resources/fingerprints/index.txt`).
- Provide **real** captured evidence (curled response headers, error XML) in the PR
  description — this is the review's main gate.
- Test against real traffic, then against the demo store's synthetic responses. Confirm the
  band you expect and that no unrelated host triggers.

**PR checklist:**

- [ ] Real, verifiable signals — every header/host/error is a signal that provider actually emits.
- [ ] `require_distinct_indicators >= 2` and no single indicator weight exceeds `report_threshold`.
- [ ] Anchored host regexes (escaped dots, provider-domain-terminated).
- [ ] Attack vectors are passive-tool-friendly manual actions.
- [ ] `mvn package` still succeeds and `RegistryLoader` doesn't log any validation errors.

## 2. Bug fix / small feature

Anything under `src/main/java/`. Keep changes focused:

- One responsibility per change; don't bundle unrelated cleanups.
- The engine (`com.cloudintel.cad.engine.*`) must stay **Burp-independent** — no imports of
  `burp.api.montoya.*` other than in `ObservationFactory` (the adapter). This is what keeps
  detection testable outside Burp.
- Detection work must stay off Burp's response and Swing EDT threads. If you add processing,
  do it inside the existing worker (`CadExtension.workerLoop`).

## 3. Larger refactor / new subsystem

Open an issue first with a short design (motivation + rough approach) so we can align before
you write code. Look at
[`docs/specs/2026-07-04-cloud-artifact-discovery-design.md`](specs/2026-07-04-cloud-artifact-discovery-design.md)
for the current architecture and the seams (`Burp ↔ Engine`, `Engine ↔ Knowledge`).

## Build & sanity check

```bash
mvn package
# -> target/cloudintel-<version>-all.jar
```

Load the JAR into Burp (Extensions → Add → Java) and run a quick smoke test against the
demo store:

```bash
python3 test-store/server.py
# Configure Burp to proxy 127.0.0.1:8787, then visit each service path.
# The CloudIntel tab should populate; Target > Issues should list the findings.
```

## Style

- Java 17 features are fine (records, `switch` expressions).
- Small, focused files; each file has one clear responsibility. Move code out of a file that
  grows beyond ~250 lines rather than adding to it.
- Comments explain **why**, not **what**. Well-named identifiers do the "what".
- No third-party libraries beyond SnakeYAML (already shaded). More dependencies = more risk
  and a larger jar.

## Reporting security issues

If you find a security issue in CloudIntel itself (e.g. an XSS in the issue detail HTML, or
a way to weaponise a malicious fingerprint from `~/.cloudintel/fingerprints/`), please do
not open a public issue. Contact the maintainer directly.
