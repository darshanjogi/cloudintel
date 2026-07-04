# Troubleshooting

## Loading

### Burp says "Extension failed to load"

Open Burp → **Extensions**, click CloudIntel, and open the **Errors** tab. Common causes:

- **Wrong Extension type.** Must be **Java**, not Python.
- **JDK too old at build time.** The jar targets Java 17 bytecode. Burp Community/Pro ship
  with JRE 21+; if you're loading into an older Burp with a JRE 11 runtime, rebuild against
  `<maven.compiler.release>11</maven.compiler.release>`.
- **JAR corrupted.** Confirm size (~450 KB) and that
  `unzip -l cloudintel-all.jar | grep CadExtension.class` shows the entry class.

### Extension loads but no CloudIntel tab appears

- Give Burp a moment — the tab is registered on the EDT after fingerprint load.
- Check the **Output** tab of the extension for
  `CloudIntel: loaded with N service fingerprints`.
- If N=0, the fingerprint registry failed to load. Check the **Errors** tab for the specific
  reason (see below).

### "no valid fingerprints loaded — detection disabled"

The registry couldn't load any signatures. The errors tab will show a specific line for the
first bad file. Usual suspects:

- A user-dir YAML in `~/.cloudintel/fingerprints/` failed validation. Move it aside and
  retry. Check the exact validation error, then fix per
  [`FINGERPRINT-GUIDE.md`](FINGERPRINT-GUIDE.md) §6.
- The bundled `fingerprints/index.txt` is missing from the jar. Rebuild.

## Runtime

### The tab is empty even though I'm proxying real cloud sites

- Confirm the traffic reaches CloudIntel — the extension observes responses, so the request
  must complete. Look for the site in Burp's **Proxy → HTTP history**.
- If Burp's scope filter is on and blocks the response tool source, CloudIntel still sees
  it, but you may miss it in your view. Turn scope filter off to compare.
- Some fingerprints require **≥ 2 distinct signals**. A single host observation intentionally
  produces no finding — hit the site more, or trigger an error (which brings XML/error-body
  signals).
- Turn on **Extensions → CloudIntel → Output** and watch for
  `CloudIntel: loaded with 40 service fingerprints`. If it says fewer, some fingerprints
  failed validation — inspect the errors tab.

### An issue shows in CloudIntel's tree but not in Target → Issues

The IssueReporter attaches the issue to the URL of the first captured request/response for
the finding. If for some reason that URL wasn't retained (very rare — happens if a proxy
mangling drops the initiating request), the issue gets a synthetic base URL. Fix path:

1. Note the finding's asset id from the CloudIntel tab.
2. Refresh the target host in Proxy history; the next hit will store a real RR.
3. On the next threshold-cross the issue re-anchors.

### False positive on a look-alike host

Contribute a `deny.hosts` glob for the offending pattern to the relevant fingerprint (see
[`FINGERPRINT-GUIDE.md`](FINGERPRINT-GUIDE.md)). If it's your local dev environment,
add the domain to `~/.cloudintel/fingerprints/` in a small override YAML rather than editing
the shipped signatures.

### Burp feels slow after loading CloudIntel

Detection runs on a bounded background worker, so it should not slow the proxy. If you see
lag:

- Check **Extensions → CloudIntel → Errors** for repeated exceptions (a bad user fingerprint
  can throw on every response — the worker logs and continues, but the noise hurts).
- The queue has a 4096-response cap and drops rather than blocks. If your traffic exceeds
  that in bursts, you'll see some observations skipped (not an error, just backpressure).

## Building

### `mvn package` fails to download plugins

Corporate proxy? Set Maven's `~/.m2/settings.xml`:

```xml
<settings>
  <proxies>
    <proxy>
      <id>corp</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>proxy.corp</host>
      <port>8080</port>
    </proxy>
  </proxies>
</settings>
```

### First `mvn package` is slow

Maven downloads the shade plugin, resources plugin, and their transitive deps on first run.
Subsequent builds are ~2 seconds.

## Reporting new issues

Open a GitHub issue with:

1. Burp Suite version + JRE version (**Help → Diagnostics**).
2. CloudIntel version (the jar's version in the file name).
3. The **Errors** tab contents.
4. A minimal reproduction — a captured request/response that should or shouldn't trigger.
