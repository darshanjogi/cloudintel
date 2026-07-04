#!/usr/bin/env python3
"""
Drive the CloudIntel demo store through Burp's proxy so all fingerprints trigger.

For each scenario the demo store implements, we send at least two requests to that host
(satisfying `require_distinct_indicators >= 2`) plus a request that elicits the error-body
signal (for services that use one). The requests go to the demo server on 127.0.0.1:8787
but carry a real cloud `Host:` header — so CloudIntel observes real hostnames.

Usage:
    # 1. Start Burp with CloudIntel loaded. Note the proxy port (default 8080).
    # 2. Start the demo server:
    python3 server.py
    # 3. Drive it:
    python3 drive.py --burp-proxy 127.0.0.1:8080
"""

import argparse
import http.client
import ssl
import sys
import urllib.parse

# (fingerprint id, host header the extension should see, path to request)
SCENARIOS: list[tuple[str, str, str]] = [
    # AWS
    ("aws-s3",              "company-assets.s3.amazonaws.com",                      "/?list-type=2"),
    ("aws-cloudfront",      "d123abcdefghij.cloudfront.net",                        "/"),
    ("aws-api-gateway",     "abc123.execute-api.us-east-1.amazonaws.com",           "/prod/ping"),
    ("aws-lambda-url",      "abcde.lambda-url.us-east-1.on.aws",                    "/"),
    ("aws-cognito",         "cognito-idp.us-east-1.amazonaws.com",                  "/"),
    ("aws-elastic-beanstalk", "demo.us-east-1.elasticbeanstalk.com",                "/"),
    ("aws-elb",             "app-lb-1234.us-east-1.elb.amazonaws.com",              "/"),
    ("aws-ec2",             "ec2-3-92-101-33.compute-1.amazonaws.com",              "/"),
    ("aws-ecr",             "123456789012.dkr.ecr.us-east-1.amazonaws.com",         "/v2/"),
    ("aws-sns",             "sns.us-east-1.amazonaws.com",                          "/"),
    ("aws-sqs",             "sqs.us-east-1.amazonaws.com",                          "/123456789012/demo"),
    ("aws-route53",         "route53.amazonaws.com",                                "/"),
    # Azure
    ("azure-blob-storage",  "company.blob.core.windows.net",                        "/pics/missing.jpg"),
    ("azure-functions",     "demoapp.azurewebsites.net",                            "/"),
    ("azure-cdn",           "cdn.azureedge.net",                                    "/"),
    ("azure-cosmos-db",     "company.documents.azure.com",                          "/"),
    ("azure-storage-queue", "company.queue.core.windows.net",                       "/"),
    ("azure-files",         "company.file.core.windows.net",                        "/"),
    ("azure-key-vault",     "secret.vault.azure.net",                               "/secrets/foo"),
    # GCP
    ("gcp-cloud-storage",   "storage.googleapis.com",                               "/demo-bucket/x"),
    ("gcp-cloud-functions", "us-central1-my-project.cloudfunctions.net",            "/hello"),
    ("gcp-firebase",        "my-app.firebaseio.com",                                "/.json"),
    ("gcp-firebase-store",  "firebasestorage.googleapis.com",                       "/v0/b/my-app.appspot.com/o"),
    ("gcp-app-engine",      "my-app.appspot.com",                                   "/"),
    ("gcp-cloud-run",       "my-service-abcd-uc.a.run.app",                         "/"),
    ("gcp-bigquery",        "bigquery.googleapis.com",                              "/bigquery/v2/projects/p/queries"),
    ("gcp-pubsub",          "pubsub.googleapis.com",                                "/v1/projects/p/topics"),
    # DigitalOcean
    ("digitalocean-spaces", "company.nyc3.digitaloceanspaces.com",                  "/"),
    ("digitalocean-app",    "cloud-artifact-lab.ondigitalocean.app",                "/"),
    # CDNs
    ("fastly-cdn",          "cdn.example.fastly.net",                               "/"),
    ("akamai-cdn",          "cdn.example.akamaized.net",                            "/"),
    ("bunnycdn-cdn",        "demo.b-cdn.net",                                       "/file/demo/logo.png"),
    # Platforms
    ("vercel-deployment",   "cloud-artifact-lab.vercel.app",                        "/"),
    ("netlify-deploy",      "cloud-artifact-netlify.netlify.app",                   "/"),
    ("github-pages",        "cloud-artifact-o45xeln93.github.io",                   "/"),
    ("heroku-app",          "cloud-artifact-h1234.herokuapp.com",                   "/"),
    # Object storage
    ("oci-object-storage",  "objectstorage.us-ashburn-1.oraclecloud.com",           "/n/tenant/b/bucket/o/x"),
    ("alibaba-oss",         "company.oss-cn-hangzhou.aliyuncs.com",                 "/"),
    ("wasabi",              "backup-prod.s3.us-east-1.wasabisys.com",               "/"),
    ("backblaze-b2",        "f001.backblazeb2.com",                                 "/file/demo/logo.png"),
]


def make_conn(store_host: str, store_port: int, burp_host: str | None, burp_port: int | None):
    if burp_host and burp_port:
        # Route through Burp's HTTP proxy. Even for http://, Burp handles the request
        # and forwards to the target — we just talk to Burp.
        conn = http.client.HTTPConnection(burp_host, burp_port, timeout=10)
        conn.set_tunnel(store_host, store_port) if False else None
        return conn, f"http://{store_host}:{store_port}"
    else:
        return http.client.HTTPConnection(store_host, store_port, timeout=10), ""


def send_one(store_host: str, store_port: int, burp_host: str | None, burp_port: int | None,
             host_header: str, path: str):
    if burp_host and burp_port:
        # Absolute-URI form so Burp forwards correctly.
        conn = http.client.HTTPConnection(burp_host, burp_port, timeout=10)
        url = f"http://{store_host}:{store_port}{path}"
        try:
            conn.request("GET", url, headers={"Host": host_header})
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()
    else:
        conn = http.client.HTTPConnection(store_host, store_port, timeout=10)
        try:
            conn.request("GET", path, headers={"Host": host_header})
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="127.0.0.1:8787", help="Demo store host:port")
    ap.add_argument("--burp-proxy", default="127.0.0.1:8080",
                    help="Burp proxy host:port (send '' to skip Burp and hit the store directly)")
    args = ap.parse_args()

    store_host, store_port = args.store.split(":")
    store_port = int(store_port)
    burp_host, burp_port = (None, None)
    if args.burp_proxy:
        bh, bp = args.burp_proxy.split(":")
        burp_host, burp_port = bh, int(bp)
        print(f"Sending through Burp proxy at {burp_host}:{burp_port}")
    else:
        print("Sending direct (no Burp proxy)")

    passes = 0
    for name, host_header, path in SCENARIOS:
        # Send twice so require_distinct_indicators (>= 2) is satisfied for indicator IDs
        # that only fire on repeat, and once for the error path.
        for _ in range(2):
            try:
                s = send_one(store_host, store_port, burp_host, burp_port, host_header, path)
                sys.stdout.write(f"  [{s}] {name:24s} {host_header}\n")
            except Exception as e:
                sys.stdout.write(f"  [ERR] {name:24s} {host_header}: {e}\n")
        passes += 1
    print(f"\nDrove {passes} scenarios. Open Burp's CloudIntel tab and Target > Issues.")


if __name__ == "__main__":
    main()
