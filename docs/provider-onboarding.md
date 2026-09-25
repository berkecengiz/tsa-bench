# Provider onboarding

How to establish the trust and authentication configuration for a timestamp
service **before** any load is applied.

Do this for every new provider. It costs one unit of quota and it is the
difference between a clean run and 48,600 `untrusted_certificate` rows.

Everything below is generalised from three qualified TSAs onboarded in a real
engagement. They appear here as **Provider A**, **B** and **C**; their
identities, endpoints and measured figures are not published. What is published
is the procedure and the failure modes, which is the part that transfers.

| | Transport | Auth | Trust anchor |
|---|---|---|---|
| **Provider A** | https, private PKI | digest, session-bound nonce | own root, not public |
| **Provider B** | https, public CA | basic | own root, not public |
| **Provider C** | **plaintext http only** | basic | own root, not public |

Two things were true of all three and are probably true of yours:

- **The TSA root is not in the public store.** A national qualified hierarchy
  almost never is. `tls.tsa_ca_file` must be set.
- **The transport CA and the TSA CA are different questions.** Provider B's TLS
  chained to a public root while its tokens did not. Do not assume one from the
  other; confirm both from a real token.

---

## 1. Settle the endpoint

Providers hand out an `http://` URL on port 80 as a matter of habit. **Check
443 before accepting it.** Two of the three answered on 443 without saying so
on their sheet; `validate` refuses a plaintext endpoint for a non-loopback host
precisely so this gets checked rather than assumed.

Probe the path too. Provider A answers every path with the same catch-all
handler, so a wrong path is invisible and will be diagnosed as something else
later. Provider C returns 404 for anything but the root, which is the more
helpful behaviour.

A `GET` to the endpoint usually returns a usage banner and consumes no quota.

### When there is genuinely no TLS

Provider C refused port 443 outright — not filtered, actively refused. There
was no https to use. That case needs `provider.allow_plaintext: true`, which is
deliberately noisy: it warns on every run and is written into the report's
limitations, because credentials cross the wire in the clear and a timestamp
whose response can be rewritten in transit proves nothing an attacker on the
path could not forge.

Set it only while the path is private, and ask the provider for an https
endpoint regardless.

---

## 2. Take one timestamp by hand

```sh
printf 'user = "%s:%s"\n' 'ACCOUNT' 'PASSWORD' > ~/.tsa-curl && chmod 600 ~/.tsa-curl

openssl ts -query -data subject.md -sha256 -cert -out req.tsq
curl -sS -f -K ~/.tsa-curl \
    -H "Content-Type: application/timestamp-query" \
    -H "Accept: application/timestamp-reply" \
    --data-binary @req.tsq -o resp.tsr \
    https://tsa.example.invalid
openssl ts -reply -in resp.tsr -text
```

Credentials go in a curl config file, never on the command line: the process
table is readable by other users on the host. `-cert` asks the TSA to embed its
chain, which the next step needs and which `request.cert_req: true` requires.

The username is typically an account or customer number the provider issues,
not a human login.

---

## 3. Confirm the trust anchor through a second channel

Extract what the token carries:

```sh
openssl ts -reply -in resp.tsr -token_out -out token.p7
openssl pkcs7 -inform DER -in token.p7 -print_certs -out all-certs.pem
```

A root taken from the endpoint proves only that the token is self-consistent.
Compare it against the copy the provider publishes on its own site:

```sh
curl -sSo root.crt https://ca.example.invalid/roots/root.crt
openssl x509 -inform DER -in root.crt -out tsa-root.pem
openssl x509 -in tsa-root.pem -noout -fingerprint -sha256
openssl ts -verify -data subject.md -in resp.tsr -CAfile tsa-root.pem
```

All three providers published a byte-identical root. Only one also published a
fingerprint, which is the stronger form — with the file alone you are comparing
two copies fetched over the same public internet. **For an engagement producing
legal evidence, get the SHA-256 confirmed by your provider contact directly.**

`openssl ts -verify` always needs `-CAfile`. Without one it reports "unable to
get local issuer certificate" regardless of what is installed, which is not
evidence of a bad token.

Verification against the public roots failing with "self-signed certificate in
certificate chain" is the expected result, not a problem.

---

## 4. Read the properties that decide whether a run succeeds

All of these are confirmable from the single manual timestamp:

- **EKU** — `X509v3 Extended Key Usage: critical`, with `Time Stamping` as the
  only usage. This tool's `checkTimeStampingEKU` requires it present,
  **exclusive and critical** (RFC 3161 §2.3). OpenSSL only checks presence, so
  a chain that satisfies `ts -verify` can still be rejected here. All three
  providers satisfied all three conditions — but this is the property most
  likely to break a run, so check it rather than assume it.
- **ESS** — if `signingCertificateV2` is present, `require_ess: true` is safe
  and should be set. Left false, a missing attribute produces a per-attempt
  warning rather than a failure.
- **Clock** — `genTime` should land well inside the 60 s `max_clock_skew`
  default. Observed skews were 64 ms to 322 ms.
- **Signer validity** — check it outlasts the engagement.
- **Policy OID** — recorded from the token. See the warning below.

### Pin the policy OID from a token, never from the documentation

Provider A's published practice statement named one policy OID; its tokens
carried a different one. Requesting a policy the server does not offer is
itself grounds for rejection, so a policy OID copied out of a PDF can fail a
whole run.

Set `request.policy_oid` only from a value you have seen in a real token, and
only if you need it pinned. The verifier records the returned policy but does
not compare it against the requested one.

---

## 5. Work out the authentication scheme empirically

Documentation was wrong or silent on this for all three providers.

**Basic** is the easy case, but it is not always observable from outside:
Provider C answered an unauthenticated `POST` with HTTP 200 and a plain banner
rather than a 401, so the scheme could only be confirmed by sending a real
credentialed request and seeing it succeed.

**Digest** needs more care. Provider A advertised:

```
WWW-Authenticate: Digest realm="...", qop="auth", nonce="<base64>"
```

No `algorithm` parameter, so MD5 per RFC 7616 §3.3.

### The session-bound nonce, and an error that lies about everything

Provider A binds its digest nonce to a servlet session handed out as a
`JSESSIONID` cookie on the 401. A client that does not return that cookie
presents a nonce the server cannot match, and gets:

```
HTTP/1.1 500
Content-Type:
Content-Length: 42

<plain-text vendor error, no PKIStatusInfo>
```

This is worth dwelling on, because **every signal the error gives is
misleading**:

- it does not vary with the request body — a valid RFC 3161 query, one without
  a nonce, one without `certReq`, the policy OID from the provider's own
  practice statement, arbitrary bytes and an empty body all produce it
- it does not vary with the credentials — a correct digest, a digest computed
  from the wrong password, and a fabricated header carrying
  `response="deadbeef"` all produce it, so getting past the 401 proves only
  that *some* `Authorization` header was present
- it is an HTTP 500 with plain vendor text and an empty `Content-Type`, where
  RFC 3161 requires HTTP 200 and a `PKIStatusInfo` rejection

The only way through is to notice the `Set-Cookie` on the 401 and return it.

Go's default `http.Client` keeps no cookies, so this tool failed exactly the
same way until `transport.New` was given a jar. `internal/load` carries a
regression test against a session-bound mock; it fails without the jar.

By hand, curl needs both `digest` **and** a cookie jar:

```sh
printf 'user = "%s:%s"\ndigest\n' 'ACCOUNT' 'PASSWORD' > ~/.tsa-curl
chmod 600 ~/.tsa-curl

curl -sS -f -K ~/.tsa-curl -c cookies.txt -b cookies.txt \
    --cacert tsa-root.pem \
    -H "Content-Type: application/timestamp-query" \
    -H "Accept: application/timestamp-reply" \
    --data-binary @req.tsq -o resp.tsr \
    https://tsa.example.invalid
```

Without `-c/-b` this returns the 500 above. With them it returns a token.

### Single-use nonces under concurrency

Provider A honours a digest nonce exactly once despite advertising
`qop="auth"`, which exists so a nonce can be reused with an incrementing
count. Under load, every worker sharing one session and one nonce is a problem:
the count is allocated atomically so no value repeats, but 150 concurrent
requests arrive with their counts interleaved rather than in order, and a
strict or session-scoped server may reject or serialise on that.

`provider.auth.challenge_per_request: true` handles it — each timestamp draws
its own challenge on its own session, so concurrent workers never invalidate
each other. The extra requests issue no timestamp and consume no quota; they
are reported as `auth_requests` in `summary.json`.

Watch the first ramp stage for `http_4xx` before committing to a sustained
stage, and **confirm with the provider that concurrent use of one account is
expected**. Confirm how they count, too: digest costs one extra HTTP request at
priming, and any stale-nonce re-answer adds another.

---

## 6. genTime encoding

DER forbids a trailing zero in the fractional seconds of a `GeneralizedTime`.
A provider emitting several fractional digits without stripping trailing zeros
will produce non-minimal encodings at a predictable rate — roughly one token in
ten for Provider A, which emitted two fractional digits.

This tool's parser is tolerant and reports these as `verification_warnings`
rather than failures. Do not read the warning as a defect in your run.

It is not a consequence of precision: Provider C emitted **seven** fractional
digits and produced zero non-minimal encodings in 43,600 tokens, because it
strips trailing zeros correctly. The 10 % at Provider A is that provider's own
encoding defect.

---

## 7. Write the configuration

```yaml
provider:
  endpoint: "https://tsa.example.invalid"
  environment: live
  auth:
    type: digest                 # or basic
    username_env: TSA_USER       # the account number
    password_env: TSA_PASS
    challenge_per_request: true  # only if the nonce is single-use

tls:
  ca_file: ""                    # empty if the transport chains to a public root
  tsa_ca_file: "/path/to/tsa-root.pem"   # required; rarely a public CA

request:
  hash_algorithm: sha256
  cert_req: true
  require_ess: true              # once you have confirmed the attribute is present
  policy_oid: ""                 # only from a value seen in a real token

limits:
  hard_cap: 50000                # the engagement allowance
  max_requests: 48600            # per-run budget, must not exceed hard_cap
```

Keep the filled-in copy outside version control (`.gitignore` excludes
`configs/*.yaml`) and `chmod 600` both it and the root.

Then confirm the whole chain end to end for one unit of quota:

```sh
export TSA_USER='...' TSA_PASS='...'

tsa-bench validate --config ~/.config/tsa-bench/provider.yaml --profile profiles/50k.yaml
tsa-bench doctor   --config ~/.config/tsa-bench/provider.yaml              # no quota
tsa-bench doctor   --config ~/.config/tsa-bench/provider.yaml --send-one   # 1 unit
```

A good `--send-one` result looks like: `Content-Type:
application/timestamp-reply`, `verification PASSED`, ESS `SigningCertificateV2`
matched, sub-second skew, round trip in the expected range.

`environment: live` means `run` additionally requires
`--acknowledge-live-environment`. See [runbook.md](runbook.md) for the run
itself, and [capacity-findings.md](capacity-findings.md) for what these three
providers turned out to do under load.
