# RelayHound
RelayHound probes SMTP, submission and SMTPS listeners for the misconfigurations that
actually get mail infrastructure abused — open relaying, credential exposure, strippable
TLS, address disclosure — and writes a Markdown report in which **every finding carries the
raw wire transcript that produced it**.

It is built for engagements where a screenshot isn't good enough and the client's mail team
is going to ask "prove it".


## Why another SMTP scanner

Most tooling tells you *that* a port is an open relay. RelayHound hands you the paragraph
you paste into the report: the finding, the impact in operational terms, the exact
byte-level exchange that demonstrates it, the one-liner the client can run themselves to
confirm it, and the config directive that fixes it.

- **Nothing is ever delivered.** Relay vectors stop at `RCPT TO` and are immediately
  followed by `RSET`. The `DATA` command is never issued, so no message enters the queue —
  you get proof of the policy gap without putting mail on the wire.
- **Raw sockets, not `smtplib`.** `smtplib` normalises and hides exactly the protocol
  behaviour an auditor needs to observe. RelayHound speaks SMTP directly and records every
  byte in both directions with timestamps.
- **No false-positive shortcuts.** TLS version and cipher probes re-check what was actually
  negotiated against what was requested, so a local OpenSSL policy that silently refuses to
  pin a legacy protocol reports "not testable here" rather than a phantom finding.

---

## Install

```bash
git clone https://github.com/<you>/relayhound.git
cd relayhound
pip install -r requirements.txt   # optional but recommended
chmod +x relayhound.py
```

Python 3.8+. The standard library alone is enough to run every SMTP-level check.

| Optional dependency | Unlocks | Without it |
|---|---|---|
| `cryptography` | Full certificate analysis (RH-040…046) | Certificate is captured but not parsed |
| `dnspython` | `--dns`: SPF / DMARC / MTA-STS checks (RH-080…085) | `--dns` is skipped with a note |

---

## Usage

```bash
# Single host, default ports 25/465/587/2525
./relayhound.py -t mail.example.com -o report.md

# Explicit port list, plus email-authentication posture
./relayhound.py -t 10.0.0.5 -p 25,587 --dns -o report.md

# Whole scope file, 8 workers, machine-readable output alongside the report
./relayhound.py -T scope.txt --threads 8 -o engagement.md --json findings.json

# Per-target ports inline
./relayhound.py -t mail.example.com:587 -t 10.0.0.5:25 -o report.md

# Opt in to mailbox enumeration (intrusive — see below)
./relayhound.py -t mail.example.com --enum-users --userlist users.txt -o report.md
```

### Options that matter

| Flag | Purpose |
|---|---|
| `-t/--target` | Host, or `host:port`. Repeatable. IPv6 as `[::1]:25`. |
| `-T/--target-file` | One target per line, `#` comments allowed. |
| `-p/--ports` | Ports used when a target has none. Default `25,465,587,2525`. |
| `--implicit-tls-ports` | Ports wrapped in TLS from the first byte. Default `465`. |
| `--relay-to` | External recipient for relay probes. Defaults to an RFC 2606 reserved domain, so it is **never deliverable anywhere**. |
| `--relay-from` | Envelope sender for relay probes. |
| `--relay-domain` | Domain to treat as local to the target. Derived from the banner if omitted. |
| `--helo` | HELO/EHLO identity you present. Set this to something attributable on a real engagement. |
| `--enum-users` | Enables RCPT-differential mailbox enumeration. Off by default. |
| `--dns` | Adds SPF / DMARC / MTA-STS assessment for the target domain. |
| `-o/--output` | Markdown report path. Default `relayhound-report.md`. |
| `--json` | Additionally write structured findings for pipeline consumption. |
| `--threads` | Concurrent endpoints. Default 4. Keep it low against production MTAs. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No actionable findings |
| `1` | Findings, none above Medium |
| `2` | At least one High or Critical finding |
| `130` | Interrupted |

Useful in CI: `./relayhound.py -t mail.internal -q -o report.md || echo "regression"`.

---

## What it checks

### Relay and access control

| ID | Check | Max severity |
|---|---|---|
| RH-060 | **Open mail relay** — nine envelope-manipulation vectors | Critical |
| RH-061 | Relay restrictions enforced (positive control) | Info |
| RH-015 | `XCLIENT` / `XFORWARD` offered to unauthenticated clients | High |
| RH-013 | `ETRN` advertised to unauthenticated clients | Low |
| RH-014 | Obsolete `TURN` verb advertised | Medium |

The nine relay vectors are external→external, null sender, spoofed local sender, percent
hack (`user%dest@target`), bang path (`dest!user@target`), source route
(`@target:user@dest`), quoted address, trailing-dot domain, and bracket-less addressing.
Legacy MTAs and appliances routinely block the first and accept one of the rest.

### Transport security

| ID | Check | Max severity |
|---|---|---|
| RH-020 | STARTTLS not offered — mail in cleartext | High |
| RH-021/022 | STARTTLS advertised but refused, or handshake fails | Medium |
| RH-030 | Deprecated TLS 1.0 / 1.1 accepted | Medium |
| RH-031 | TLS 1.3 unsupported | Info |
| RH-032 | Weak suite negotiated by default | High |
| RH-033 | Broken cipher family accepted (aNULL, eNULL, EXPORT, RC4, DES/3DES) | High |
| RH-070 | **STARTTLS plaintext command injection** — pre-TLS buffer not reset | High |
| RH-071 | Injected command answered in cleartext after upgrade agreed | Medium |

RH-070 is the CVE-2011-0411 bug class: RFC 3207 §6 requires the server to discard buffered
input the moment it agrees to upgrade. RelayHound sends `STARTTLS\r\nNOOP\r\n` in a single
plaintext packet and then listens *inside* the TLS session for a reply it never asked for.
An answer there means an on-path attacker can inject commands the server will attribute to
the encrypted session.

### Certificate

| ID | Check | Max severity |
|---|---|---|
| RH-040 | Certificate expired | High |
| RH-041 | Certificate not yet valid | Medium |
| RH-042 | Expiring within 30 days | Low |
| RH-043 | Self-signed | Medium |
| RH-044 | Does not cover the queried hostname | Low |
| RH-045 | Weak signature hash (MD5 / SHA-1) | Medium |
| RH-046 | Undersized public key | High |

### Authentication and disclosure

| ID | Check | Max severity |
|---|---|---|
| RH-050 | Cleartext `AUTH PLAIN`/`LOGIN` offered before TLS | Critical |
| RH-051 | Legacy SASL mechanisms (CRAM-MD5, DIGEST-MD5, NTLM) | Low |
| RH-052 | Submission port advertises no AUTH | Info |
| RH-011 | `VRFY` enabled | Medium |
| RH-012 | `EXPN` enabled | Medium |
| RH-017 | RCPT-differential mailbox enumeration *(`--enum-users`)* | Medium |
| RH-010 | MTA product/version disclosed in banner | Low |
| RH-016 | No message size limit (`SIZE 0`) | Low |

RH-050 is rated Critical when the host offers no STARTTLS at all: there is then no path by
which a client could ever protect the password.

### Email authentication posture *(`--dns`)*

| ID | Check | Max severity |
|---|---|---|
| RH-080 | No SPF record | Medium |
| RH-081 | SPF permits any sender (`+all`) | High |
| RH-082 | SPF neutral (`?all`) | Low |
| RH-083 | No DMARC record | Medium |
| RH-084 | DMARC monitoring-only (`p=none`) | Low |
| RH-085 | No MTA-STS policy | Low |

---

## The report

`-o report.md` produces a document structured for direct inclusion in an engagement
deliverable:

1. **Executive summary** — severity counts and the single worst issue, named.
2. **Scope and reachability** — what answered, on what port, with what capabilities.
3. **Findings index** — severity-ranked table.
4. **Findings detail** — per finding: description, operational impact, the captured
   transcript, a collapsible structured-detail block, a copy-pasteable manual reproduction
   command, remediation with the actual config directive, and references (RFC / CVE / CWE).
5. **Service detail** — banner, capability list before and after STARTTLS, negotiated TLS,
   protocol support matrix, certificate summary with SHA-256 fingerprint.
6. **Appendix** — complete unedited session transcripts, one collapsible block per endpoint.
7. **Methodology and legal notice** — including the explicit statement that no message was
   delivered.

A full example against the bundled mock servers is checked in at
[`examples/sample-report.md`](examples/sample-report.md).

Evidence blocks look like this, which is the part that ends arguments:

```text
[  0.515s] >> MAIL FROM:<audit@example.org>
[  0.515s] << 250 2.1.0 Ok
[  0.515s] >> RCPT TO:<relay-test@example.net>
[  0.515s] << 250 2.1.5 Ok
[  0.515s] ** !! vector 'external-to-external' ACCEPTED - sending RSET, no DATA
[  0.515s] >> RSET
[  0.515s] << 250 2.0.0 Ok
```

---

## Safe by default

| Behaviour | Default |
|---|---|
| Sends `DATA` / delivers mail | **Never**, under any flag |
| Relay probe recipient | RFC 2606 reserved domain — undeliverable by design |
| Mailbox enumeration | Off — requires `--enum-users` |
| Credential guessing / spraying | Not implemented |
| Writes to the target | Never |

The only intrusive check is `--enum-users`, which issues `RCPT TO` for a wordlist of
local-parts plus a random control address and compares response codes. It is noisy and will
appear in the target's logs. Get it in scope in writing before you use it.

Two things worth knowing when interpreting results:

- **Relay policy is source-address dependent.** A clean RH-061 from your testing VPS says
  nothing about what the same MTA does for a host inside `mynetworks`. Re-test from every
  network position that is in scope.
- **A missing finding is not a guarantee.** RelayHound reports what the service disclosed
  to it. Confirm anything you intend to act on.

---

## Testing it

The repo ships deliberately broken servers so you can validate detections without touching
anything real:

```bash
python3 tests/mock_smtp.py vulnerable 12525   # open relay, VRFY/EXPN, XCLIENT, TURN,
                                              # cleartext AUTH, weak self-signed cert,
                                              # STARTTLS buffer not reset
python3 tests/mock_smtp.py hardened   12526   # should produce no protocol findings
python3 tests/mock_smtp.py plaintext  12527   # no STARTTLS, AUTH in the clear
python3 tests/mock_smtp.py enumleak   12528   # differential RCPT responses

./relayhound.py -t 127.0.0.1:12525 -t 127.0.0.1:12526 -t 127.0.0.1:12527 \
                -o /tmp/selftest.md --no-color
```

These bind to loopback only. Do not expose them — the `vulnerable` profile is an open relay
by design.

## Contributing

Additional relay vectors, MTA-specific remediation strings and new check modules are
welcome. A new check is a method on `SMTPAuditor` that appends `Finding` objects and is
added to the tuple in `SMTPAuditor.run()`; keep it non-delivering, give it a stable
`RH-xxx` ID, and add a mock-server profile that exercises it.

## Licence

MIT — see [LICENSE](LICENSE).
