#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RelayHound - SMTP service security auditor with evidence-grade reporting.

Probes SMTP / submission / SMTPS listeners for misconfiguration and weak
transport security, and emits a Markdown report in which every finding is
backed by the raw wire transcript that produced it.

Default behaviour is non-destructive and non-delivering:
  * Open-relay vectors stop at RCPT TO and are always followed by RSET.
    The DATA command is never issued, so no message is ever queued or sent.
  * User enumeration (VRFY / EXPN / RCPT differential) is opt-in via --enum-users.
  * Nothing is written to the target; no credentials are guessed or sprayed.

Author : (c) 2026 - released under the MIT Licence
Project: https://github.com/<you>/relayhound
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import os
import re
import socket
import ssl
import sys
import textwrap
import time
import warnings
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "1.0.0"
__toolname__ = "RelayHound"

# Probing deprecated protocol versions is the point of this tool, so silence
# Python's own complaints about asking for them.
warnings.filterwarnings("ignore", message=r".*TLSVersion\.TLSv1.*",
                        category=DeprecationWarning)

# --------------------------------------------------------------------------- #
# Optional dependencies - the tool degrades gracefully without them.
# --------------------------------------------------------------------------- #
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa

    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False

try:
    import dns.resolver  # type: ignore

    HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    HAVE_DNSPYTHON = False


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

ANSI = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[0;37m",
    "OK": "\033[1;32m",
    "DIM": "\033[2m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}

USE_COLOR = True


def c(text: str, key: str) -> str:
    if not USE_COLOR:
        return text
    return f"{ANSI.get(key, '')}{text}{ANSI['RESET']}"


def log(msg: str, level: str = "INFO", quiet: bool = False) -> None:
    if quiet:
        return
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Finding:
    """A single audit result, carrying its own proof."""

    check_id: str
    title: str
    severity: str
    target: str
    summary: str
    impact: str
    remediation: str
    evidence: List[str] = dataclasses.field(default_factory=list)
    reproduce: List[str] = dataclasses.field(default_factory=list)
    references: List[str] = dataclasses.field(default_factory=list)
    detail: Dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def rank(self) -> int:
        return SEV_ORDER.get(self.severity, 9)


@dataclasses.dataclass
class TranscriptLine:
    ts: float
    direction: str  # '>>' client->server, '<<' server->client, '**' annotation
    text: str

    def render(self, t0: float) -> str:
        return f"[{self.ts - t0:7.3f}s] {self.direction} {self.text}"


class Transcript:
    """Ordered record of everything that crossed the wire."""

    def __init__(self) -> None:
        self.t0 = time.time()
        self.lines: List[TranscriptLine] = []

    def add(self, direction: str, text: str) -> None:
        for part in text.replace("\r\n", "\n").split("\n"):
            self.lines.append(TranscriptLine(time.time(), direction, part))

    def note(self, text: str) -> None:
        self.add("**", text)

    def mark(self) -> int:
        return len(self.lines)

    def slice(self, start: int, end: Optional[int] = None) -> List[str]:
        end = len(self.lines) if end is None else end
        return [ln.render(self.t0) for ln in self.lines[start:end]]

    def render_all(self) -> List[str]:
        return [ln.render(self.t0) for ln in self.lines]


class SMTPError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Low level SMTP wire
# --------------------------------------------------------------------------- #
class SMTPWire:
    """Minimal, transcript-recording SMTP client built straight on sockets.

    smtplib is deliberately avoided: it normalises and hides exactly the
    protocol-level behaviour an auditor needs to observe and evidence.
    """

    def __init__(self, host: str, port: int, timeout: float, transcript: Transcript):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tx = transcript
        self.sock: Optional[socket.socket] = None
        self.raw: Optional[socket.socket] = None
        self.buf = b""
        self.tls_active = False
        self.tls_info: Dict[str, Any] = {}

    # -- connection ------------------------------------------------------- #
    def connect(self) -> None:
        last: Optional[Exception] = None
        for fam, stype, proto, _cn, sa in socket.getaddrinfo(
            self.host, self.port, 0, socket.SOCK_STREAM
        ):
            try:
                s = socket.socket(fam, stype, proto)
                s.settimeout(self.timeout)
                s.connect(sa)
                self.sock = s
                self.raw = s
                self.tx.note(f"TCP connect -> {sa[0]}:{sa[1]} established")
                return
            except Exception as exc:  # try next address family
                last = exc
                try:
                    s.close()
                except Exception:
                    pass
        raise SMTPError(f"connect failed: {last}")

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None

    # -- raw io ----------------------------------------------------------- #
    def _recv(self, timeout: Optional[float] = None) -> bytes:
        assert self.sock is not None
        self.sock.settimeout(self.timeout if timeout is None else timeout)
        return self.sock.recv(8192)

    def readline(self, timeout: Optional[float] = None) -> Optional[str]:
        while b"\r\n" not in self.buf:
            try:
                chunk = self._recv(timeout)
            except socket.timeout:
                raise SMTPError("timeout waiting for server response")
            if not chunk:
                if self.buf:
                    line, self.buf = self.buf, b""
                    return line.decode("utf-8", "replace")
                return None
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\r\n")
        return line.decode("utf-8", "replace")

    def read_response(self, timeout: Optional[float] = None) -> Tuple[int, List[str]]:
        """Read one (possibly multi-line) SMTP reply."""
        lines: List[str] = []
        while True:
            line = self.readline(timeout)
            if line is None:
                break
            lines.append(line)
            self.tx.add("<<", line)
            if len(line) < 4 or line[3] != "-":
                break
        if not lines:
            raise SMTPError("connection closed by peer with no response")
        code = int(lines[0][:3]) if lines[0][:3].isdigit() else -1
        return code, lines

    def send_line(self, text: str, log_as: Optional[str] = None) -> None:
        assert self.sock is not None
        self.tx.add(">>", log_as if log_as is not None else text)
        self.sock.sendall((text + "\r\n").encode("utf-8", "replace"))

    def send_raw(self, data: bytes, note: str) -> None:
        assert self.sock is not None
        self.tx.add(">>", note)
        self.sock.sendall(data)

    def cmd(self, text: str, timeout: Optional[float] = None) -> Tuple[int, List[str]]:
        self.send_line(text)
        return self.read_response(timeout)

    def pending(self, wait: float = 2.0) -> Optional[str]:
        """Return unsolicited data already waiting to be read, if any."""
        if self.buf:
            line, _, self.buf = self.buf.partition(b"\r\n")
            return line.decode("utf-8", "replace")
        try:
            data = self._recv(wait)
        except socket.timeout:
            return None
        except OSError:
            return None
        if not data:
            return None
        self.buf += data
        line, _, self.buf = self.buf.partition(b"\r\n")
        return line.decode("utf-8", "replace")

    # -- TLS -------------------------------------------------------------- #
    def wrap_tls(self, ctx: ssl.SSLContext) -> None:
        assert self.sock is not None
        self.tx.note("initiating TLS handshake")
        wrapped = ctx.wrap_socket(self.sock, server_hostname=self.host)
        self.sock = wrapped
        self.tls_active = True
        cipher = wrapped.cipher() or ("?", "?", 0)
        der = wrapped.getpeercert(binary_form=True)
        self.tls_info = {
            "protocol": wrapped.version(),
            "cipher": cipher[0],
            "cipher_proto": cipher[1],
            "cipher_bits": cipher[2],
            "der": der,
        }
        self.tx.note(
            f"TLS established: {wrapped.version()} / {cipher[0]} / {cipher[2]} bits"
        )


# --------------------------------------------------------------------------- #
# TLS helpers
# --------------------------------------------------------------------------- #
def build_ctx(
    min_ver: Optional[ssl.TLSVersion] = None,
    max_ver: Optional[ssl.TLSVersion] = None,
    ciphers: Optional[str] = None,
) -> ssl.SSLContext:
    """A deliberately permissive client context - we are measuring the server,
    not trusting it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers(ciphers or "ALL:@SECLEVEL=0")
    except ssl.SSLError:
        try:
            ctx.set_ciphers(ciphers or "ALL")
        except ssl.SSLError:
            pass
    if min_ver is not None:
        try:
            ctx.minimum_version = min_ver
        except (ValueError, OSError):
            pass
    if max_ver is not None:
        try:
            ctx.maximum_version = max_ver
        except (ValueError, OSError):
            pass
    return ctx


TLS_VERSIONS: List[Tuple[str, Any]] = []
for _name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
    _v = getattr(ssl.TLSVersion, _name, None)
    if _v is not None:
        TLS_VERSIONS.append((_name.replace("_", "."), _v))

WEAK_CIPHER_TOKENS = (
    "NULL", "EXPORT", "RC4", "RC2", "DES-CBC3", "3DES", "DES", "MD5",
    "ADH", "AECDH", "aNULL", "eNULL", "IDEA", "SEED", "PSK", "SRP",
)


def cipher_is_weak(name: str, bits: int) -> Optional[str]:
    up = name.upper()
    for tok in WEAK_CIPHER_TOKENS:
        if tok.upper() in up:
            return tok
    if bits and bits < 128:
        return f"{bits}-bit key"
    if "CBC" in up and "TLS_" not in up and "GCM" not in up:
        return None  # CBC alone is not reported as weak, only noted
    return None


def wildcard_match(hostname: str, pattern: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        if hostname.endswith(suffix):
            left = hostname[: -len(suffix)]
            return left != "" and "." not in left
    return False


def parse_certificate(der: bytes) -> Dict[str, Any]:
    """Best-effort certificate introspection."""
    info: Dict[str, Any] = {"parsed": False}
    if not der:
        return info
    info["pem"] = ssl.DER_cert_to_PEM_cert(der)
    if not HAVE_CRYPTOGRAPHY:
        return info
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        info["error"] = str(exc)
        return info

    def _dt(attr_utc: str, attr: str):
        v = getattr(cert, attr_utc, None)
        if v is not None:
            return v
        v = getattr(cert, attr)
        return v.replace(tzinfo=dt.timezone.utc)

    names: List[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = list(san.value.get_values_for_type(x509.DNSName))
        for ip in san.value.get_values_for_type(x509.IPAddress):
            names.append(str(ip))
    except Exception:
        pass
    cn = ""
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        pass

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        keytype, keysize = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        keytype, keysize = f"EC/{pub.curve.name}", pub.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        keytype, keysize = "DSA", pub.key_size
    else:
        keytype, keysize = type(pub).__name__, getattr(pub, "key_size", 0)

    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?"
    except Exception:
        sig = "?"

    info.update(
        parsed=True,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        common_name=cn,
        san=names,
        serial=format(cert.serial_number, "x"),
        not_before=_dt("not_valid_before_utc", "not_valid_before"),
        not_after=_dt("not_valid_after_utc", "not_valid_after"),
        self_signed=cert.subject == cert.issuer,
        key_type=keytype,
        key_size=keysize,
        sig_hash=sig,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )
    return info


# --------------------------------------------------------------------------- #
# Open relay vectors - all stop at RCPT TO, none ever issue DATA.
# --------------------------------------------------------------------------- #
def relay_vectors(target_domain: str, probe_to: str, probe_from: str) -> List[Tuple[str, str, str]]:
    """Return (label, MAIL FROM address, RCPT TO address) triples."""
    ext_user, ext_dom = probe_to.split("@", 1)
    return [
        ("external-to-external",
         f"<{probe_from}>", f"<{probe_to}>"),
        ("null-sender",
         "<>", f"<{probe_to}>"),
        ("spoofed-local-sender",
         f"<postmaster@{target_domain}>", f"<{probe_to}>"),
        ("percent-hack",
         f"<{probe_from}>", f"<{ext_user}%{ext_dom}@{target_domain}>"),
        ("bang-path",
         f"<{probe_from}>", f"<{ext_dom}!{ext_user}@{target_domain}>"),
        ("source-route",
         f"<{probe_from}>", f"<@{target_domain}:{probe_to}>"),
        ("quoted-address",
         f"<{probe_from}>", f'<"{probe_to}"@{target_domain}>'),
        ("trailing-dot-domain",
         f"<{probe_from}>", f"<{ext_user}@{ext_dom}.>"),
        ("no-brackets",
         probe_from, probe_to),
    ]


BANNER_VERSION_RE = re.compile(
    r"(postfix|exim|sendmail|exchange|microsoft|zimbra|qmail|opensmtpd|smtpd|haraka|"
    r"mailenable|kerio|courier|dovecot|mdaemon|iredmail|proofpoint|barracuda|mimecast)"
    r"[^\r\n]{0,60}?(\d+\.[\d.]+)?",
    re.I,
)


# --------------------------------------------------------------------------- #
# The auditor
# --------------------------------------------------------------------------- #
class SMTPAuditor:
    def __init__(self, host: str, port: int, args: argparse.Namespace):
        self.host = host
        self.port = port
        self.args = args
        self.target = f"{host}:{port}"
        self.tx = Transcript()
        self.findings: List[Finding] = []
        self.facts: Dict[str, Any] = {
            "host": host,
            "port": port,
            "reachable": False,
            "banner": "",
            "ehlo_caps": {},
            "ehlo_caps_tls": {},
            "starttls": False,
            "implicit_tls": False,
            "tls": {},
            "cert": {},
            "tls_versions": {},
            "error": None,
        }
        self.implicit = port in args.implicit_ports

    # -- helpers ---------------------------------------------------------- #
    def add(self, **kw: Any) -> Finding:
        f = Finding(target=self.target, **kw)
        self.findings.append(f)
        return f

    def _new_wire(self, transcript: Optional[Transcript] = None) -> SMTPWire:
        return SMTPWire(self.host, self.port, self.args.timeout, transcript or self.tx)

    def _open_session(self, tls: bool = False) -> Tuple[SMTPWire, Dict[str, str]]:
        """Connect, greet, and return the wire plus EHLO capabilities."""
        w = self._new_wire()
        w.connect()
        if self.implicit or tls:
            w.wrap_tls(build_ctx())
        w.read_response()
        caps = self._ehlo(w)
        return w, caps

    def _ehlo(self, w: SMTPWire) -> Dict[str, str]:
        code, lines = w.cmd(f"EHLO {self.args.helo}")
        caps: Dict[str, str] = {}
        if code == 250:
            for line in lines[1:]:
                body = line[4:].strip()
                if not body:
                    continue
                key, _, rest = body.partition(" ")
                caps[key.upper()] = rest.strip()
        return caps

    @staticmethod
    def _quiet_quit(w: SMTPWire) -> None:
        try:
            w.send_line("QUIT")
            w.read_response(timeout=2)
        except Exception:
            pass
        w.close()

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        try:
            self._probe_service()
        except SMTPError as exc:
            self.facts["error"] = str(exc)
            self.tx.note(f"ABORT: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            self.facts["error"] = f"{type(exc).__name__}: {exc}"
            self.tx.note(f"ABORT: {exc}")
            return

        for check in (
            self.check_banner_disclosure,
            self.check_transport_security,
            self.check_tls_versions,
            self.check_certificate,
            self.check_weak_ciphers,
            self.check_auth_exposure,
            self.check_verify_expand,
            self.check_dangerous_verbs,
            self.check_open_relay,
            self.check_starttls_injection,
            self.check_user_enumeration,
            self.check_dns_posture,
        ):
            try:
                check()
            except SMTPError as exc:
                self.tx.note(f"check {check.__name__} aborted: {exc}")
            except Exception as exc:  # noqa: BLE001
                self.tx.note(f"check {check.__name__} error: {type(exc).__name__}: {exc}")

        self.findings.sort(key=lambda f: (f.rank, f.check_id))

    # ------------------------------------------------------------------ #
    # Baseline
    # ------------------------------------------------------------------ #
    def _probe_service(self) -> None:
        w = self._new_wire()
        w.connect()
        self.facts["reachable"] = True

        if self.implicit:
            try:
                w.wrap_tls(build_ctx())
                self.facts["implicit_tls"] = True
                self.facts["tls"] = {
                    k: v for k, v in w.tls_info.items() if k != "der"
                }
                self.facts["cert"] = parse_certificate(w.tls_info.get("der") or b"")
            except Exception as exc:
                self.tx.note(f"implicit TLS handshake failed: {exc}")
                self.implicit = False
                w.close()
                w = self._new_wire()
                w.connect()

        code, lines = w.read_response()
        banner = lines[0] if lines else ""
        self.facts["banner"] = banner
        if code != 220:
            self.add(
                check_id="RH-000",
                title="Service did not present a 220 service-ready greeting",
                severity="INFO",
                summary=f"The listener answered with `{banner}` instead of a 220 greeting.",
                impact="The port may not be running SMTP, or the source address is blocked "
                       "or tarpitted by the service.",
                remediation="Confirm the intended service is bound to this port.",
                evidence=self.tx.slice(0),
            )

        caps = self._ehlo(w)
        self.facts["ehlo_caps"] = caps
        self.facts["starttls"] = "STARTTLS" in caps
        if not caps:
            # Fall back to legacy HELO for pre-ESMTP servers.
            code, _ = w.cmd(f"HELO {self.args.helo}")
            self.facts["esmtp"] = False
            if code == 250:
                self.add(
                    check_id="RH-001",
                    title="Server does not support ESMTP (EHLO rejected, HELO accepted)",
                    severity="LOW",
                    summary="The service rejected EHLO but accepted the legacy HELO verb.",
                    impact="Without ESMTP there is no STARTTLS, no SIZE negotiation and no "
                           "authentication extension, so all traffic is necessarily cleartext.",
                    remediation="Upgrade or reconfigure the MTA to advertise ESMTP and STARTTLS.",
                    evidence=self.tx.slice(0),
                    references=["RFC 5321 §2.2"],
                )
        else:
            self.facts["esmtp"] = True

        self._quiet_quit(w)

    # ------------------------------------------------------------------ #
    def check_banner_disclosure(self) -> None:
        banner = self.facts.get("banner", "")
        if not banner:
            return
        m = BANNER_VERSION_RE.search(banner)
        if not m:
            return
        product = m.group(1)
        version = m.group(2)
        sev = "LOW" if version else "INFO"
        self.add(
            check_id="RH-010",
            title="MTA product and version disclosed in service banner",
            severity=sev,
            summary=f"The greeting identifies the mail server as **{product}"
                    f"{' ' + version if version else ''}**.",
            impact="Banner detail lets an attacker map the listener to known CVEs and pick "
                   "exploits or bypasses without touching the service further, and it aids "
                   "target selection during mass scanning.",
            remediation="Override the greeting with a generic string "
                        "(Postfix: `smtpd_banner = $myhostname ESMTP`; "
                        "Exim: `smtp_banner`; Sendmail: `confSMTP_LOGIN_MSG`). "
                        "Treat this as defence-in-depth, not a fix in itself.",
            evidence=[f"[banner] << {banner}"],
            reproduce=[f"printf 'QUIT\\r\\n' | nc {self.host} {self.port}"],
            detail={"product": product, "version": version or "not disclosed"},
            references=["OWASP WSTG-INFO-02"],
        )

    # ------------------------------------------------------------------ #
    def check_transport_security(self) -> None:
        caps = self.facts["ehlo_caps"]
        if self.facts.get("implicit_tls"):
            return  # port is already TLS-only

        if "STARTTLS" not in caps:
            sev = "HIGH" if self.port in (587, 465) else "MEDIUM"
            self.add(
                check_id="RH-020",
                title="STARTTLS not offered - mail transported in cleartext",
                severity=sev,
                summary="The EHLO capability list contains no STARTTLS keyword, so the "
                        "session cannot be upgraded to TLS.",
                impact="Message bodies, envelope addresses and any AUTH credentials cross the "
                       "network in plaintext, readable and modifiable by anyone on-path. "
                       "On a submission port this also means user passwords are exposed.",
                remediation="Enable STARTTLS with a valid certificate. On submission (587) "
                            "make TLS mandatory (Postfix: `smtpd_tls_security_level = encrypt` "
                            "on the submission service).",
                evidence=self._cap_evidence(),
                reproduce=[f"openssl s_client -starttls smtp -connect {self.host}:{self.port}"],
                references=["RFC 3207", "RFC 8314 §3"],
            )
            return

        # STARTTLS advertised - verify it actually works.
        w = self._new_wire()
        start = self.tx.mark()
        try:
            w.connect()
            w.read_response()
            self._ehlo(w)
            code, lines = w.cmd("STARTTLS")
            if code != 220:
                self.add(
                    check_id="RH-021",
                    title="STARTTLS advertised but refused",
                    severity="MEDIUM",
                    summary=f"The server advertises STARTTLS but answered `{lines[0]}`.",
                    impact="Clients that opportunistically upgrade will silently fall back to "
                           "cleartext, so the advertised protection never applies.",
                    remediation="Fix the TLS configuration (certificate/key path and "
                                "permissions are the usual cause) or stop advertising STARTTLS.",
                    evidence=self.tx.slice(start),
                )
                self._quiet_quit(w)
                return
            w.wrap_tls(build_ctx())
            self.facts["tls"] = {k: v for k, v in w.tls_info.items() if k != "der"}
            self.facts["cert"] = parse_certificate(w.tls_info.get("der") or b"")
            caps_tls = self._ehlo(w)
            self.facts["ehlo_caps_tls"] = caps_tls
            self._quiet_quit(w)
        except Exception as exc:
            self.tx.note(f"STARTTLS probe failed: {exc}")
            self.add(
                check_id="RH-022",
                title="STARTTLS handshake failed",
                severity="MEDIUM",
                summary=f"TLS negotiation after STARTTLS failed: `{exc}`.",
                impact="Opportunistic senders will downgrade to cleartext delivery.",
                remediation="Inspect the MTA TLS logs; verify the certificate chain, key "
                            "permissions and enabled protocol versions.",
                evidence=self.tx.slice(start),
                reproduce=[f"openssl s_client -starttls smtp -connect {self.host}:{self.port}"],
            )
            w.close()

    def _cap_evidence(self) -> List[str]:
        caps = self.facts["ehlo_caps"]
        out = [
            f"[greeting] << {self.facts.get('banner', '')}",
            f"[EHLO]     >> EHLO {self.args.helo}",
        ]
        keys = list(caps)
        for i, k in enumerate(keys):
            sep = " " if i == len(keys) - 1 else "-"
            v = caps[k]
            out.append(f"[EHLO]     << 250{sep}{k}{(' ' + v) if v else ''}")
        if not keys:
            out.append("[EHLO]     << (no capabilities advertised)")
        return out

    # ------------------------------------------------------------------ #
    def check_tls_versions(self) -> None:
        if not (self.facts.get("starttls") or self.facts.get("implicit_tls")):
            return
        supported: Dict[str, Any] = {}
        start = self.tx.mark()
        for label, ver in TLS_VERSIONS:
            ok, note = self._try_tls_version(label, ver)
            supported[label] = ok
            self.tx.note(f"TLS probe {label}: {'ACCEPTED' if ok else 'rejected'} ({note})")
        self.facts["tls_versions"] = supported

        legacy = [k for k in ("TLSv1", "TLSv1.1") if supported.get(k)]
        if legacy:
            self.add(
                check_id="RH-030",
                title=f"Deprecated TLS version(s) accepted: {', '.join(legacy)}",
                severity="MEDIUM",
                summary=f"The service completed a handshake using {', '.join(legacy)}, both "
                        "formally deprecated by RFC 8996.",
                impact="Legacy TLS keeps CBC padding-oracle and downgrade weaknesses "
                       "(BEAST, LUCKY13, POODLE-TLS) reachable and fails PCI DSS and most "
                       "hardening baselines.",
                remediation="Restrict to TLS 1.2 and 1.3 (Postfix: "
                            "`smtpd_tls_mandatory_protocols = >=TLSv1.2`, "
                            "`smtpd_tls_protocols = >=TLSv1.2`).",
                evidence=self.tx.slice(start),
                reproduce=[
                    f"openssl s_client -tls1 -starttls smtp -connect {self.host}:{self.port}",
                    f"openssl s_client -tls1_1 -starttls smtp -connect {self.host}:{self.port}",
                ],
                detail=supported,
                references=["RFC 8996", "RFC 7525"],
            )
        if supported.get("TLSv1.3") is False and supported.get("TLSv1.2"):
            self.add(
                check_id="RH-031",
                title="TLS 1.3 not supported",
                severity="INFO",
                summary="The highest protocol the service would negotiate is TLS 1.2.",
                impact="No forward-secrecy-by-default, no 0-RTT-free handshake simplification; "
                       "hardening only, not directly exploitable.",
                remediation="Enable TLS 1.3 where the MTA and OpenSSL build support it.",
                evidence=self.tx.slice(start),
                detail=supported,
            )

    def _try_tls_version(self, label: str, ver: Any) -> Tuple[bool, str]:
        """Pin the client to exactly one protocol version and see if it lands.

        The negotiated version is re-checked against the requested one so that a
        local OpenSSL policy silently refusing to pin cannot produce a false
        positive.
        """
        ctx = build_ctx(min_ver=ver, max_ver=ver)
        if (getattr(ctx, "minimum_version", None) != ver
                or getattr(ctx, "maximum_version", None) != ver):
            return False, "local OpenSSL refused to pin this version (untestable here)"
        w = SMTPWire(self.host, self.port, min(self.args.timeout, 8.0), Transcript())
        try:
            w.connect()
            if self.implicit:
                w.wrap_tls(ctx)
            else:
                w.read_response()
                self._ehlo(w)
                if w.cmd("STARTTLS")[0] != 220:
                    return False, "STARTTLS refused"
                w.wrap_tls(ctx)
            negotiated = w.tls_info.get("protocol") or "?"
            if negotiated != label:
                return False, f"negotiated {negotiated} instead"
            return True, f"{negotiated} / {w.tls_info.get('cipher')}"
        except ssl.SSLError as exc:
            return False, str(exc).split("] ")[-1][:70]
        except Exception as exc:
            return False, f"{type(exc).__name__}"
        finally:
            w.close()

    # ------------------------------------------------------------------ #
    def check_weak_ciphers(self) -> None:
        if not (self.facts.get("starttls") or self.facts.get("implicit_tls")):
            return
        tls = self.facts.get("tls") or {}
        name, bits = tls.get("cipher", ""), tls.get("cipher_bits", 0) or 0
        reason = cipher_is_weak(name, bits)
        if reason:
            self.add(
                check_id="RH-032",
                title=f"Weak cipher suite negotiated by default: {name}",
                severity="HIGH",
                summary=f"The default handshake settled on `{name}` ({bits} bits) - flagged "
                        f"because of `{reason}`.",
                impact="Weak or export-grade suites permit practical decryption or tampering of "
                       "the mail session by an on-path attacker.",
                remediation="Set a modern cipher policy (AEAD suites only) and disable "
                            "NULL/EXPORT/RC4/DES/3DES and anonymous key exchange.",
                evidence=[f"[TLS] ** negotiated {tls.get('protocol')} / {name} / {bits} bits"],
                reproduce=[f"nmap --script ssl-enum-ciphers -p {self.port} {self.host}"],
                references=["RFC 7525 §4.2"],
            )

        # Targeted probe for the genuinely broken families.
        start = self.tx.mark()
        for label, spec, tokens in (
            ("anonymous (aNULL)", "aNULL:@SECLEVEL=0", ("ADH", "AECDH", "ANON")),
            ("NULL encryption (eNULL)", "eNULL:@SECLEVEL=0", ("NULL",)),
            ("EXPORT grade", "EXPORT:@SECLEVEL=0", ("EXP",)),
            ("RC4", "RC4:@SECLEVEL=0", ("RC4",)),
            ("single DES / 3DES", "DES:3DES:@SECLEVEL=0", ("DES",)),
        ):
            ok, detail = self._try_cipher_spec(spec, tokens)
            self.tx.note(f"cipher probe {label}: {'ACCEPTED - ' + detail if ok else 'rejected'}")
            if ok:
                self.add(
                    check_id="RH-033",
                    title=f"Broken cipher family accepted: {label}",
                    severity="HIGH" if "NULL" in label or "EXPORT" in label else "MEDIUM",
                    summary=f"The server completed a handshake restricted to {label} "
                            f"({detail}).",
                    impact="These families provide no confidentiality (NULL/anon), trivially "
                           "breakable confidentiality (EXPORT), or known plaintext-recovery "
                           "weaknesses (RC4, SWEET32 for 3DES).",
                    remediation="Remove the family from the server cipher list and pin a "
                                "modern AEAD-only policy.",
                    evidence=self.tx.slice(start),
                    reproduce=[
                        f"openssl s_client -cipher '{spec.split(':@')[0]}' -starttls smtp "
                        f"-connect {self.host}:{self.port}"
                    ],
                    references=["CVE-2016-2183 (SWEET32)", "RFC 7465 (RC4 prohibited)"],
                )

    def _try_cipher_spec(self, spec: str, tokens: Sequence[str]) -> Tuple[bool, str]:
        """Offer only one broken cipher family and confirm what comes back.

        Built strictly: if the local OpenSSL cannot even express the cipher
        string, the probe reports 'not testable' rather than falling back to a
        permissive list and mis-attributing the result to the server.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, OSError):
            pass
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # these families are pre-1.3
        except (ValueError, OSError):
            pass
        try:
            ctx.set_ciphers(spec)
        except ssl.SSLError:
            return False, "not testable with local OpenSSL"
        w = SMTPWire(self.host, self.port, min(self.args.timeout, 8.0), Transcript())
        try:
            w.connect()
            if self.implicit:
                w.wrap_tls(ctx)
            else:
                w.read_response()
                self._ehlo(w)
                if w.cmd("STARTTLS")[0] != 220:
                    return False, "STARTTLS refused"
                w.wrap_tls(ctx)
            name = (w.tls_info.get("cipher") or "").upper()
            if tokens and not any(t.upper() in name for t in tokens):
                return False, f"negotiated unrelated suite {name}"
            return True, f"{w.tls_info.get('protocol')} / {w.tls_info.get('cipher')}"
        except Exception:
            return False, ""
        finally:
            w.close()

    # ------------------------------------------------------------------ #
    def check_certificate(self) -> None:
        cert = self.facts.get("cert") or {}
        if not cert.get("parsed"):
            if cert.get("pem"):
                self.tx.note("certificate captured but not parsed (cryptography missing)")
            return

        now = dt.datetime.now(dt.timezone.utc)
        not_after = cert["not_after"]
        not_before = cert["not_before"]
        days = (not_after - now).days
        base_ev = [
            f"[cert] subject      : {cert['subject']}",
            f"[cert] issuer       : {cert['issuer']}",
            f"[cert] serial       : {cert['serial']}",
            f"[cert] valid from   : {not_before.isoformat()}",
            f"[cert] valid until  : {not_after.isoformat()} ({days} days)",
            f"[cert] SAN          : {', '.join(cert['san']) or '(none)'}",
            f"[cert] key          : {cert['key_type']} {cert['key_size']} bits",
            f"[cert] signature    : {cert['sig_hash']}",
            f"[cert] SHA-256 FP   : {cert['fingerprint_sha256']}",
        ]
        repro = [
            f"openssl s_client -starttls smtp -connect {self.host}:{self.port} "
            f"</dev/null 2>/dev/null | openssl x509 -noout -text"
        ]

        if now > not_after:
            self.add(
                check_id="RH-040", title="TLS certificate has expired", severity="HIGH",
                summary=f"The presented certificate expired on {not_after.date()} "
                        f"({abs(days)} days ago).",
                impact="Validating peers refuse or downgrade the session; users and admins are "
                       "trained to click through the warning, which normalises MITM.",
                remediation="Renew the certificate and automate renewal (ACME/certbot with an "
                            "MTA reload hook).",
                evidence=base_ev, reproduce=repro,
            )
        elif now < not_before:
            self.add(
                check_id="RH-041", title="TLS certificate is not yet valid", severity="MEDIUM",
                summary=f"The certificate becomes valid on {not_before.date()}.",
                impact="Validating clients reject the handshake; likely a clock or "
                       "provisioning fault.",
                remediation="Check system time and reissue if the notBefore date is wrong.",
                evidence=base_ev, reproduce=repro,
            )
        elif days <= 30:
            self.add(
                check_id="RH-042", title=f"TLS certificate expires in {days} days",
                severity="LOW",
                summary=f"The certificate expires on {not_after.date()}.",
                impact="An unnoticed expiry causes a mail outage or a silent downgrade to "
                       "cleartext for opportunistic senders.",
                remediation="Automate renewal and alert at 30/14/7 days.",
                evidence=base_ev, reproduce=repro,
            )

        if cert.get("self_signed"):
            self.add(
                check_id="RH-043", title="TLS certificate is self-signed", severity="MEDIUM",
                summary="The certificate subject and issuer are identical, so no external "
                        "authority vouches for this host.",
                impact="Peers cannot distinguish the real server from an interceptor. Because "
                       "opportunistic SMTP TLS does not validate by default, an on-path "
                       "attacker can substitute their own certificate and read all mail.",
                remediation="Deploy a publicly trusted certificate and publish MTA-STS and "
                            "DANE/TLSA so senders can enforce validation.",
                evidence=base_ev, reproduce=repro,
                references=["RFC 8461 (MTA-STS)", "RFC 7672 (DANE for SMTP)"],
            )

        # Hostname coverage
        if not _is_ip(self.host):
            names = list(cert.get("san") or [])
            if not names and cert.get("common_name"):
                names = [cert["common_name"]]
            if names and not any(wildcard_match(self.host, n) for n in names):
                self.add(
                    check_id="RH-044",
                    title="TLS certificate does not cover the queried hostname",
                    severity="LOW",
                    summary=f"`{self.host}` matches none of: {', '.join(names)}.",
                    impact="Strict senders (MTA-STS enforce mode, DANE) will fail delivery; "
                           "everyone else silently ignores the mismatch, which weakens the "
                           "value of the certificate to nothing.",
                    remediation="Reissue covering the MX hostname, or correct the MX record to "
                                "a name the certificate covers.",
                    evidence=base_ev + [f"[cert] queried name : {self.host}"],
                    reproduce=repro,
                )

        if cert.get("sig_hash", "").lower() in ("md5", "sha1"):
            self.add(
                check_id="RH-045",
                title=f"Certificate signed with weak hash ({cert['sig_hash'].upper()})",
                severity="MEDIUM",
                summary=f"The signature algorithm uses {cert['sig_hash'].upper()}.",
                impact="Chosen-prefix collisions against SHA-1/MD5 are practical, enabling "
                       "forged certificates for this identity.",
                remediation="Reissue with SHA-256 or stronger.",
                evidence=base_ev, reproduce=repro,
                references=["CVE-2005-4900 (SHA-1)", "SHAttered / SHA-1 is a Shambles"],
            )

        ksize = cert.get("key_size") or 0
        ktype = cert.get("key_type", "")
        if (ktype.startswith("RSA") or ktype.startswith("DSA")) and ksize < 2048:
            self.add(
                check_id="RH-046",
                title=f"Certificate public key is undersized ({ktype} {ksize} bits)",
                severity="MEDIUM" if ksize >= 1024 else "HIGH",
                summary=f"The server key is {ksize}-bit {ktype}.",
                impact="Keys below 2048 bits are within reach of well-resourced factoring and "
                       "are rejected by modern trust stores.",
                remediation="Reissue with a 2048-bit (or larger) RSA key, or a P-256 EC key.",
                evidence=base_ev, reproduce=repro,
                references=["NIST SP 800-57 Part 1"],
            )

    # ------------------------------------------------------------------ #
    def check_auth_exposure(self) -> None:
        caps = self.facts["ehlo_caps"]
        auth_plain = caps.get("AUTH", "")
        # Some servers advertise the non-standard 'AUTH=LOGIN' form too.
        for k, v in caps.items():
            if k.startswith("AUTH="):
                auth_plain = (auth_plain + " " + k[5:] + " " + v).strip()

        if auth_plain and not self.facts.get("implicit_tls"):
            mechs = [m.upper() for m in auth_plain.split() if m]
            cleartext = [m for m in mechs if m in ("PLAIN", "LOGIN")]
            if cleartext:
                self.add(
                    check_id="RH-050",
                    title="Cleartext AUTH mechanisms offered before TLS",
                    severity="CRITICAL" if not self.facts["starttls"] else "HIGH",
                    summary=f"AUTH {' '.join(cleartext)} is advertised on the unencrypted "
                            f"channel (full list: {' '.join(mechs)}).",
                    impact="PLAIN and LOGIN transmit the password base64-encoded, which is "
                           "encoding, not encryption. Any on-path observer - or an attacker who "
                           "strips the STARTTLS capability from the EHLO response - captures "
                           "valid mailbox credentials verbatim.",
                    remediation="Refuse AUTH until the session is encrypted "
                                "(Postfix: `smtpd_tls_auth_only = yes`; Exim: "
                                "`auth_advertise_hosts` gated on `${if def:tls_in_cipher}`), "
                                "and prefer implicit TLS on 465 per RFC 8314.",
                    evidence=self._cap_evidence(),
                    reproduce=[
                        f"printf 'EHLO {self.args.helo}\\r\\nQUIT\\r\\n' | nc {self.host} {self.port}"
                    ],
                    detail={"mechanisms": mechs},
                    references=["RFC 4954 §13.1", "RFC 8314"],
                )
            weak = [m for m in mechs if m in ("CRAM-MD5", "DIGEST-MD5", "NTLM", "MSN", "LOGIN")]
            if weak:
                self.add(
                    check_id="RH-051",
                    title=f"Legacy/weak SASL mechanisms advertised: {', '.join(sorted(set(weak)))}",
                    severity="LOW",
                    summary="The service offers challenge-response mechanisms with known "
                            "cryptographic or design weaknesses.",
                    impact="CRAM-MD5 and DIGEST-MD5 require reversible password storage and are "
                           "offline-crackable from a captured exchange; NTLM is relay-prone.",
                    remediation="Offer only PLAIN over TLS (with strong password storage) or "
                                "SCRAM-SHA-256, and disable the rest.",
                    evidence=self._cap_evidence(),
                    detail={"mechanisms": sorted(set(weak))},
                    references=["RFC 6331 (DIGEST-MD5 obsoleted)"],
                )

        if self.port == 587 and not caps.get("AUTH") and not self.facts.get("ehlo_caps_tls", {}).get("AUTH"):
            self.add(
                check_id="RH-052",
                title="Submission port advertises no AUTH mechanism",
                severity="INFO",
                summary="Port 587 is reachable but never offers AUTH, before or after STARTTLS.",
                impact="Either the port is acting as an unauthenticated relay for a trusted "
                       "network (verify the RH-060 relay result), or submission is misconfigured.",
                remediation="Submission must require authentication per RFC 6409 §4.3.",
                evidence=self._cap_evidence(),
                references=["RFC 6409 §4.3"],
            )

    # ------------------------------------------------------------------ #
    def check_verify_expand(self) -> None:
        start = self.tx.mark()
        w, _ = self._open_session()
        results: Dict[str, Tuple[int, str, str]] = {}
        try:
            for verb, probe in (("VRFY", self.args.enum_user), ("EXPN", "postmaster")):
                try:
                    code, lines = w.cmd(f"{verb} {probe}")
                    results[verb] = (code, lines[0], probe)
                except SMTPError as exc:
                    results[verb] = (-1, str(exc), probe)
        finally:
            self._quiet_quit(w)

        ev = self.tx.slice(start)
        for verb, (code, line, probe) in results.items():
            # 252 == "cannot VRFY but will accept" - explicitly NOT a disclosure.
            if code in (250, 251):
                self.add(
                    check_id="RH-011" if verb == "VRFY" else "RH-012",
                    title=f"{verb} command enabled - address disclosure",
                    severity="MEDIUM",
                    summary=f"`{verb} {probe}` returned `{line}` instead of the 252/502 "
                            "a hardened server should give.",
                    impact="VRFY confirms whether an individual mailbox exists and EXPN expands "
                           "distribution lists to their members. Together they let an attacker "
                           "build an accurate, current list of valid internal recipients for "
                           "phishing, password spraying or spam - without authenticating.",
                    remediation="Disable both verbs (Postfix: `disable_vrfy_command = yes`; "
                                "Exim: leave `acl_smtp_vrfy`/`acl_smtp_expn` denying; "
                                "Sendmail: `PrivacyOptions=noexpn,novrfy`).",
                    evidence=ev,
                    reproduce=[
                        f"printf 'EHLO {self.args.helo}\\r\\n{verb} {probe}\\r\\nQUIT\\r\\n' "
                        f"| nc {self.host} {self.port}"
                    ],
                    references=["RFC 5321 §3.5", "CWE-204"],
                )

    # ------------------------------------------------------------------ #
    def check_dangerous_verbs(self) -> None:
        caps = {**self.facts["ehlo_caps"], **self.facts.get("ehlo_caps_tls", {})}
        ev = self._cap_evidence()

        if "ETRN" in caps:
            self.add(
                check_id="RH-013", title="ETRN advertised to unauthenticated clients",
                severity="LOW",
                summary="The capability list includes ETRN.",
                impact="ETRN lets an unauthenticated peer force the queue to be flushed toward "
                       "an arbitrary domain, which is usable for queue-state probing and as a "
                       "resource-amplification nuisance.",
                remediation="Restrict ETRN to known peers "
                            "(Postfix: `smtpd_etrn_restrictions`) or disable it.",
                evidence=ev, references=["RFC 1985"],
            )
        if "TURN" in caps:
            self.add(
                check_id="RH-014", title="Obsolete TURN command advertised", severity="MEDIUM",
                summary="The service advertises the TURN verb.",
                impact="TURN reverses the client/server roles with no authentication, allowing "
                       "an attacker to claim and collect another domain's queued mail.",
                remediation="Disable TURN; use ETRN or ATRN with authentication if on-demand "
                            "queue release is required.",
                evidence=ev, references=["RFC 1985 (TURN deprecated)"],
            )
        for verb in ("XCLIENT", "XFORWARD"):
            if verb in caps:
                self.add(
                    check_id="RH-015", title=f"{verb} advertised to unauthenticated clients",
                    severity="HIGH",
                    summary=f"The service advertises {verb} in its capability list.",
                    impact=f"{verb} lets the client overwrite the connection's apparent source "
                           "address, hostname and login name. An attacker who can use it "
                           "bypasses IP-based relay and rate-limit policy and forges the "
                           "Received headers used for later attribution.",
                    remediation=f"Limit the {verb} capability to trusted content-filter hosts "
                                f"(Postfix: `smtpd_authorized_{verb.lower()}_hosts`).",
                    evidence=ev,
                    reproduce=[
                        f"printf 'EHLO {self.args.helo}\\r\\nQUIT\\r\\n' | nc {self.host} {self.port}"
                    ],
                )
        if "SIZE" in caps:
            raw = caps.get("SIZE", "").strip()
            if raw.isdigit() and int(raw) == 0:
                self.add(
                    check_id="RH-016", title="No message size limit declared (SIZE 0)",
                    severity="LOW",
                    summary="The SIZE extension advertises an unlimited maximum message size.",
                    impact="Unbounded message size invites disk-exhaustion denial of service.",
                    remediation="Set a realistic `message_size_limit`.",
                    evidence=ev, references=["RFC 1870"],
                )

    # ------------------------------------------------------------------ #
    def check_open_relay(self) -> None:
        """Probe relay acceptance without ever delivering a message.

        Each vector issues MAIL FROM / RCPT TO and is immediately followed by
        RSET. DATA is never sent, so an accepted RCPT proves the policy gap
        without a message ever entering the queue.
        """
        domain = self.args.relay_domain or _guess_domain(self.facts.get("banner", "")) or self.host
        vectors = relay_vectors(domain, self.args.relay_to, self.args.relay_from)
        accepted: List[Dict[str, str]] = []
        tested: List[Dict[str, str]] = []

        start = self.tx.mark()
        self.tx.note(
            "OPEN RELAY probe - non-delivering: MAIL FROM + RCPT TO then RSET, DATA never sent"
        )
        w, _ = self._open_session()
        try:
            for label, mfrom, rcpt in vectors:
                try:
                    code, lines = w.cmd(f"MAIL FROM:{mfrom}")
                    if code not in (250, 251):
                        tested.append({"vector": label, "mail_from": mfrom, "rcpt_to": rcpt,
                                       "result": f"MAIL FROM rejected: {lines[0]}"})
                        w.cmd("RSET")
                        continue
                    code, lines = w.cmd(f"RCPT TO:{rcpt}")
                    entry = {"vector": label, "mail_from": mfrom, "rcpt_to": rcpt,
                             "result": lines[0]}
                    tested.append(entry)
                    if code in (250, 251):
                        accepted.append(entry)
                        self.tx.note(f"!! vector '{label}' ACCEPTED - sending RSET, no DATA")
                    w.cmd("RSET")
                except SMTPError as exc:
                    tested.append({"vector": label, "mail_from": mfrom, "rcpt_to": rcpt,
                                   "result": f"error: {exc}"})
                    # Session probably dead - reopen for the next vector.
                    w.close()
                    try:
                        w, _ = self._open_session()
                    except Exception:
                        break
        finally:
            self._quiet_quit(w)

        self.facts["relay_vectors"] = tested
        ev = self.tx.slice(start)

        if accepted:
            names = ", ".join(a["vector"] for a in accepted)
            self.add(
                check_id="RH-060",
                title=f"Open mail relay - {len(accepted)} vector(s) accepted",
                severity="CRITICAL",
                summary=f"The server accepted an unauthenticated envelope from "
                        f"`{self.args.relay_from}` to the external address "
                        f"`{self.args.relay_to}` via: {names}.",
                impact="Anyone on the internet can send mail through this host to arbitrary "
                       "third parties. In practice that means spam and phishing sent from the "
                       "organisation's own IP and domain reputation, rapid RBL/DNSBL listing "
                       "with knock-on loss of legitimate mail flow, and a trusted-looking "
                       "channel for internal-to-internal phishing.",
                remediation="Reject all relaying for unauthenticated, non-local clients. "
                            "Postfix: `smtpd_recipient_restrictions = permit_mynetworks, "
                            "permit_sasl_authenticated, reject_unauth_destination` and check "
                            "`mynetworks` is not over-broad. Exim: verify the "
                            "`acl_check_rcpt` relay conditions. Then re-test.",
                evidence=ev,
                reproduce=[
                    f"printf 'EHLO {self.args.helo}\\r\\nMAIL FROM:{accepted[0]['mail_from']}\\r\\n"
                    f"RCPT TO:{accepted[0]['rcpt_to']}\\r\\nRSET\\r\\nQUIT\\r\\n' "
                    f"| nc {self.host} {self.port}",
                    f"nmap --script smtp-open-relay -p {self.port} {self.host}",
                ],
                detail={"accepted_vectors": accepted, "all_vectors": tested},
                references=["CWE-269", "RFC 5321 §7.2", "M3AAWG Sender Best Practices"],
            )
        else:
            self.add(
                check_id="RH-061",
                title="Relay restrictions enforced (no vector accepted)",
                severity="INFO",
                summary=f"All {len(tested)} relay vectors were rejected before DATA.",
                impact="No unauthenticated relay path was found from this source address. "
                       "Note that relay policy is frequently source-IP dependent - re-test from "
                       "any network segment that is in scope.",
                remediation="No action required for this control.",
                evidence=ev,
                detail={"all_vectors": tested},
            )

    # ------------------------------------------------------------------ #
    def check_starttls_injection(self) -> None:
        """Detect plaintext command injection across the STARTTLS boundary.

        A correct implementation discards any buffered input at the moment
        STARTTLS is accepted (RFC 3207 §6). A vulnerable one keeps it and
        executes commands the attacker injected in cleartext as though they had
        arrived inside the TLS session - the class of bug behind CVE-2011-0411.
        """
        if not self.facts.get("starttls") or self.facts.get("implicit_tls"):
            return
        start = self.tx.mark()
        w = self._new_wire()
        try:
            w.connect()
            w.read_response()
            self._ehlo(w)
            # Single write: STARTTLS immediately followed by an injected NOOP.
            w.send_raw(b"STARTTLS\r\nNOOP\r\n",
                       "STARTTLS\\r\\nNOOP\\r\\n   (both commands in ONE plaintext packet)")
            code, lines = w.read_response()
            if code != 220:
                self.tx.note("STARTTLS not accepted during injection probe")
                self._quiet_quit(w)
                return
            # Anything still buffered here was answered in cleartext AFTER the
            # server agreed to upgrade. Drain it so it cannot be mistaken for a
            # reply arriving inside the TLS session.
            leaked_plain, w.buf = w.buf, b""
            w.wrap_tls(build_ctx())
            echo = w.pending(wait=min(3.0, self.args.timeout))
            self._quiet_quit(w)

            if echo and echo[:3].isdigit():
                self.add(
                    check_id="RH-070",
                    title="STARTTLS plaintext command injection (buffer not reset)",
                    severity="HIGH",
                    summary="A NOOP injected in the same cleartext packet as STARTTLS was "
                            f"executed inside the TLS session; the server replied `{echo}` "
                            "before the client sent anything.",
                    impact="The pre-TLS input buffer is not discarded on upgrade, so an on-path "
                           "attacker can inject SMTP commands that the server attributes to the "
                           "authenticated, encrypted session - including MAIL FROM/RCPT TO for "
                           "mail the victim never sent, or capturing the victim's AUTH exchange.",
                    remediation="Patch the MTA to a fixed release and confirm the STARTTLS "
                                "handler flushes all buffered input on upgrade, per RFC 3207 §6.",
                    evidence=self.tx.slice(start),
                    reproduce=[
                        "printf 'EHLO probe\\r\\nSTARTTLS\\r\\nNOOP\\r\\n' | "
                        f"openssl s_client -quiet -starttls smtp -connect {self.host}:{self.port}"
                    ],
                    references=["CVE-2011-0411", "CVE-2011-1430", "CVE-2011-1926",
                                "RFC 3207 §6"],
                )
            elif leaked_plain:
                self.add(
                    check_id="RH-071",
                    title="Injected command answered in cleartext after STARTTLS accepted",
                    severity="MEDIUM",
                    summary="The server responded to the injected NOOP on the plaintext channel "
                            "after it had already agreed to upgrade.",
                    impact="The upgrade boundary is not handled atomically, indicating the "
                           "buffer-reset requirement of RFC 3207 is not implemented cleanly. "
                           "Worth manual follow-up for full command injection.",
                    remediation="Review the STARTTLS state machine; discard buffered input at "
                                "the 220 response.",
                    evidence=self.tx.slice(start) +
                             [f"[leak] << {leaked_plain.decode('utf-8','replace').strip()}"],
                    references=["RFC 3207 §6"],
                )
        except Exception as exc:
            self.tx.note(f"STARTTLS injection probe inconclusive: {exc}")
            w.close()

    # ------------------------------------------------------------------ #
    def check_user_enumeration(self) -> None:
        """Opt-in RCPT TO differential enumeration (--enum-users)."""
        if not self.args.enum_users:
            return
        users = list(self.args.userlist or DEFAULT_USERS)
        control = f"rh-{int(time.time())}-nonexistent"
        probes = users + [control]
        domain = self.args.relay_domain or _guess_domain(self.facts.get("banner", "")) or self.host

        start = self.tx.mark()
        self.tx.note(f"USER ENUMERATION probe (opt-in) against domain '{domain}'")
        w, _ = self._open_session()
        results: Dict[str, str] = {}
        try:
            for u in probes:
                try:
                    w.cmd(f"MAIL FROM:<{self.args.relay_from}>")
                    code, lines = w.cmd(f"RCPT TO:<{u}@{domain}>")
                    results[u] = f"{code} {lines[0][4:].strip()}"
                    w.cmd("RSET")
                except SMTPError as exc:
                    results[u] = f"error: {exc}"
                    break
        finally:
            self._quiet_quit(w)

        baseline = results.get(control, "")
        differing = {u: r for u, r in results.items()
                     if u != control and r and r[:3] != baseline[:3]}
        self.facts["user_enum"] = results
        if differing:
            self.add(
                check_id="RH-017",
                title="Recipient validation leaks valid mailboxes (RCPT differential)",
                severity="MEDIUM",
                summary=f"{len(differing)} of {len(users)} probed local-parts produced a "
                        f"different response code than the known-invalid control address "
                        f"`{control}@{domain}` (`{baseline}`).",
                impact="An unauthenticated attacker can enumerate valid mailboxes at line rate "
                       "and use the result to target phishing and credential stuffing at real "
                       "users only, raising success rate and lowering detection.",
                remediation="Return an identical response for valid and invalid recipients at "
                            "RCPT time (accept-then-bounce is not recommended either - prefer "
                            "uniform rejection plus rate limiting and greylisting on repeated "
                            "unknown recipients).",
                evidence=self.tx.slice(start),
                detail={"responses": results, "differing": differing},
                references=["CWE-204", "OWASP WSTG-IDNT-04"],
            )

    # ------------------------------------------------------------------ #
    def check_dns_posture(self) -> None:
        """Optional email-authentication posture for the target domain (--dns)."""
        if not self.args.dns:
            return
        domain = self.args.relay_domain or _guess_domain(self.facts.get("banner", "")) or self.host
        if _is_ip(domain):
            return
        if not HAVE_DNSPYTHON:
            self.tx.note("--dns requested but dnspython is not installed; skipping")
            return

        ev: List[str] = [f"[dns] zone under test: {domain}"]

        def q(name: str, rr: str = "TXT") -> List[str]:
            try:
                ans = dns.resolver.resolve(name, rr, lifetime=self.args.timeout)
                out = []
                for r in ans:
                    s = r.to_text().strip('"').replace('" "', "")
                    out.append(s)
                    ev.append(f"[dns] {rr} {name} -> {s}")
                return out
            except Exception as exc:
                ev.append(f"[dns] {rr} {name} -> {type(exc).__name__}")
                return []

        spf = [t for t in q(domain) if t.lower().startswith("v=spf1")]
        dmarc = [t for t in q(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
        mtasts = [t for t in q(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]

        if not spf:
            self.add(
                check_id="RH-080", title="No SPF record published", severity="MEDIUM",
                summary=f"`{domain}` publishes no `v=spf1` TXT record.",
                impact="Receivers have no authorised-sender list for the domain, so mail "
                       "spoofing its addresses passes a basic authentication check.",
                remediation="Publish an SPF record ending in `-all` once the legitimate "
                            "senders are inventoried.",
                evidence=ev, references=["RFC 7208"],
            )
        else:
            rec = spf[0]
            if rec.rstrip().endswith("+all") or " +all" in rec or rec.rstrip().endswith(" all"):
                self.add(
                    check_id="RH-081", title="SPF record permits any sender (+all)",
                    severity="HIGH",
                    summary=f"SPF for `{domain}` ends with a permissive `all` mechanism: `{rec}`",
                    impact="The record explicitly authorises the entire internet to send as this "
                           "domain, which is worse than publishing nothing because it can cause "
                           "receivers to pass spoofed mail.",
                    remediation="Replace the terminal mechanism with `-all` (or `~all` while "
                                "monitoring).",
                    evidence=ev, references=["RFC 7208 §5.1"],
                )
            elif rec.rstrip().endswith("?all"):
                self.add(
                    check_id="RH-082", title="SPF policy is neutral (?all)", severity="LOW",
                    summary=f"SPF for `{domain}` ends in `?all`: `{rec}`",
                    impact="A neutral result gives receivers no basis to reject spoofed mail.",
                    remediation="Move to `~all` then `-all`.",
                    evidence=ev, references=["RFC 7208"],
                )

        if not dmarc:
            self.add(
                check_id="RH-083", title="No DMARC record published", severity="MEDIUM",
                summary=f"`_dmarc.{domain}` returns no `v=DMARC1` record.",
                impact="Without DMARC there is no alignment requirement and no reporting, so "
                       "direct-domain spoofing of this organisation is unconstrained and "
                       "invisible.",
                remediation="Publish `v=DMARC1; p=none; rua=mailto:...` first, review the "
                            "aggregate reports, then progress to `p=quarantine` and `p=reject`.",
                evidence=ev, references=["RFC 7489"],
            )
        elif "p=none" in dmarc[0].replace(" ", "").lower():
            self.add(
                check_id="RH-084", title="DMARC policy is monitoring-only (p=none)",
                severity="LOW",
                summary=f"DMARC for `{domain}`: `{dmarc[0]}`",
                impact="Receivers are told to take no action on unaligned mail, so spoofed "
                       "messages are still delivered to recipients.",
                remediation="Advance to `p=quarantine` and then `p=reject` once aggregate "
                            "reports show legitimate sources are aligned.",
                evidence=ev, references=["RFC 7489 §6.3"],
            )

        if not mtasts:
            self.add(
                check_id="RH-085", title="No MTA-STS policy published", severity="LOW",
                summary=f"`_mta-sts.{domain}` returns no policy record.",
                impact="Sending MTAs cannot distinguish a genuine STARTTLS failure from an "
                       "active downgrade attack, so opportunistic TLS remains strippable.",
                remediation="Publish an MTA-STS policy (and consider DANE/TLSA if the zone is "
                            "DNSSEC-signed).",
                evidence=ev, references=["RFC 8461", "RFC 7672"],
            )


DEFAULT_USERS = [
    "root", "admin", "administrator", "postmaster", "webmaster", "info",
    "support", "sales", "test", "user", "mail", "backup", "hr", "finance",
]


def _is_ip(value: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, value)
            return True
        except OSError:
            continue
    return False


def _guess_domain(banner: str) -> str:
    """Extract the server's own hostname from its 220 greeting."""
    m = re.match(r"220[- ]([A-Za-z0-9._-]+)", banner or "")
    if not m:
        return ""
    host = m.group(1)
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else host


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
LEGAL_NOTICE = (
    "This report was produced by an automated auditing tool. It records only what the "
    "target voluntarily disclosed over the SMTP protocol. No message was ever queued or "
    "delivered: every relay vector stops at `RCPT TO` and is followed by `RSET`, and the "
    "`DATA` command is never issued. Findings should be confirmed manually before being "
    "acted on, and testing must only be performed against systems you are authorised in "
    "writing to assess."
)


def md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def build_markdown(results: List[SMTPAuditor], args: argparse.Namespace) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    all_findings: List[Finding] = [f for r in results for f in r.findings]
    counts = {s: sum(1 for f in all_findings if f.severity == s) for s in SEV_ORDER}
    actionable = [f for f in all_findings if f.severity != "INFO"]

    out: List[str] = []
    A = out.append

    A(f"# {__toolname__} SMTP Security Assessment")
    A("")
    A(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    A(f"**Tool:** {__toolname__} v{__version__}  ")
    A(f"**Operator HELO identity:** `{args.helo}`  ")
    A(f"**Mode:** {'intrusive checks enabled' if args.enum_users else 'safe / non-delivering'}  ")
    A(f"**Targets:** {len(results)} endpoint(s)")
    A("")
    A("---")
    A("")

    # ---- executive summary ---- #
    A("## 1. Executive summary")
    A("")
    A("| Severity | Count |")
    A("|---|---|")
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        A(f"| {s.title()} | {counts.get(s, 0)} |")
    A("")
    if not actionable:
        A("No issues above informational severity were identified on the endpoints tested. "
          "Note that SMTP policy is frequently source-address dependent; a clean result from "
          "one network position does not generalise to all of them.")
    else:
        worst = min(actionable, key=lambda f: f.rank)
        A(f"{len(actionable)} actionable finding(s) were identified across "
          f"{len({f.target for f in actionable})} endpoint(s). The highest-severity issue is "
          f"**{worst.severity}: {worst.title}** on `{worst.target}`.")
    A("")

    # ---- scope ---- #
    A("## 2. Scope and reachability")
    A("")
    A("| Endpoint | Reachable | ESMTP | STARTTLS | Implicit TLS | Findings |")
    A("|---|---|---|---|---|---|")
    for r in results:
        f = r.facts
        A("| `{t}` | {reach} | {esmtp} | {stls} | {itls} | {n} |".format(
            t=r.target,
            reach="yes" if f["reachable"] else f"no ({f.get('error') or 'unknown'})",
            esmtp="yes" if f.get("esmtp") else "no",
            stls="yes" if f.get("starttls") else "no",
            itls="yes" if f.get("implicit_tls") else "no",
            n=len([x for x in r.findings if x.severity != "INFO"]),
        ))
    A("")

    # ---- findings index ---- #
    A("## 3. Findings index")
    A("")
    if all_findings:
        A("| # | Severity | ID | Finding | Endpoint |")
        A("|---|---|---|---|---|")
        for i, f in enumerate(sorted(all_findings, key=lambda x: (x.rank, x.target)), 1):
            A(f"| {i} | **{f.severity}** | {f.check_id} | {md_escape(f.title)} | `{f.target}` |")
    else:
        A("_No findings recorded._")
    A("")

    # ---- detail ---- #
    A("## 4. Findings detail")
    A("")
    if not all_findings:
        A("_Nothing to report._")
    for i, f in enumerate(sorted(all_findings, key=lambda x: (x.rank, x.target)), 1):
        A(f"### 4.{i} [{f.severity}] {f.title}")
        A("")
        A("| Field | Value |")
        A("|---|---|")
        A(f"| **Check ID** | `{f.check_id}` |")
        A(f"| **Severity** | {f.severity} |")
        A(f"| **Endpoint** | `{f.target}` |")
        A("")
        A("**Description**")
        A("")
        A(f.summary)
        A("")
        A("**Impact**")
        A("")
        A(f.impact)
        A("")
        if f.evidence:
            A("**Evidence** — captured wire transcript")
            A("")
            A("```text")
            for line in f.evidence:
                A(line)
            A("```")
            A("")
        if f.detail:
            A("<details><summary>Structured detail</summary>")
            A("")
            A("```json")
            A(_json_dump(f.detail))
            A("```")
            A("")
            A("</details>")
            A("")
        if f.reproduce:
            A("**Manual reproduction**")
            A("")
            A("```bash")
            for line in f.reproduce:
                A(line)
            A("```")
            A("")
        A("**Remediation**")
        A("")
        A(f.remediation)
        A("")
        if f.references:
            A("**References:** " + " · ".join(f.references))
            A("")
        A("---")
        A("")

    # ---- service detail ---- #
    A("## 5. Service detail")
    A("")
    for r in results:
        f = r.facts
        A(f"### `{r.target}`")
        A("")
        if f.get("error"):
            A(f"Not assessed: `{f['error']}`")
            A("")
            continue
        A(f"- **Banner:** `{f.get('banner','')}`")
        caps = f.get("ehlo_caps") or {}
        A(f"- **EHLO capabilities ({len(caps)}):** " +
          (", ".join(f"`{k}{(' ' + v) if v else ''}`" for k, v in caps.items()) or "_none_"))
        if f.get("ehlo_caps_tls"):
            A(f"- **Capabilities after STARTTLS:** " +
              ", ".join(f"`{k}`" for k in f["ehlo_caps_tls"]))
        tls = f.get("tls") or {}
        if tls:
            A(f"- **TLS negotiated:** {tls.get('protocol')} / {tls.get('cipher')} "
              f"/ {tls.get('cipher_bits')} bits")
        if f.get("tls_versions"):
            A("- **Protocol support:** " + ", ".join(
                f"{k}={'yes' if v else 'no'}" for k, v in f["tls_versions"].items()))
        cert = f.get("cert") or {}
        if cert.get("parsed"):
            A(f"- **Certificate subject:** `{cert['subject']}`")
            A(f"- **Certificate issuer:** `{cert['issuer']}`")
            A(f"- **Validity:** {cert['not_before'].date()} → {cert['not_after'].date()}")
            A(f"- **Key / signature:** {cert['key_type']} {cert['key_size']} bits, "
              f"{cert['sig_hash']}")
            A(f"- **SHA-256 fingerprint:** `{cert['fingerprint_sha256']}`")
        A("")

    # ---- appendix ---- #
    A("## 6. Appendix — full session transcripts")
    A("")
    A("Complete, unedited record of each audit session. `>>` is client-to-server, "
      "`<<` is server-to-client, `**` is a tool annotation.")
    A("")
    for r in results:
        A(f"<details><summary><code>{r.target}</code> — full transcript</summary>")
        A("")
        A("```text")
        for line in r.tx.render_all():
            A(line)
        A("```")
        A("")
        A("</details>")
        A("")

    A("## 7. Methodology and legal notice")
    A("")
    A(LEGAL_NOTICE)
    A("")
    A("**Relay methodology.** Nine envelope-manipulation vectors are attempted "
      "(external→external, null sender, spoofed local sender, percent-hack, bang-path, "
      "source-route, quoted address, trailing-dot domain, and bracket-less addressing). "
      "A `2xx` response to `RCPT TO` is treated as proof of "
      "acceptance; the session is immediately reset. Relay policy commonly depends on the "
      "client's source address, so results should be reproduced from every network position "
      "that is in scope.")
    A("")
    return "\n".join(out)


def _json_dump(obj: Any) -> str:
    import json

    def default(o: Any) -> str:
        if isinstance(o, (dt.datetime, dt.date)):
            return o.isoformat()
        if isinstance(o, bytes):
            return o.hex()
        return str(o)

    return json.dumps(obj, indent=2, default=default)


def build_json(results: List[SMTPAuditor]) -> str:
    payload = {
        "tool": __toolname__,
        "version": __version__,
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
        "targets": [
            {
                "target": r.target,
                "facts": {k: v for k, v in r.facts.items() if k != "cert"},
                "certificate": {k: v for k, v in (r.facts.get("cert") or {}).items()
                                if k != "pem"},
                "findings": [dataclasses.asdict(f) for f in r.findings],
                "transcript": r.tx.render_all(),
            }
            for r in results
        ],
    }
    return _json_dump(payload)


# --------------------------------------------------------------------------- #
# Console output
# --------------------------------------------------------------------------- #
def print_console(r: SMTPAuditor) -> None:
    print(c(f"\n[*] {r.target}", "BOLD"))
    if r.facts.get("error"):
        print(f"    {c('unreachable', 'DIM')}: {r.facts['error']}")
        return
    print(f"    banner  : {r.facts.get('banner','')}")
    caps = ", ".join(r.facts.get("ehlo_caps", {}).keys()) or "(none)"
    print(f"    ehlo    : {caps}")
    tls = r.facts.get("tls") or {}
    if tls:
        print(f"    tls     : {tls.get('protocol')} / {tls.get('cipher')}")
    if not r.findings:
        print(c("    no findings", "OK"))
    for f in r.findings:
        print(f"    {c(f'[{f.severity:8}]', f.severity)} {f.check_id}  {f.title}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
BANNER_ART = r"""
   ___     _         _  _                 _
  | _ \___| |__ _ _ _| || |___ _  _ _ _  _| |
  |   / -_) / _` | || | __ / _ \ || | ' \/ _` |
  |_|_\___|_\__,_|\_, |_||_\___/\_,_|_||_\__,_|
                  |__/   SMTP posture auditor
"""


def parse_targets(args: argparse.Namespace) -> List[Tuple[str, int]]:
    hosts: List[str] = list(args.target or [])
    if args.target_file:
        with open(args.target_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.append(line)
    pairs: List[Tuple[str, int]] = []
    for h in hosts:
        if "]" in h and h.startswith("["):  # [::1]:25
            host, _, p = h.rpartition("]:")
            pairs.append((host.lstrip("["), int(p)))
            continue
        if h.count(":") == 1 and not _is_ip(h):
            host, _, p = h.partition(":")
            if p.isdigit():
                pairs.append((host, int(p)))
                continue
        for port in args.ports:
            pairs.append((h, port))
    # de-duplicate, preserve order
    seen = set()
    out = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def parse_ports(spec: str) -> List[int]:
    ports: List[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, _, b = chunk.partition("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(chunk))
    return ports


def main(argv: Optional[Sequence[str]] = None) -> int:
    global USE_COLOR

    ap = argparse.ArgumentParser(
        prog="relayhound",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{__toolname__} v{__version__} - SMTP posture auditor with "
                    f"evidence-grade Markdown reporting.",
        epilog=textwrap.dedent("""\
            examples:
              relayhound.py -t mail.example.com -o report.md
              relayhound.py -t 10.0.0.5 -p 25,465,587,2525 --dns -o report.md
              relayhound.py -T scope.txt --threads 8 -o engagement.md --json findings.json
              relayhound.py -t mail.example.com --enum-users --userlist users.txt -o report.md

            Only test systems you are explicitly authorised to assess.
        """),
    )
    ap.add_argument("-t", "--target", action="append",
                    help="target host, or host:port (repeatable)")
    ap.add_argument("-T", "--target-file", help="file of targets, one per line")
    ap.add_argument("-p", "--ports", default="25,465,587,2525",
                    help="ports to test when none is given per-target (default: %(default)s)")
    ap.add_argument("--implicit-tls-ports", default="465",
                    help="ports treated as implicit TLS / SMTPS (default: %(default)s)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="socket timeout in seconds (default: %(default)s)")
    ap.add_argument("--threads", type=int, default=4,
                    help="concurrent endpoints (default: %(default)s)")
    ap.add_argument("--helo", default="relayhound.test",
                    help="HELO/EHLO identity to present (default: %(default)s)")
    ap.add_argument("--relay-from", default="audit@example.org",
                    help="envelope sender for relay probes (default: %(default)s)")
    ap.add_argument("--relay-to", default="relay-test@example.net",
                    help="external recipient for relay probes; RFC 2606 reserved domain by "
                         "default so nothing is ever deliverable (default: %(default)s)")
    ap.add_argument("--relay-domain",
                    help="domain to treat as local to the target (default: derived from banner)")
    ap.add_argument("--enum-users", action="store_true",
                    help="INTRUSIVE: RCPT TO differential mailbox enumeration")
    ap.add_argument("--userlist", type=lambda p: [l.strip() for l in open(p) if l.strip()],
                    help="file of local-parts for --enum-users")
    ap.add_argument("--enum-user", default="root",
                    help="single local-part used for the VRFY probe (default: %(default)s)")
    ap.add_argument("--dns", action="store_true",
                    help="also assess SPF / DMARC / MTA-STS for the target domain "
                         "(requires dnspython)")
    ap.add_argument("-o", "--output", default="relayhound-report.md",
                    help="Markdown report path (default: %(default)s)")
    ap.add_argument("--json", dest="json_output",
                    help="additionally write machine-readable findings to this path")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress console findings")
    ap.add_argument("-V", "--version", action="version",
                    version=f"{__toolname__} {__version__}")

    args = ap.parse_args(argv)

    USE_COLOR = not args.no_color and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"

    if not args.target and not args.target_file:
        ap.error("at least one of --target/--target-file is required")

    args.ports = parse_ports(args.ports)
    args.implicit_ports = set(parse_ports(args.implicit_tls_ports))

    if "@" not in args.relay_to or "@" not in args.relay_from:
        ap.error("--relay-to and --relay-from must be full email addresses")

    targets = parse_targets(args)
    if not args.quiet:
        print(c(BANNER_ART, "BOLD"))
        print(c("  Authorised testing only. Relay probes never issue DATA.\n", "DIM"))
        print(f"  {len(targets)} endpoint(s) queued, {args.threads} worker(s)\n")

    results: List[SMTPAuditor] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        futs = {}
        for host, port in targets:
            auditor = SMTPAuditor(host, port, args)
            futs[pool.submit(auditor.run)] = auditor
        for fut in concurrent.futures.as_completed(futs):
            auditor = futs[fut]
            try:
                fut.result()
            except Exception as exc:  # noqa: BLE001
                auditor.facts["error"] = f"{type(exc).__name__}: {exc}"
            results.append(auditor)
            if not args.quiet:
                print_console(auditor)

    results.sort(key=lambda r: (r.host, r.port))

    report = build_markdown(results, args)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as fh:
            fh.write(build_json(results))

    total = sum(len([f for f in r.findings if f.severity != "INFO"]) for r in results)
    crit = sum(len([f for f in r.findings if f.severity in ("CRITICAL", "HIGH")])
               for r in results)
    if not args.quiet:
        print()
        print(c(f"[+] Report written to {args.output}", "OK"))
        if args.json_output:
            print(c(f"[+] JSON written to {args.json_output}", "OK"))
        print(f"[+] {total} actionable finding(s), {crit} high or critical")

    return 2 if crit else (1 if total else 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
