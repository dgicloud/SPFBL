"""Normalize private Exim signal snapshots and pseudonymize local SPFBL tickets.

This module is Python 3.6 compatible for older cPanel hosts. It has no network,
mail-content, DNS, or provider dependencies.
"""
from __future__ import print_function

import hashlib
import hmac
import os
import re
import stat


METADATA_KEY_PATH = "/etc/had-antispam/signals-hmac.key"
METADATA_KEY_BYTES = 32
TICKET_TOKEN = re.compile(r"^[A-Za-z0-9_-]{44,512}$")
FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")
EXIM_SIGNAL_FIELDS = (
    "spf_result",
    "dkim_verify_status",
    "dmarc_status",
    "dmarc_alignment_spf",
    "dmarc_alignment_dkim",
    "spfbl_decision",
    "rspamd_bucket",
    "reverse_dns_valid",
    "authenticated_smtp",
    "tls_in_cipher",
)

_ENUMS = {
    "spf": frozenset(("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror", "invalid", "unknown")),
    "dkim": frozenset(("pass", "fail", "invalid", "none", "unknown")),
    "dmarc": frozenset(("accept", "reject", "quarantine", "none", "norecord", "nofrom", "temperror", "off", "unknown")),
    "spfbl": frozenset(("pass", "white", "accept", "flag", "greylist", "hold", "listed", "blocked", "fail", "softfail", "neutral", "none", "spamtrap", "nxdomain", "invalid", "lan", "inexistent", "nxsender", "banned", "unknown")),
    "rspamd": frozenset(("below_threshold", "borderline", "above_threshold", "unknown")),
    "dmarc_alignment_spf": frozenset(("aligned", "misaligned", "none", "unknown")),
    "dmarc_alignment_dkim": frozenset(("aligned", "misaligned", "none", "unknown")),
}
_ENUM_NAMES = (
    "spf", "dkim", "dmarc", "spfbl", "rspamd",
    "dmarc_alignment_spf", "dmarc_alignment_dkim",
)
SIGNAL_NAMES = _ENUM_NAMES + ("reverse_dns_valid", "authenticated_smtp", "smtp_tls")
_SIGNAL_NAMES = SIGNAL_NAMES
_SIGNAL_FIELDS = frozenset(_SIGNAL_NAMES)
_MANUAL_FEEDBACK_DECISIONS = frozenset(("pass", "white", "flag", "hold", "softfail", "neutral", "none"))
MANUAL_FEEDBACK_DECISIONS = _MANUAL_FEEDBACK_DECISIONS


class SignalError(ValueError):
    """Invalid or unavailable local technical-signal data."""


def _enum(value, allowed, aliases=None):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 256:
        return "unknown"
    normalized = value.strip().lower()
    if aliases:
        normalized = aliases.get(normalized, normalized)
    return normalized if normalized in allowed else "unknown"


def _bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes"):
            return True
        if normalized in ("0", "false", "no"):
            return False
    return None


def _dkim(value):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 256 or not value.strip():
        return "unknown"
    statuses = [part.strip().lower() for part in value.split(":")]
    if not statuses or any(status not in ("pass", "fail", "invalid", "none") for status in statuses):
        return "unknown"
    return statuses[0] if len(set(statuses)) == 1 else "unknown"


def normalize_exim_signals(snapshot):
    """Return only the fixed Jev schema; never preserve raw Exim values."""
    if not hasattr(snapshot, "keys"):
        raise SignalError("signal_snapshot_invalid")
    if set(snapshot) - set(EXIM_SIGNAL_FIELDS):
        raise SignalError("signal_snapshot_has_unsupported_fields")
    tls = snapshot.get("tls_in_cipher")
    parsed_tls = _bool(tls)
    if parsed_tls is None and isinstance(tls, str):
        parsed_tls = bool(tls.strip()) if len(tls.encode("utf-8")) <= 256 else None
    spf_aliases = {"(invalid)": "invalid"}
    return {
        "spf": _enum(snapshot.get("spf_result"), _ENUMS["spf"], spf_aliases),
        "dkim": _dkim(snapshot.get("dkim_verify_status")),
        "dmarc": _enum(snapshot.get("dmarc_status"), _ENUMS["dmarc"]),
        "dmarc_alignment_spf": _alignment(snapshot.get("dmarc_alignment_spf")),
        "dmarc_alignment_dkim": _alignment(snapshot.get("dmarc_alignment_dkim")),
        "spfbl": _enum(snapshot.get("spfbl_decision"), _ENUMS["spfbl"]),
        "rspamd": _enum(snapshot.get("rspamd_bucket"), _ENUMS["rspamd"]),
        "reverse_dns_valid": _bool(snapshot.get("reverse_dns_valid")),
        "authenticated_smtp": _bool(snapshot.get("authenticated_smtp")),
        "smtp_tls": parsed_tls,
    }


def _alignment(value):
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower()
    if normalized == "yes":
        return "aligned"
    if normalized == "no":
        return "misaligned"
    return "unknown"


def validate_signal_state(state):
    if not hasattr(state, "keys") or set(state) != _SIGNAL_FIELDS:
        raise SignalError("signal_state_invalid")
    clean = {}
    for name in _SIGNAL_NAMES:
        value = state[name]
        if name in _ENUMS:
            if not isinstance(value, str) or value not in _ENUMS[name]:
                raise SignalError("signal_state_invalid")
            clean[name] = value
        else:
            if value is not None and not isinstance(value, bool):
                raise SignalError("signal_state_invalid")
            clean[name] = value
    return clean


def ticket_fingerprint(ticket, key):
    if not isinstance(ticket, str) or not TICKET_TOKEN.fullmatch(ticket):
        raise SignalError("signal_ticket_invalid")
    if not isinstance(key, bytes) or len(key) != METADATA_KEY_BYTES:
        raise SignalError("signal_key_invalid")
    return hmac.new(key, ticket.encode("ascii"), hashlib.sha256).hexdigest()


def format_signal_event(ticket, key, state):
    """Format an identity-free syslog record using one keyed ticket fingerprint."""
    clean = validate_signal_state(state)
    fingerprint = ticket_fingerprint(ticket, key)
    values = []
    for name in _SIGNAL_NAMES:
        value = clean[name]
        if value is None:
            value = "unknown"
        elif isinstance(value, bool):
            value = "true" if value else "false"
        values.append(name + "=" + value)
    return "had-antispam-signals signal_id={} {}".format(fingerprint, " ".join(values))


def parse_signal_event_line(line):
    """Parse one exact local signal event, returning no source log text."""
    if not isinstance(line, str) or len(line) > 1024:
        return None
    marker = "had-antispam-signals "
    position = line.find(marker)
    if position < 0:
        return None
    fields = line[position:].strip().split()
    if len(fields) != len(_SIGNAL_NAMES) + 2 or fields[0] != "had-antispam-signals":
        return None
    identity_name, separator, signal_id = fields[1].partition("=")
    if identity_name != "signal_id" or not separator or not FINGERPRINT.fullmatch(signal_id):
        return None
    parsed = {}
    for expected_name, field in zip(_SIGNAL_NAMES, fields[2:]):
        name, separator, value = field.partition("=")
        if name != expected_name or not separator:
            return None
        if expected_name in _ENUMS:
            parsed[expected_name] = value
        else:
            parsed[expected_name] = {"true": True, "false": False, "unknown": None}.get(value, "invalid")
            if parsed[expected_name] == "invalid":
                return None
    try:
        return signal_id, validate_signal_state(parsed)
    except SignalError:
        return None


def load_metadata_key(path=METADATA_KEY_PATH, enforce_root_permissions=True):
    """Load the cPanel-local correlation key; never create it from the daemon."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise SignalError("signal_key_unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SignalError("signal_key_invalid")
        if enforce_root_permissions and os.name == "posix":
            try:
                expected_gid = __import__("grp").getgrnam("mail").gr_gid
                parent = os.stat(os.path.dirname(os.path.abspath(path)))
            except (KeyError, OSError) as exc:
                raise SignalError("signal_key_permissions_invalid") from exc
            if (info.st_uid != 0 or info.st_gid != expected_gid
                    or stat.S_IMODE(info.st_mode) != 0o640
                    or parent.st_uid != 0 or parent.st_gid != expected_gid
                    or stat.S_IMODE(parent.st_mode) != 0o750):
                raise SignalError("signal_key_permissions_invalid")
        key = os.read(descriptor, METADATA_KEY_BYTES + 1)
        if len(key) != METADATA_KEY_BYTES:
            raise SignalError("signal_key_invalid")
        return key
    finally:
        os.close(descriptor)


def ensure_metadata_key(path=METADATA_KEY_PATH, enforce_root_permissions=True):
    """Create the group-readable key once during root installation, if absent."""
    try:
        return load_metadata_key(path, enforce_root_permissions)
    except SignalError as exc:
        if exc.args != ("signal_key_unavailable",):
            raise
    if enforce_root_permissions and os.name == "posix":
        try:
            group_id = __import__("grp").getgrnam("mail").gr_gid
        except KeyError as exc:
            raise SignalError("signal_key_permissions_invalid") from exc
    else:
        group_id = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o640 if enforce_root_permissions else 0o600)
    except FileExistsError:
        return load_metadata_key(path, enforce_root_permissions)
    except OSError as exc:
        raise SignalError("signal_key_unavailable") from exc
    try:
        if enforce_root_permissions and os.name == "posix":
            os.fchown(descriptor, 0, group_id)
            os.fchmod(descriptor, 0o640)
        key = os.urandom(METADATA_KEY_BYTES)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise SignalError("signal_key_unavailable") from exc
    return load_metadata_key(path, enforce_root_permissions)
