"""guardctl command implementations. `bin/guardctl` is the thin entry point
that parses argv and calls run(); everything here is written to be called
directly from tests too, with all paths injected via a GuardCtx.
"""
from __future__ import annotations

import getpass
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from dg_policy.hosts import normalize_host
from dg_policy.model import PolicyStore
from dg_policy.text import tokens as tokenize
from guardctl import auth, compile as compile_mod, notify
from guardctl.registry import Kind, all_commands, command, get, kind_of
from guardctl.state import StateDir

MAX_TEMP_ALLOW_MINUTES = 240


def _write_json_for_proxy(p: Path, data) -> None:
    """Atomically write a JSON file the proxy (group distraction-guard) must
    be able to read: mode 0640, group copied from the directory.

    Found live: write_terms used to finish with chmod(parent, 0o750), which
    silently CLEARED the directory's setgid bit. From the second add-term
    on, the replacement file took root's group instead of distraction-guard,
    the proxy hit EACCES, and kept running its last-good policy -- none of
    the new terms were ever enforced. Never touch the directory's mode, and
    set the group explicitly rather than relying on setgid."""
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, 0o640)
    try:
        os.chown(tmp, -1, p.parent.stat().st_gid)
    except PermissionError:
        pass  # not root (tests); setgid on the real directory still applies
    os.replace(tmp, p)


class GuardError(Exception):
    """User-facing error: printed to stderr, exits nonzero, no traceback."""


@dataclass
class GuardCtx:
    """Every path guardctl touches, injected so tests never hit the real
    filesystem. Production defaults match the layout in the plan."""
    etc_dir: str = "/etc/distraction-guard"
    local_dir: str = "/etc/distraction-guard/local"
    private_dir: str = "/etc/distraction-guard/private"
    lists_dir: str = "/var/lib/distraction-guard/lists"
    lexicon_path: str = "/usr/local/lib/distraction-guard/lexicon/context.txt"
    compiled_policy_path: str = "/var/lib/distraction-guard/compiled/policy.json"
    state_dir: str = "/var/lib/distraction-guard/state"
    firefox_policy_path: str = "/etc/firefox/policies/policies.json"
    ca_path: str = "/etc/distraction-guard/ca.pem"
    nft_path: str = "/var/lib/distraction-guard/compiled/guard.nft"
    decision_log_path: str = "/var/log/distraction-guard/proxy/decisions.jsonl"
    dnsmasq_always_on_path: str = "/etc/NetworkManager/dnsmasq.d/distraction-guard.conf"
    # Staged OUTSIDE dnsmasq.d on purpose: NetworkManager starts dnsmasq with
    # --conf-dir=/etc/NetworkManager/dnsmasq.d, which loads every file there
    # regardless of suffix -- the old ".conf.off" copy was silently live,
    # sinkholing ~90k domains (reddit.com included) even in shadow mode.
    # dg-watchdog copies it into dnsmasq.d only while degraded.
    dnsmasq_sinkhole_off_path: str = "/var/lib/distraction-guard/compiled/dnsmasq-sinkhole.conf"
    sudo_user: str | None = field(default_factory=lambda: os.environ.get("SUDO_USER"))
    code_reader: "object" = None  # callable() -> str; defaults to getpass on /dev/tty
    notifier: "object" = None  # callable(title, body); defaults to notify.enqueue
    resolver: "object" = None  # callable(hostname) -> (v4_list, v6_list); defaults to real DNS
    lock_sys: "object" = None  # guardctl.lock.Sys; defaults to the real system

    def __post_init__(self):
        self.state = StateDir(self.state_dir)

    # --- local/*.json overlay helpers -----------------------------------

    def _local_path(self, name: str) -> Path:
        return Path(self.local_dir) / name

    def read_local_list(self, name: str) -> list:
        p = self._local_path(name)
        if not p.exists():
            return []
        return json.loads(p.read_text())

    def read_local_dict(self, name: str) -> dict:
        p = self._local_path(name)
        if not p.exists():
            return {}
        return json.loads(p.read_text())

    def write_local_dict(self, name: str, data: dict) -> None:
        _write_json_for_proxy(self._local_path(name), data)

    def write_local_list(self, name: str, data: list) -> None:
        _write_json_for_proxy(self._local_path(name), data)

    # --- terms (private, separate from local/*.json) ---------------------

    def _terms_path(self) -> Path:
        return Path(self.private_dir) / "terms.json"

    def read_terms(self) -> list[dict]:
        p = self._terms_path()
        if not p.exists():
            return []
        return json.loads(p.read_text())

    def write_terms(self, terms: list[dict]) -> None:
        _write_json_for_proxy(self._terms_path(), terms)

    def next_term_id(self, terms: list[dict]) -> str:
        nums = [int(t["id"].split("-")[1]) for t in terms if t["id"].startswith("T-")]
        return f"T-{(max(nums) + 1) if nums else 1:04d}"

    # --- compile -----------------------------------------------------------

    def recompile(self) -> dict:
        sources = compile_mod.load_sources_from_disk(
            etc_dir=self.etc_dir,
            local_dir=self.local_dir,
            lists_dir=self.lists_dir,
            terms_path=str(self._terms_path()),
            lexicon_path=self.lexicon_path,
            health_token_path=str(Path(self.private_dir) / "health.token"),
        )
        return compile_mod.compile_policy(sources, self.compiled_policy_path)

    def current_policy(self):
        store = PolicyStore(self.compiled_policy_path)
        store.refresh(force=True)
        return store.policy

    def write_assets(self, raw_policy: dict) -> dict:
        """Renders and writes nft/dnsmasq/firefox from the just-compiled
        policy. Does real DNS resolution and reads the real Firefox
        policies.json -- called from _refresh (periodic) and install.sh
        (initial), never from unit tests directly (see test_assets.py,
        which exercises guardctl.assets with an injected resolver)."""
        from guardctl.assets import AssetPaths, write_assets as _write_assets

        policy_toml = compile_mod._read_toml(Path(self.etc_dir) / "policy.toml")
        lists_toml_path = Path(self.etc_dir) / "lists.toml"
        catalog = []
        if lists_toml_path.exists():
            catalog = compile_mod._read_toml(lists_toml_path).get("list", [])

        existing_firefox = None
        ff_path = Path(self.firefox_policy_path)
        if ff_path.exists():
            existing_firefox = ff_path.read_text()

        paths = AssetPaths(
            nft_path=self.nft_path,
            dnsmasq_always_on_path=self.dnsmasq_always_on_path,
            dnsmasq_sinkhole_off_path=self.dnsmasq_sinkhole_off_path,
            firefox_policy_path=self.firefox_policy_path,
            ca_path=self.ca_path,
            resolved_cache_path=str(Path(self.state_dir) / "resolved.json"),
        )
        kwargs = {}
        if self.resolver is not None:
            kwargs["resolver"] = self.resolver
        return _write_assets(
            raw_policy, catalog,
            paths=paths,
            ssh_allow_hostnames=policy_toml.get("ssh_allow", []),
            lan_tcp_ports=policy_toml.get("lan_tcp_ports", []),
            critical_direct_hostnames=policy_toml.get("critical_direct", []),
            existing_firefox_json=existing_firefox,
            **kwargs,
        )

    # --- auth / audit / notify --------------------------------------------

    def read_code(self) -> str:
        if self.code_reader is not None:
            return self.code_reader()
        try:
            tty = open("/dev/tty")
        except OSError:
            raise GuardError("a friend code is required but no terminal is available to enter one")
        return getpass.getpass("Friend code: ", stream=tty)

    def notify(self, title: str, body: str) -> None:
        if self.notifier is not None:
            self.notifier(title, body)
            return
        try:
            notify.enqueue(self.state, title, body)
        except Exception:  # noqa: BLE001 - notification failure must never block the command
            pass

    def audit(self, *, cmd_line: str, classification: Kind, auth_method: str, summary: str) -> None:
        self.state.audit(
            command=cmd_line, classification=classification.value, auth=auth_method,
            summary=summary, sudo_user=self.sudo_user,
        )


# --- dispatch ------------------------------------------------------------

def run(ctx: GuardCtx, argv: list[str]) -> int:
    if not argv:
        print("usage: guardctl <command> [args...]", file=sys.stderr)
        return 2
    name, args = argv[0], argv[1:]
    cmd = get(name)
    if cmd is None:
        print(f"guardctl: unknown command {name!r}", file=sys.stderr)
        return 2

    if cmd.min_args and len(args) < cmd.min_args or (cmd.max_args is not None and len(args) > cmd.max_args):
        print(f"guardctl: wrong number of arguments for {name!r}", file=sys.stderr)
        return 2

    try:
        if cmd.kind == Kind.INTERNAL and ctx.sudo_user is not None:
            raise GuardError(f"{name} is systemd-only and cannot be run via sudo")
        summary = _describe(name, args)
        if cmd.kind == Kind.LOOSEN:
            _authorize(ctx, summary)
        result = cmd.handler(ctx, args)
        auth_method = "root" if auth.caller_is_real_root(ctx.sudo_user) else ("totp" if (cmd.kind == Kind.LOOSEN and ctx.state.is_locked()) else "none")
        ctx.audit(cmd_line=" ".join([name, *args]), classification=cmd.kind, auth_method=auth_method, summary=summary)
        if cmd.kind != Kind.NEUTRAL:
            ctx.notify(f"[guard] {name}", summary)
        if result is not None:
            print(result)
        return 0
    except GuardError as e:
        print(f"guardctl: {e}", file=sys.stderr)
        return 1


def _describe(name: str, args: list[str]) -> str:
    return f"{name} {' '.join(args)}".strip()


def _authorize(ctx: GuardCtx, summary: str, *, force: bool = False) -> None:
    """Ask for a friend code. Pre-lock, loosen commands run freely -- except
    with force=True (the lock itself), which always needs one."""
    if not force and not ctx.state.is_locked():
        return
    if auth.caller_is_real_root(ctx.sudo_user):
        return  # the friend, via `su -`
    print(summary)
    locked_out, remaining = auth.lockout_status(ctx.state)
    if locked_out:
        raise GuardError(f"locked out for {int(remaining)}s after too many failed codes")
    code = ctx.read_code()
    try:
        result = auth.verify_code(ctx.state, code, notify_fn=ctx.notify)
    except auth.NotEnrolled as e:
        # Shouldn't be reachable via the intended flow (guardctl lock
        # requires enrollment first), but state is just files on disk --
        # treat "locked with no secret enrolled" as a clean error, not a
        # crash, the same way every other "the config is in a state I
        # didn't expect" case in this project degrades rather than raises.
        raise GuardError(f"system is locked but no friend code is enrolled ({e}) -- this needs root to fix") from e
    if not result.ok:
        raise GuardError(result.reason or "incorrect code")


# --- commands --------------------------------------------------------------

@command("status", Kind.NEUTRAL)
def cmd_status(ctx: GuardCtx, args: list[str]) -> str:
    policy = ctx.current_policy()
    locked = ctx.state.is_locked()
    if policy is None:
        return f"locked={locked} policy=NOT LOADED"
    return f"locked={locked} enforce={policy.enforce} hash={policy.hash} block_lists={len(policy.block_sets)}"


@command("doctor", Kind.NEUTRAL)
def cmd_doctor(ctx: GuardCtx, args: list[str]) -> str:
    """Checks the invariants that keep this system safe, and reports
    plainly rather than silently. Never raises -- a check that errors out
    (subprocess missing, path not found) is reported as a failure, not a
    crash, consistent with the rest of this project."""
    import subprocess

    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))

    for unit in ("distraction-guard.service", "distraction-guard-nft.service", "distraction-guard-watchdog.service"):
        try:
            r = subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=5)
            add(f"{unit} active", r.returncode == 0)
        except (OSError, subprocess.SubprocessError) as e:
            add(f"{unit} active", False, str(e))

    try:
        r = subprocess.run(["nft", "list", "table", "inet", "distraction_guard"], capture_output=True, timeout=5)
        add("nft table present", r.returncode == 0)
    except (OSError, subprocess.SubprocessError) as e:
        add("nft table present", False, str(e))

    try:
        r = subprocess.run(["trust", "list"], capture_output=True, text=True, timeout=5)
        add("CA trust anchor present", "Distraction Guard" in r.stdout)
    except (OSError, subprocess.SubprocessError) as e:
        add("CA trust anchor present", False, str(e))

    policy = ctx.current_policy()
    add("policy loaded", policy is not None, "" if policy else f"check {ctx.compiled_policy_path}")

    # The proxy keeps its last-good policy when a reload fails, so a valid
    # compiled policy doesn't mean it's the one being ENFORCED -- found live,
    # when unreadable terms left the proxy on an old policy for hours with
    # nothing visible. Its health endpoint reports the hash it's running.
    if policy is not None:
        try:
            from guardctl.watchdog import _check_admin_endpoint
            token_path = Path(ctx.private_dir) / "health.token"
            token = token_path.read_text().strip() if token_path.exists() else ""
            running = _check_admin_endpoint("127.0.0.1", 8081, token, policy.hash, 3.0)
            add("proxy is enforcing the current policy", running,
                "" if running else "the proxy is running an older policy (or is down) -- see: journalctl -u distraction-guard -n 20")
        except Exception as e:  # noqa: BLE001 - doctor never raises
            add("proxy is enforcing the current policy", False, str(e))

    try:
        r = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True, timeout=5)
        add("clock synced (needed for TOTP)", r.stdout.strip() == "yes")
    except (OSError, subprocess.SubprocessError) as e:
        add("clock synced (needed for TOTP)", False, str(e))

    if ctx.state.is_locked():
        try:
            from guardctl import lock as lock_mod
            rec = lock_mod.load_record(ctx.state.root)
            user = rec.get("user") or _probe_user(ctx, None)
            for name, ok in lock_mod.integrity_checks(ctx.lock_sys or lock_mod.Sys(), user, ctx.state.path("audit.log")):
                add(f"lock: {name}", ok)
        except Exception as e:  # noqa: BLE001 - doctor never raises
            add("lock integrity", False, str(e))

    lines = []
    all_ok = True
    for name, ok, detail in checks:
        mark = "OK" if ok else "FAIL"
        all_ok = all_ok and ok
        lines.append(f"[{mark}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    lines.append("" )
    lines.append("all checks passed" if all_ok else "one or more checks FAILED -- see above")
    return "\n".join(lines)


@command("compile", Kind.NEUTRAL)
def cmd_compile(ctx: GuardCtx, args: list[str]) -> str:
    raw = ctx.recompile()
    return f"compiled policy hash={raw['hash']}"


@command("test-url", Kind.NEUTRAL, min_args=1, max_args=1)
def cmd_test_url(ctx: GuardCtx, args: list[str]) -> str:
    from urllib.parse import urlsplit
    from dg_policy.hosts import HostKind

    policy = ctx.current_policy()
    if policy is None:
        return "no policy loaded"
    parts = urlsplit(args[0])
    decision = policy.classify(parts.hostname or "")
    if decision.kind == HostKind.BLOCK:
        return f"BLOCK ({decision.rule_id})"
    if decision.kind == HostKind.PASSTHROUGH:
        return "PASSTHROUGH (not inspected)"
    if decision.kind == HostKind.ALLOW_TEMP:
        return "ALLOW (temporary)"
    return "INSPECT (allowed, content-checked)"


@command("log", Kind.NEUTRAL)
def cmd_log(ctx: GuardCtx, args: list[str]) -> str:
    """`guardctl log [-n N] [--audit]`: the proxy's block/would_block
    decisions by default (what the install checklist tells you to look
    at), or guardctl's own command audit trail with --audit."""
    audit = False
    limit = 20
    rest = list(args)
    while rest:
        a = rest.pop(0)
        if a == "--audit":
            audit = True
        elif a == "-n" and rest:
            a = rest.pop(0)
            if not a.isdigit():
                raise GuardError(f"-n needs a number, got {a!r}")
            limit = int(a)
        elif a.isdigit():
            limit = int(a)
        else:
            raise GuardError(f"usage: guardctl log [-n N] [--audit] (unexpected {a!r})")

    if audit:
        entries = ctx.state.read_audit(limit=limit)
        return "\n".join(f"{e['ts']}\t{e['classification']}\t{e['auth']}\t{e['summary']}" for e in entries) or "(no entries)"

    from collections import deque
    p = Path(ctx.decision_log_path)
    if not p.exists():
        return "(no proxy decisions logged yet)"
    with open(p, encoding="utf-8", errors="replace") as f:
        lines = deque(f, maxlen=limit)
    out = []
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        where = (d.get("host") or "-") + (d.get("path_head") or "")
        extra = f"\t({d['detail']})" if d.get("detail") else ""
        out.append(f"{d.get('ts', '?')}\t{d.get('action', '?')}\t{d.get('rule', '?')}\t{where}{extra}")
    return "\n".join(out) or "(no proxy decisions logged yet)"


@command("block", Kind.TIGHTEN, min_args=1, max_args=1)
def cmd_block(ctx: GuardCtx, args: list[str]) -> str:
    domain = args[0].strip().lower()
    blocks = ctx.read_local_list("blocks.json")
    if domain not in blocks:
        blocks.append(domain)
        ctx.write_local_list("blocks.json", blocks)
        ctx.recompile()
    return f"Blocked {domain}"


@command("block-path", Kind.TIGHTEN, min_args=2, max_args=2)
def cmd_block_path(ctx: GuardCtx, args: list[str]) -> str:
    host_suffix, glob = args
    paths = ctx.read_local_list("paths.json")
    rule_id = f"R-{len(paths) + 1}"
    paths.append({"id": rule_id, "host_suffix": host_suffix.strip().lower(), "path_glob": glob})
    ctx.write_local_list("paths.json", paths)
    ctx.recompile()
    return f"Blocked {host_suffix}{glob} ({rule_id})"


@command("add-context-word", Kind.TIGHTEN, min_args=0, max_args=0)
def cmd_add_context_word(ctx: GuardCtx, args: list[str]) -> str:
    word = getpass.getpass("Context word (no echo): ")
    words = ctx.read_local_list("context.json")
    toks = tokenize(word)
    added = 0
    for t in toks:
        if t not in words:
            words.append(t)
            added += 1
    ctx.write_local_list("context.json", words)
    ctx.recompile()
    return f"added {added} context word(s)"


@command("add-term", Kind.TIGHTEN, min_args=0, max_args=1)
def cmd_add_term(ctx: GuardCtx, args: list[str]) -> str:
    """Usage: add-term [--strict|--contextual|--combo]. Reads the term (or,
    for --combo, two parts) from the terminal with no echo. Never prints the
    term text back -- only the assigned rule id."""
    ttype = "contextual"
    if args:
        flag = args[0].lstrip("-")
        if flag not in ("strict", "contextual", "combo"):
            raise GuardError(f"unknown term type: {args[0]}")
        ttype = flag

    if ttype == "combo":
        a = getpass.getpass("Part 1 (no echo): ")
        b = getpass.getpass("Part 2 (no echo): ")
        parts = [tokenize(a), tokenize(b)]
    else:
        phrase = getpass.getpass("Term (no echo): ")
        parts = [tokenize(phrase)]

    if any(not p for p in parts):
        raise GuardError("term normalized to nothing -- try a different phrase")

    terms = ctx.read_terms()
    new_id = ctx.next_term_id(terms)
    terms.append({"id": new_id, "type": ttype, "parts": parts})
    ctx.write_terms(terms)
    ctx.recompile()
    return f"added {new_id} ({ttype})"


@command("remove-term", Kind.LOOSEN, min_args=1, max_args=1)
def cmd_remove_term(ctx: GuardCtx, args: list[str]) -> str:
    term_id = args[0]
    terms = ctx.read_terms()
    new_terms = [t for t in terms if t["id"] != term_id]
    if len(new_terms) == len(terms):
        raise GuardError(f"no such term: {term_id}")
    ctx.write_terms(new_terms)
    ctx.recompile()
    return f"removed {term_id}"


@command("find-term", Kind.NEUTRAL, min_args=0, max_args=0)
def cmd_find_term(ctx: GuardCtx, args: list[str]) -> str:
    """Asks for a term (no echo) and prints the ID(s) it's stored under, so
    `remove-term <ID>` can be used without terms ever being listed. Matches
    the normalized form, so spelling/case variants find it too."""
    parts = tokenize(getpass.getpass("Term to find (no echo): "))
    if not parts:
        raise GuardError("empty term")
    hits = [t for t in ctx.read_terms() if any(list(p) == parts for p in t["parts"])]
    if not hits:
        return "no stored term matches that"
    return "\n".join(f"{t['id']} ({t['type']})" for t in hits)


@command("unblock", Kind.LOOSEN, min_args=1, max_args=1)
def cmd_unblock(ctx: GuardCtx, args: list[str]) -> str:
    host = args[0].strip().lower()
    exceptions = ctx.read_local_list("exceptions.json")
    if host not in exceptions:
        exceptions.append(host)
        ctx.write_local_list("exceptions.json", exceptions)
        ctx.recompile()
    return f"Unblocked {host}"


@command("passthrough", Kind.LOOSEN, min_args=1, max_args=1)
def cmd_passthrough(ctx: GuardCtx, args: list[str]) -> str:
    host = args[0].strip().lower()
    hosts = ctx.read_local_list("passthrough.json")
    if host not in hosts:
        hosts.append(host)
        ctx.write_local_list("passthrough.json", hosts)
        ctx.recompile()
    return f"Passthrough (never inspected): {host}"


@command("allow-temp", Kind.LOOSEN, min_args=2, max_args=2)
def cmd_allow_temp(ctx: GuardCtx, args: list[str]) -> str:
    host, minutes_str = args
    try:
        minutes = int(minutes_str)
    except ValueError:
        raise GuardError("minutes must be an integer")
    if not (0 < minutes <= MAX_TEMP_ALLOW_MINUTES):
        raise GuardError(f"minutes must be 1-{MAX_TEMP_ALLOW_MINUTES}")
    host = host.strip().lower()
    expires_at = time.time() + minutes * 60
    allows = ctx.read_local_list("temp_allows.json")
    allows = [a for a in allows if a["host"] != host]
    allows.append({"host": host, "expires_at": expires_at})
    ctx.write_local_list("temp_allows.json", allows)
    ctx.recompile()
    return f"Allow {host} for {minutes} minute(s)"


@command("disable-list", Kind.LOOSEN, min_args=1, max_args=1)
def cmd_disable_list(ctx: GuardCtx, args: list[str]) -> str:
    name = args[0]
    disabled = ctx.read_local_list("disabled_lists.json")
    if name not in disabled:
        disabled.append(name)
        ctx.write_local_list("disabled_lists.json", disabled)
        ctx.recompile()
    return f"Disabled list {name}"


@command("enable-list", Kind.TIGHTEN, min_args=1, max_args=1)
def cmd_enable_list(ctx: GuardCtx, args: list[str]) -> str:
    name = args[0]
    disabled = ctx.read_local_list("disabled_lists.json")
    if name in disabled:
        disabled.remove(name)
        ctx.write_local_list("disabled_lists.json", disabled)
        ctx.recompile()
    return f"Enabled list {name}"


@command("totp-enroll", Kind.LOOSEN, min_args=0, max_args=0)
def cmd_totp_enroll(ctx: GuardCtx, args: list[str]) -> str:
    """Enroll the friend's authenticator: show a QR code, then require one
    valid code from it before the new secret counts. A failed or abandoned
    confirmation restores the previous enrollment (if any), so a botched
    re-enroll can never leave a secret nobody holds."""
    import subprocess
    secret_path = ctx.state.path(auth.TOTP_SECRET_FILE)
    previous = secret_path.read_bytes() if secret_path.exists() else None
    uri = auth.enroll(ctx.state)
    try:
        subprocess.run(["qrencode", "-t", "ansiutf8", uri], check=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        print(uri)
    print("Friend: scan this into your authenticator app and BACK IT UP.")
    ok = False
    try:
        result = auth.verify_code(ctx.state, ctx.read_code(), notify_fn=ctx.notify)
        ok = result.ok
    finally:
        if not ok:
            if previous is None:
                secret_path.unlink(missing_ok=True)
            else:
                secret_path.write_bytes(previous)
    if not ok:
        raise GuardError("that code didn't match -- enrollment NOT saved (previous one kept). Run totp-enroll again.")
    return "enrolled: codes from the friend's app now work"


@command("notify-setup", Kind.LOOSEN, min_args=0, max_args=0)
def cmd_notify_setup(ctx: GuardCtx, args: list[str]) -> str:
    url = notify.setup(ctx.state)
    sent = notify.send_test(ctx.state)
    return (f"Friend: subscribe to {url} in the ntfy app (or open it in a browser).\n"
            + ("A test message was sent -- check it arrived." if sent
               else "The test message could NOT be sent -- check the connection and run notify-setup again."))


# --- emergency kill switch ---------------------------------------------
# The one thing that must work even if everything else about this system
# is broken: a single command that unconditionally stops redirecting
# traffic. Pre-lock (the only time it can run without a code -- see
# _authorize), this is what you reach for instead of a full uninstall.sh
# if something goes wrong. Every step is best-effort and independent --
# one failing must never stop the rest from running, because this is the
# panic button, not a normal command.

_EMERGENCY_UNITS = ("distraction-guard-nft.service", "distraction-guard.service", "distraction-guard-watchdog.service")


@command("emergency-off", Kind.LOOSEN, min_args=0, max_args=0)
def cmd_emergency_off(ctx: GuardCtx, args: list[str]) -> str:
    import subprocess

    steps: list[tuple[str, bool]] = []

    def run_step(name: str, argv: list[str]) -> None:
        try:
            r = subprocess.run(argv, capture_output=True, timeout=15)
            steps.append((name, r.returncode == 0))
        except (OSError, subprocess.SubprocessError):
            steps.append((name, False))

    # Delete the table FIRST -- this is the actual fix, everything after
    # is cleanup. Even if every other step below fails, traffic stops
    # being redirected the instant this succeeds.
    run_step("delete nft table", ["nft", "delete", "table", "inet", "distraction_guard"])
    for unit in _EMERGENCY_UNITS:
        run_step(f"stop {unit}", ["systemctl", "disable", "--now", unit])
    run_step("remove NM dns override", ["rm", "-f", "/etc/NetworkManager/conf.d/50-distraction-guard.conf"])
    run_step("remove dnsmasq sinkhole (on)", ["rm", "-f", "/etc/NetworkManager/dnsmasq.d/distraction-guard-sinkhole.conf"])
    run_step("remove legacy dnsmasq sinkhole (.off)", ["rm", "-f", "/etc/NetworkManager/dnsmasq.d/distraction-guard-sinkhole.conf.off"])
    run_step("remove dnsmasq always-on", ["rm", "-f", "/etc/NetworkManager/dnsmasq.d/distraction-guard.conf"])
    run_step("reload NM DNS", ["nmcli", "general", "reload", "dns-full"])
    # Firefox's own block list (WebsiteFilter) and CA pin live in its policy
    # file; without this, a browser restart after emergency-off still
    # blocked the social sites.
    try:
        from guardctl.firefox import restore_original
        steps.append(("restore Firefox policy", restore_original(
            str(Path(ctx.etc_dir) / "firefox-policies.orig.json"), ctx.firefox_policy_path)))
    except Exception:  # noqa: BLE001 - panic button: never stop on one failed step
        steps.append(("restore Firefox policy", False))

    summary = ", ".join(f"{n}={'ok' if ok else 'FAILED'}" for n, ok in steps)
    return f"emergency-off: {summary}\nNothing is redirected or blocked now. Re-enable with: sudo guardctl emergency-on"


@command("emergency-on", Kind.TIGHTEN, min_args=0, max_args=0)
def cmd_emergency_on(ctx: GuardCtx, args: list[str]) -> str:
    """Reverses emergency-off using the same careful ordering as
    install.sh: start the proxy, POLL until it's genuinely healthy on
    both the admin endpoint and the transparent port, and only THEN apply
    nftables. Aborts before touching nftables if the proxy never becomes
    healthy -- same guarantee install.sh gives on first install."""
    import subprocess
    from guardctl.watchdog import check_health

    subprocess.run(["systemctl", "daemon-reload"], timeout=15)
    subprocess.run(["systemctl", "enable", "--now", "distraction-guard.service"], timeout=15)

    token = ""
    token_path = Path(ctx.private_dir) / "health.token"
    if token_path.exists():
        token = token_path.read_text().strip()

    healthy = False
    for _ in range(20):
        if check_health(token=token, timeout=2):
            healthy = True
            break
        time.sleep(1)

    if not healthy:
        raise GuardError(
            "proxy did not become healthy -- nftables NOT applied. "
            "Check: sudo systemctl status distraction-guard.service"
        )

    probe = _apply_nft_guarded(_probe_user(ctx, None))
    subprocess.run(["systemctl", "enable", "--now", "distraction-guard-watchdog.service"], timeout=15)
    return f"emergency-on: proxy healthy, {probe}, watchdog running."


# --- guarded nft apply ("try mode") ------------------------------------
# A health check on the proxy's own ports can't tell you whether the
# nftables table lets real traffic THROUGH to it -- six live installs
# passed that check and still took jack offline (see the ct status dnat
# comment in templates/guard.nft.in). So applying the table is never
# trusted on its own: a revert timer is armed first, a real HTTPS fetch
# is made as jack (so it takes the exact redirected path), and only a
# passing fetch disarms the timer. If this process hangs, is Ctrl-C'd, or
# the terminal dies, the timer still reverts -- worst case is
# AUTOREVERT_SECONDS offline, never "until the friend is reachable".

AUTOREVERT_SECONDS = 90
AUTOREVERT_UNIT = "dg-autorevert"
PROBE_URL = "https://example.com"
_REVERT_SHELL = (
    "nft delete table inet distraction_guard; "
    "systemctl disable distraction-guard-nft.service"
)


def _probe_user(ctx: GuardCtx, explicit: str | None) -> str:
    """The user whose traffic the table redirects (uid 1000 by default,
    matching the template's meta skuid) -- the probe must run as them or
    it wouldn't touch the redirect at all."""
    if explicit:
        return explicit
    if ctx.sudo_user:
        return ctx.sudo_user
    import pwd
    return pwd.getpwuid(1000).pw_name


def _apply_nft_guarded(user: str) -> str:
    import subprocess

    def run(argv, **kw):
        return subprocess.run(argv, capture_output=True, text=True, timeout=kw.pop("timeout", 15), **kw)

    # Clear a stale timer from an earlier run, then arm. Arming failing is
    # a hard stop: without the timer there's no guarantee, so don't apply.
    run(["systemctl", "stop", f"{AUTOREVERT_UNIT}.timer", f"{AUTOREVERT_UNIT}.service"])
    armed = run([
        "systemd-run", f"--unit={AUTOREVERT_UNIT}", f"--on-active={AUTOREVERT_SECONDS}", "--collect",
        "/bin/sh", "-c", _REVERT_SHELL,
    ])
    if armed.returncode != 0:
        raise GuardError(f"could not arm the auto-revert timer -- nftables NOT applied: {armed.stderr.strip()}")

    run(["systemctl", "enable", "distraction-guard-nft.service"])
    # restart, not start: the unit is RemainAfterExit, so a plain start on
    # an already-active unit wouldn't re-run nft -f with the new table.
    run(["systemctl", "restart", "distraction-guard-nft.service"])

    families = ["-4"]
    if run(["ip", "-6", "route", "show", "default"]).stdout.strip():
        families.append("-6")

    failures = []
    for fam in families:
        ok, detail = False, ""
        for _ in range(2):
            r = run(
                ["runuser", "-u", user, "--", "curl", fam, "-sS", "-m", "10",
                 "-o", "/dev/null", "-w", "%{http_code} %header{x-distraction-guard}", PROBE_URL],
                timeout=25,
            )
            code, _, marker = r.stdout.strip().partition(" ")
            # A block page from the proxy itself (e.g. during the night
            # block) still proves traffic is reaching it through the
            # redirect -- only a missing/foreign response means broken.
            if r.returncode == 0 and (code[:1] in ("2", "3") or marker):
                ok = True
                break
            detail = f"curl {fam}: exit {r.returncode}, http {code or '-'} {r.stderr.strip()}"
        if not ok:
            failures.append(detail)

    if failures:
        # Revert now rather than waiting out the timer, then gather what's
        # needed to diagnose it without the internet being down meanwhile.
        run(["/bin/sh", "-c", _REVERT_SHELL])
        run(["systemctl", "stop", f"{AUTOREVERT_UNIT}.timer", f"{AUTOREVERT_UNIT}.service"])
        rejects = run(["journalctl", "-k", "-b", "--no-pager", "-n", "8", "--grep", "dg-reject"]).stdout
        proxy = run(["journalctl", "-u", "distraction-guard.service", "--no-pager", "-n", "15"]).stdout
        raise GuardError(
            "nftables applied but traffic did NOT get through the proxy, so it was reverted "
            "immediately -- your internet is untouched.\n  " + "\n  ".join(failures)
            + f"\n--- recent dg-reject kernel log ---\n{rejects}--- proxy log ---\n{proxy}"
        )

    disarm = run(["systemctl", "stop", f"{AUTOREVERT_UNIT}.timer"])
    if disarm.returncode != 0:
        raise GuardError(
            f"traffic works, but the auto-revert timer could not be disarmed ({disarm.stderr.strip()}) "
            f"-- nftables WILL be removed within {AUTOREVERT_SECONDS}s. Re-run to retry."
        )
    return f"nftables applied and verified ({', '.join(families)} fetch of {PROBE_URL} through the proxy)"


@command("_apply-nft", Kind.INTERNAL, min_args=1, max_args=1)
def cmd_apply_nft(ctx: GuardCtx, args: list[str]) -> str:
    """install.sh's nftables step: the same guarded apply emergency-on
    uses. Takes the probe user explicitly since install.sh has to drop
    SUDO_USER to get past the INTERNAL gate."""
    return _apply_nft_guarded(_probe_user(ctx, args[0]))


# --- internal (systemd-only) commands ---------------------------------

@command("_notify-flush", Kind.INTERNAL, min_args=0, max_args=0)
def cmd_notify_flush(ctx: GuardCtx, args: list[str]) -> str:
    sent, remaining = notify.flush_queue(ctx.state)
    return f"sent={sent} remaining={remaining}"


@command("_expire", Kind.INTERNAL, min_args=0, max_args=0)
def cmd_expire(ctx: GuardCtx, args: list[str]) -> str:
    """Prunes expired temp_allows entries (cosmetic -- classify_host()
    already checks expiry live, so this is cleanup, not a correctness
    dependency) and recompiles if anything changed."""
    now = time.time()
    allows = ctx.read_local_list("temp_allows.json")
    kept = [a for a in allows if a["expires_at"] > now]
    if len(kept) != len(allows):
        ctx.write_local_list("temp_allows.json", kept)
        ctx.recompile()
    return f"expired {len(allows) - len(kept)} entrie(s)"


@command("_refresh", Kind.INTERNAL, min_args=0, max_args=0)
def cmd_refresh(ctx: GuardCtx, args: list[str]) -> str:
    """The refresh timer's job: update block lists, prune expired
    temp_allows, recompile, and send a daily heartbeat so the friend
    notices a genuinely dead system (missing heartbeat) rather than only
    ever hearing about it when something goes wrong."""
    from guardctl.lists import ListSpec, update_all
    import tomllib

    lists_toml_path = Path(ctx.etc_dir) / "lists.toml"
    results: dict[str, tuple[bool, str]] = {}
    if lists_toml_path.exists():
        with open(lists_toml_path, "rb") as f:
            catalog = tomllib.load(f).get("list", [])
        disabled = set(ctx.read_local_list("disabled_lists.json"))
        specs = [
            ListSpec(
                name=e["name"], url=e["url"], format=e["format"], rule=e["rule"],
                category=e.get("category", ""), min_entries=e.get("min_entries", 100),
                dns_sinkhole=e.get("dns_sinkhole", False),
                enabled=e.get("enabled", True) and e["name"] not in disabled,
            )
            for e in catalog
        ]
        results = update_all(specs, ctx.lists_dir)

    cmd_expire(ctx, [])
    raw = ctx.recompile()
    asset_error = None
    try:
        ctx.write_assets(raw)
    except Exception as e:  # noqa: BLE001 - asset write failure must not block the heartbeat/list refresh
        asset_error = f"{type(e).__name__}: {e}"
        ctx.notify("Distraction Guard: asset write failed", asset_error)

    failed = [name for name, (ok, _) in results.items() if not ok]
    if failed:
        ctx.notify("Distraction Guard: list refresh", f"failed for: {', '.join(failed)} (previous list kept)")

    status = "ok" if not asset_error and not failed else "PROBLEMS"
    heartbeat = f"[guard] {status} - locked={ctx.state.is_locked()} - policy {raw['hash'][:8]} - lists failed: {len(failed)}"
    if asset_error:
        heartbeat += f" - ASSET WRITE FAILED: {asset_error}"
    ctx.notify("Distraction Guard heartbeat", heartbeat)
    return heartbeat


@command("_post-upgrade", Kind.INTERNAL, min_args=0, max_args=0)
def cmd_post_upgrade(ctx: GuardCtx, args: list[str]) -> str:
    """Run by the pacman hook after nftables/NetworkManager/dnsmasq/
    firefox/systemd/ca-certificates/sudo are touched, to re-assert
    anything a package upgrade might have reset."""
    import subprocess

    anomalies = []

    nft_check = subprocess.run(["nft", "list", "table", "inet", "distraction_guard"], capture_output=True, timeout=10)
    if nft_check.returncode != 0:
        anomalies.append("nft table missing")
        try:
            ctx.recompile()
        except compile_mod.CompileError:
            pass
        subprocess.run(["systemctl", "restart", "distraction-guard-nft.service"], check=False, timeout=15)

    ca_path = str(Path(ctx.etc_dir) / "ca.pem")
    trust_check = subprocess.run(["trust", "list"], capture_output=True, text=True, timeout=10)
    if "Distraction Guard" not in trust_check.stdout and Path(ca_path).exists():
        anomalies.append("CA trust anchor missing")
        subprocess.run(["trust", "anchor", "--store", ca_path], check=False, timeout=15)

    if ctx.state.is_locked():
        try:
            from guardctl import lock as lock_mod
            user = lock_mod.load_record(ctx.state.root).get("user") or _probe_user(ctx, None)
            anomalies += [f"lock: {x}" for x in lock_mod.reassert(ctx.lock_sys or lock_mod.Sys(), user)]
        except Exception as e:  # noqa: BLE001 - must not break pacman
            anomalies.append(f"lock reassert FAILED: {e}")

    if anomalies:
        ctx.notify("Distraction Guard: post-upgrade", f"reasserted: {', '.join(anomalies)}")
    return f"anomalies: {len(anomalies)}"


# --- class mode ----------------------------------------------------------

CLASS_MODE_DEFAULTS = {
    "title_prefix": "Class:",
    "pad_minutes": 5,
    "bookmark_folders": ["classes", "dev"],
    "bookmark_labels": ["zoom"],
    "exclude_labels": ["claude", "gemini"],
    "extra_hosts": ["zoom.us"],
    # Bookmark folders whose sites are trusted: never content-scanned.
    "passthrough_folders": ["classes", "dev", "coms"],
    # Daily block: these folders' sites are blocked for every request, every
    # day, between start and end (local time).
    "daily_block_folders": ["life"],
    "daily_block_start": "09:00",
    "daily_block_end": "22:00",
    "daily_block_extra_hosts": ["youtu.be", "max.com"],  # short links / HBO Max's other name
    "daily_block_exempt": ["aws.amazon.com"],  # AWS console lives under amazon.com
    # Night block: ALL traffic through the proxy is cut between these times
    # (wraps midnight if start > end). Equal times disable it.
    "night_block_start": "01:00",
    "night_block_end": "07:00",
}
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def _class_mode_cfg(ctx: GuardCtx) -> dict:
    import tomllib
    cfg = dict(CLASS_MODE_DEFAULTS)
    p = Path(ctx.etc_dir) / "policy.toml"
    if p.exists():
        with open(p, "rb") as f:
            cfg.update(tomllib.load(f).get("class_mode", {}))
    return cfg


def _read_user_file(ctx: GuardCtx, path: Path) -> str:
    """Read a file schedule-sync takes from jack's home. guardctl runs as
    root via sudo, so without this, `--calcurse /etc/shadow` or a symlink
    planted at ~/.local/share/calcurse/apts would have root read any file
    (and parse errors echo lines). Via sudo: no symlinks, and the file must
    be owned by the invoking user. The friend (real root) is unrestricted."""
    if ctx.sudo_user is None:
        return path.read_text()
    import pwd
    uid = pwd.getpwnam(ctx.sudo_user).pw_uid
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise GuardError(f"can't read {path}: {e.strerror}" + (" (symlinks aren't allowed)" if e.errno == 40 else "")) from e
    with os.fdopen(fd, encoding="utf-8") as f:
        if os.fstat(f.fileno()).st_uid != uid:
            raise GuardError(f"{path} isn't owned by {ctx.sudo_user}")
        return f.read()


def _user_home(ctx: GuardCtx) -> Path:
    import pwd
    user = ctx.sudo_user or pwd.getpwuid(1000).pw_name
    return Path(pwd.getpwnam(user).pw_dir)


@command("schedule-sync", Kind.TIGHTEN, min_args=0, max_args=4)
def cmd_schedule_sync(ctx: GuardCtx, args: list[str]) -> str:
    """Re-read class times from calcurse and the class-time allowlist from
    the startpage bookmarks, and snapshot both into root-owned config.

    Registered TIGHTEN so adding class time or dropping a site is always
    free; if the new snapshot REMOVES class time or ADDS an allowed site,
    this asks for a friend code itself (once locked), with the exact
    loosening spelled out first."""
    import datetime as dt
    from dg_policy.schedule import ScheduleError, Window, parse_calcurse, removed_time
    from guardctl.classmode import BookmarkError, allow_hosts, parse_bookmarks

    opts = {"--calcurse": None, "--bookmarks": None}
    rest = list(args)
    while rest:
        a = rest.pop(0)
        if a not in opts or not rest:
            raise GuardError("usage: guardctl schedule-sync [--calcurse PATH] [--bookmarks PATH]")
        opts[a] = rest.pop(0)
    home = None if (opts["--calcurse"] and opts["--bookmarks"]) else _user_home(ctx)
    calcurse_path = Path(opts["--calcurse"] or home / ".local/share/calcurse/apts")
    bookmarks_path = Path(opts["--bookmarks"] or home / ".config/startpage/bookmarks.js")

    cfg = _class_mode_cfg(ctx)
    today = dt.date.today()
    try:
        windows = parse_calcurse(_read_user_file(ctx, calcurse_path), prefix=cfg["title_prefix"], today=today)
        folders = parse_bookmarks(_read_user_file(ctx, bookmarks_path))
        allow = allow_hosts(
            folders,
            include_folders=cfg["bookmark_folders"], include_labels=cfg["bookmark_labels"],
            exclude_labels=cfg["exclude_labels"], extra_hosts=cfg["extra_hosts"],
        )
        trusted = allow_hosts(
            folders, include_folders=cfg["passthrough_folders"], include_labels=[], exclude_labels=[],
            extra_hosts=[h for h in cfg["extra_hosts"]],
        )
        daily_hosts = allow_hosts(
            folders, include_folders=cfg["daily_block_folders"], include_labels=[], exclude_labels=[],
            extra_hosts=cfg["daily_block_extra_hosts"],
        ) if cfg["daily_block_folders"] else []
        daily = {
            "start": cfg["daily_block_start"], "end": cfg["daily_block_end"],
            "hosts": daily_hosts, "exempt": sorted(normalize_host(h) for h in cfg["daily_block_exempt"]),
        }
        _minutes(daily["start"]), _minutes(daily["end"])  # validate
        night = {"start": cfg["night_block_start"], "end": cfg["night_block_end"]}
        _minutes(night["start"]), _minutes(night["end"])  # validate
    except (OSError, ScheduleError, BookmarkError) as e:
        raise GuardError(f"schedule-sync: {e}") from e
    if not windows:
        raise GuardError(f"schedule-sync: no {cfg['title_prefix']!r} entries found in {calcurse_path} -- refusing to clear class mode")

    current = ctx.read_local_dict("class_mode.json")
    old_windows = [Window.from_json(w) for w in current.get("windows", [])]
    removed = removed_time(old_windows, windows, today=today)
    added_hosts = sorted(set(allow) - set(current.get("allow", []))) if current else []
    # Passthrough = never scanned, so newly trusting a site is a loosening.
    added_trusted = sorted(set(trusted) - set(current.get("passthrough", []))) if current.get("passthrough") is not None else []
    pad = int(cfg["pad_minutes"])
    pad_cut = bool(current) and pad < int(current.get("pad_minutes", 0))
    daily_loosen = _daily_block_loosenings(current.get("daily_block"), daily)
    night_loosen = _night_block_loosenings(current.get("night_block"), night)

    if removed or added_hosts or added_trusted or pad_cut or daily_loosen or night_loosen:
        lines = ["schedule-sync would LOOSEN class mode:"]
        lines += [f"  - removes {_DAYS[w.weekday]} {w.start}-{w.end} {w.title}" for w in removed]
        lines += [f"  - allows {h} during class" for h in added_hosts]
        lines += [f"  - stops scanning {h} (passthrough)" for h in added_trusted]
        if pad_cut:
            lines.append(f"  - shrinks padding {current.get('pad_minutes')} -> {pad} min")
        lines += [f"  - {x}" for x in daily_loosen + night_loosen]
        _authorize(ctx, "\n".join(lines))

    ctx.write_local_dict("class_mode.json", {
        "pad_minutes": pad,
        "windows": [w.to_json() for w in windows],
        "allow": allow,
        "passthrough": trusted,
        "daily_block": daily,
        "night_block": night,
    })
    raw = ctx.recompile()
    return f"class mode: {len(windows)} weekly windows, {len(allow)} allowed sites, {len(trusted)} never-scanned sites (policy {raw['hash'][:8]})\n" + cmd_schedule(ctx, [])


@command("schedule", Kind.NEUTRAL, min_args=0, max_args=0)
def cmd_schedule(ctx: GuardCtx, args: list[str]) -> str:
    import datetime as dt
    from dg_policy.schedule import SUPPORT_HOSTS, Window, active_window

    current = ctx.read_local_dict("class_mode.json")
    if not current.get("windows"):
        return "class mode: not set up (run: sudo guardctl schedule-sync)"
    windows = [Window.from_json(w) for w in current["windows"]]
    pad = int(current.get("pad_minutes", 0))
    now = dt.datetime.now()
    active = active_window(windows, now, pad_minutes=pad)
    out = [f"class mode is {'ON now: ' + active.title + ' (until ' + active.end + f' +{pad}m)' if active else 'off right now'}"]
    out.append(f"windows (+/-{pad} min):")
    out += [f"  {_DAYS[w.weekday]} {w.start}-{w.end}  {w.title}  (until {w.until or 'forever'})" for w in windows]
    out.append("allowed to open during class: " + ", ".join(current.get("allow", [])))
    out.append("always allowed (sign-in): " + ", ".join(SUPPORT_HOSTS))
    out.append("never scanned (passthrough): " + ", ".join(current.get("passthrough", [])))
    night = current.get("night_block") or {}
    if night and night["start"] != night["end"]:
        out.append(f"offline every night {night['start']}-{night['end']} (all internet)")
    daily = current.get("daily_block") or {}
    if daily.get("hosts"):
        out.append(f"blocked daily {daily['start']}-{daily['end']}: " + ", ".join(daily["hosts"])
                   + (f"  (except {', '.join(daily['exempt'])})" if daily.get("exempt") else ""))
    return "\n".join(out)


@command("set", Kind.TIGHTEN, min_args=2, max_args=2)
def cmd_set(ctx: GuardCtx, args: list[str]) -> str:
    """`guardctl set enforce true|false` / `guardctl set youtube_restrict
    strict|moderate`. Registered TIGHTEN: tightening is always free; the
    loosening direction (enforce false, moderate) asks for a friend code
    itself once locked. Edits the top-level key in policy.toml, recompiles,
    and rewrites assets (Firefox's WebsiteFilter follows enforce; the
    YouTube DNS pin follows youtube_restrict)."""
    import re
    key, value = args
    allowed = {"enforce": ("true", "false"), "youtube_restrict": ("strict", "moderate")}
    if key not in allowed or value not in allowed[key]:
        raise GuardError("usage: guardctl set enforce true|false | guardctl set youtube_restrict strict|moderate")
    p = Path(ctx.etc_dir) / "policy.toml"
    text = p.read_text() if p.exists() else ""
    if (key, value) == ("enforce", "false"):
        _authorize(ctx, "set enforce false -- turns ALL blocking off (log-only shadow mode)")
    if (key, value) == ("youtube_restrict", "moderate"):
        _authorize(ctx, "set youtube_restrict moderate -- YouTube shows more (lighter Restricted Mode)")
    line = f'{key} = {value}' if key == "enforce" else f'{key} = "{value}"'
    new, n = re.subn(rf"(?m)^{key}\s*=\s*\S+\s*$", line, text)
    if n == 0:
        # Top-level key: must come before the first [table].
        m = re.search(r"(?m)^\[", text)
        new = text[: m.start()] + line + "\n\n" + text[m.start():] if m else text + ("\n" if text and not text.endswith("\n") else "") + line + "\n"
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(new)
    os.chmod(tmp, 0o644)
    os.replace(tmp, p)
    raw = ctx.recompile()
    try:
        ctx.write_assets(raw)
    except Exception as e:  # noqa: BLE001 - the proxy already has the new policy; assets are secondary
        return f"{key}={value} (policy {raw['hash'][:8]}); assets NOT updated: {e}"
    if key == "youtube_restrict":
        import subprocess
        subprocess.run(["nmcli", "general", "reload", "dns-full"], capture_output=True, timeout=15)
        return f"youtube_restrict={value} (policy {raw['hash'][:8]}). Reload YouTube."
    return f"enforce={value} (policy {raw['hash'][:8]}). Restart Firefox for its site list to update."


def _minutes(hhmm: str) -> int:
    from dg_policy.schedule import _minutes as m
    return m(hhmm)


def _daily_block_loosenings(old: dict | None, new: dict) -> list[str]:
    """What a new daily-block snapshot would take away versus the current
    one: sites no longer blocked, new exemptions, or fewer blocked hours."""
    if not old:
        return []
    out = [f"stops blocking {h} daily" for h in sorted(set(old.get("hosts", [])) - set(new["hosts"]))]
    out += [f"exempts {h} from the daily block" for h in sorted(set(new["exempt"]) - set(old.get("exempt", [])))]
    if new["hosts"] and (_minutes(new["start"]) > _minutes(old["start"]) or _minutes(new["end"]) < _minutes(old["end"])):
        out.append(f"shortens the daily block {old['start']}-{old['end']} -> {new['start']}-{new['end']}")
    return out


def _night_minutes(block: dict | None) -> set[int]:
    """Minutes of the day covered by a night block (handles wrapping)."""
    if not block:
        return set()
    a, b = _minutes(block["start"]), _minutes(block["end"])
    if a == b:
        return set()
    return set(range(a, b)) if a < b else set(range(a, 1440)) | set(range(0, b))


def _night_block_loosenings(old: dict | None, new: dict) -> list[str]:
    lost = _night_minutes(old) - _night_minutes(new)
    if not lost:
        return []
    return [f"shortens the night block {old['start']}-{old['end']} -> {new['start']}-{new['end']}"]


# --- lock / unlock -----------------------------------------------------------

def _lock_prechecks(ctx: GuardCtx, sys_, user: str) -> list[tuple[str, bool]]:
    from guardctl import lock as lock_mod
    policy = ctx.current_policy()
    doctor = cmd_doctor(ctx, [])
    return [
        (f"target user is {user}, not root", user not in ("", "root")),
        ("blocking is on (enforce = true)", bool(policy and policy.enforce)),
        ("guardctl doctor: all checks pass", "all checks passed" in doctor),
        ("friend's authenticator is enrolled (totp-enroll)", auth.is_enrolled(ctx.state)),
        ("friend notifications are set up (notify-setup)", notify.is_configured(ctx.state)),
        ("root password is set (the friend's break-glass)", lock_mod.root_password_set(sys_)),
        ("root password was changed in the last day (by the friend, at the ceremony)", lock_mod.root_password_fresh(sys_)),
    ]


@command("lock", Kind.TIGHTEN, min_args=0, max_args=1)
def cmd_lock(ctx: GuardCtx, args: list[str]) -> str:
    """Hand the off switch to the friend. See guardctl/lock.py. Always needs
    a friend code (even though nothing is locked yet), so it can't be
    scripted or rushed. --dry-run shows the checks and steps, changes
    nothing, and needs no code."""
    from guardctl import lock as lock_mod
    dry = args == ["--dry-run"]
    if args and not dry:
        raise GuardError("usage: guardctl lock [--dry-run]")
    if ctx.state.is_locked():
        raise GuardError("already locked")
    user = _probe_user(ctx, None)
    sys_ = ctx.lock_sys or lock_mod.Sys()

    checks = _lock_prechecks(ctx, sys_, user)
    print("prechecks:")
    for name, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
    failed = [n for n, ok in checks if not ok]

    record = {"user": user, "locked_at": time.time()}
    steps = lock_mod.lock_steps(sys_, user, record, ctx.state.root, ctx.state.path("audit.log"), ctx.state.set_locked)
    if dry:
        print("steps:")
        lock_mod.run_steps(steps, dry_run=True)
        return "dry run: nothing was changed" + (f" (would stop at prechecks: {len(failed)} failing)" if failed else "")
    if failed:
        raise GuardError("not locking -- fix the failing prechecks above first")

    _authorize(ctx, f"LOCK: {user} loses sudo (except guardctl/guard-pkg), wheel and docker groups, and the boot editor", force=True)
    print("steps:")
    try:
        lock_mod.run_steps(steps)
    except lock_mod.LockError as e:
        raise GuardError(str(e)) from e
    lock_mod.save_record(ctx.state.root, record)
    return (
        "LOCKED. Reboot now -- sessions started before the lock still carry the old groups.\n"
        "After rebooting: sudo guardctl doctor"
    )


@command("unlock", Kind.LOOSEN, min_args=0, max_args=0)
def cmd_unlock(ctx: GuardCtx, args: list[str]) -> str:
    """Reverse the lock (friend code, via run()'s LOOSEN check)."""
    from guardctl import lock as lock_mod
    if not ctx.state.is_locked():
        raise GuardError("not locked")
    sys_ = ctx.lock_sys or lock_mod.Sys()
    record = lock_mod.load_record(ctx.state.root)
    user = record.get("user") or _probe_user(ctx, None)
    steps = lock_mod.unlock_steps(sys_, user, record, ctx.state.root, ctx.state.path("audit.log"), ctx.state.set_locked)
    try:
        lock_mod.run_steps(steps)
    except lock_mod.LockError as e:
        raise GuardError(str(e)) from e
    return "UNLOCKED. Log out and back in (or reboot) to get the groups back."
