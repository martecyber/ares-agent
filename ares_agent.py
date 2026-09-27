#!/usr/bin/env python3
"""
ares-agent — remote scan daemon for the Ares platform.

Usage:
  ares-agent enroll --server URL --code CODE [--name NAME]
      One-time setup. Exchanges the enrollment code for a long-lived bearer
      token, writes /etc/ares-agent/config.json (or ~/.config/ares-agent/config.json
      when not root).

  ares-agent run [--max-concurrent-tasks N]
      Daemon mode. Heartbeats every 30s on the main thread regardless of
      task state. Tasks run in worker threads (default 1; override with
      --max-concurrent-tasks or ARES_MAX_CONCURRENT_TASKS env var).

  ares-agent capabilities
      Probe and print this host's available scan tools as JSON.

  ares-agent version
      Print the running agent version.
"""

import argparse
import datetime
import json
import os
import platform
import re as _re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def _log(tag: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write(f"[{ts}] [{tag}] {msg}\n")
    sys.stderr.flush()

# Bumped on each release; reported in heartbeats so the server can drive auto-update.
# Must match `ares.versions.agent` in the platform's application.yml — the agent will
# fetch the new script and self-restart whenever the server version is strictly newer.
AGENT_VERSION = "1.0.0-beta21"

# Base directory for per-task working directories. Set by cmd_run from --workdir
# or ARES_WORKDIR; None means let tempfile use the OS default (usually /tmp).
_WORKDIR_BASE: "Path | None" = None

# Minimum free bytes required to accept new tasks (hard stop).
_DISK_MIN_FREE_BYTES = 512 * 1024 * 1024   # 512 MB
# Warn in heartbeat log when free space drops below this.
_DISK_WARN_FREE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB


def _disk_free_bytes(base: "Path | None" = None) -> int:
    """Free bytes on the filesystem that hosts task workdirs."""
    import tempfile as _tempfile
    check = str(base) if base else _tempfile.gettempdir()
    try:
        return shutil.disk_usage(check).free
    except OSError:
        return 0


def _cleanup_orphaned_workdirs(base: "Path | None") -> None:
    """Delete ALL ares-task-* dirs left by a previous (crashed) agent run."""
    import tempfile as _tempfile
    scan_dir = base if base else Path(_tempfile.gettempdir())
    cleaned = 0
    try:
        for entry in scan_dir.iterdir():
            if entry.is_dir() and entry.name.startswith("ares-task-"):
                try:
                    shutil.rmtree(entry, ignore_errors=True)
                    cleaned += 1
                except OSError:
                    pass
    except OSError:
        pass
    if cleaned:
        _log("start", f"cleaned up {cleaned} orphaned task workdir(s) from previous run")


def _cleanup_stale_workdirs(base: "Path | None", active_task_ids: "set[int]") -> int:
    """
    Periodically removes ares-task-* dirs whose task is no longer active.
    A 5-minute grace period avoids touching dirs that belong to tasks that
    just started. Called from the heartbeat loop while the agent is running,
    so space is reclaimed even if a previous run was SIGKILL'd without
    executing the execute_task finally block.
    Returns the number of directories removed.
    """
    import tempfile as _tempfile, time as _time
    scan_dir = base if base else Path(_tempfile.gettempdir())
    now = _time.time()
    _GRACE = 5 * 60  # seconds
    cleaned = 0
    try:
        for entry in scan_dir.iterdir():
            if not (entry.is_dir() and entry.name.startswith("ares-task-")):
                continue
            # Dir name pattern: ares-task-{task_id}-{random_suffix}
            parts = entry.name.split('-')
            try:
                task_id = int(parts[2])
            except (IndexError, ValueError):
                task_id = None
            # Leave dirs for currently active tasks untouched
            if task_id is not None and task_id in active_task_ids:
                continue
            try:
                if now - entry.stat().st_mtime >= _GRACE:
                    shutil.rmtree(entry, ignore_errors=True)
                    cleaned += 1
            except OSError:
                pass
    except OSError:
        pass
    return cleaned

# Cache directory for KB wordlists downloaded from the server.
_WL_CACHE_DIR = Path(os.environ.get("ARES_WORDLIST_CACHE", str(Path.home() / ".ares-agent" / "wordlist-cache")))


def _is_newer_version(candidate: str, current: str) -> bool:
    """
    Returns True only if `candidate` is strictly newer than `current`.
    Format: MAJOR.MINOR.PATCH[-betaN]. Numeric components compared numerically;
    beta suffix treated as pre-release (beta1 < beta2 < release).
    Prevents server misconfiguration from causing accidental downgrades.
    """
    import re as _re
    _VER_RE = _re.compile(r'^(\d+)\.(\d+)\.(\d+)(?:-beta(\d+))?$')
    def _parse(v):
        m = _VER_RE.match(v)
        if not m:
            return None
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # No beta suffix → release; treat as beta∞ so release > any beta.
        beta = int(m.group(4)) if m.group(4) is not None else 10**9
        return (major, minor, patch, beta)
    c = _parse(candidate)
    cur = _parse(current)
    if c is None or cur is None:
        return False
    return c > cur

# Cache directory for a tool's optional customBuilder module (see AgentToolSpec.
# CustomBuilder's own doc, ares-core) — downloaded once per checksum, re-verified
# before every use. Only ever populated when allow_agent_plugin_code is enabled.
_BUILDER_MODULE_CACHE_DIR = Path(os.environ.get(
    "ARES_BUILDER_CACHE", str(Path.home() / ".ares-agent" / "builder-modules")))


# ── config file location ─────────────────────────────────────────────────────

def config_path() -> Path:
    """System-wide when running as root, per-user otherwise."""
    if os.name == "posix" and os.geteuid() == 0:
        return Path("/etc/ares-agent/config.json")
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ares-agent" / "config.json"
    return Path.home() / ".config" / "ares-agent" / "config.json"


def load_config() -> dict:
    p = config_path()
    if not p.exists():
        sys.stderr.write(f"No config at {p}. Run `ares-agent enroll` first.\n")
        sys.exit(2)
    return json.loads(p.read_text())


def save_config(cfg: dict) -> None:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


# ── tool-spec catalog: cache, sync, capability probe ─────────────────────────
# Replaces the old static KNOWN_TOOLS list entirely (Fase 2 / Part B) — every scan
# tool this agent can even attempt now comes from GET /agent/tool-specs (every
# installed, enabled plugin's AgentToolSpec), never a hardcoded name. A tool with
# no plugin installed on the server is simply absent from the catalog and never
# considered — no "unsupported tool" special-casing needed anywhere below.

def _tool_specs_cache_path() -> Path:
    return config_path().parent / "tool-specs-cache.json"


def _load_tool_specs_cache() -> "tuple[list[dict], int | None]":
    p = _tool_specs_cache_path()
    if not p.exists():
        return [], None
    try:
        data = json.loads(p.read_text())
        return data.get("specs") or [], data.get("version")
    except (OSError, ValueError):
        return [], None


def _save_tool_specs_cache(specs: list[dict], version: int) -> None:
    p = _tool_specs_cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"specs": specs, "version": version}))
    except OSError:
        pass


def _custom_builder_module_path(tool: str) -> "Path | None":
    p = _BUILDER_MODULE_CACHE_DIR / f"{tool}.py"
    return p if p.exists() else None


def _verify_custom_builder_checksum(tool: str, spec: dict, module_path: Path) -> None:
    import hashlib as _hashlib
    expected = ((spec.get("customBuilder") or {}).get("sha256") or "")
    actual = _hashlib.sha256(module_path.read_bytes()).hexdigest()
    if not expected or actual != expected:
        raise RuntimeError(f"{tool}: builder module checksum mismatch — refusing to run")


def _sync_custom_builder_modules(sess, server: str, cfg: dict, specs: list[dict]) -> None:
    """Downloads (and checksum-verifies) any customBuilder module a refreshed catalog
    references, but only when this agent's operator has opted in — otherwise the tool
    just stays unavailable, same as a missing binary (see probe_capabilities)."""
    if not cfg.get("allow_agent_plugin_code"):
        return
    import hashlib as _hashlib
    for spec in specs:
        cb = spec.get("customBuilder")
        if not cb:
            continue
        tool = spec["toolId"]
        expected = cb.get("sha256") or ""
        module_path = _BUILDER_MODULE_CACHE_DIR / f"{tool}.py"
        if module_path.exists() and _hashlib.sha256(module_path.read_bytes()).hexdigest() == expected:
            continue  # already in sync
        try:
            r = sess.get(f"{server}/api/v1/agent/tool-specs/{tool}/builder", timeout=30)
            if r.status_code != 200:
                _log("sync", f"failed to fetch builder module for '{tool}': HTTP {r.status_code}")
                continue
            actual = _hashlib.sha256(r.content).hexdigest()
            if actual != expected:
                _log("sync", f"builder module for '{tool}' failed checksum verification — not caching")
                continue
            _BUILDER_MODULE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            module_path.write_bytes(r.content)
            _log("sync", f"synced builder module for '{tool}' (sha256={actual[:12]}…)")
        except requests.RequestException as e:
            _log("sync", f"failed to fetch builder module for '{tool}': {e}")


def sync_tool_specs(sess, server: str, cfg: dict, current_version: "int | None",
                     server_version: "int | None") -> "tuple[list[dict], int] | None":
    """Refetches GET /agent/tool-specs only when `server_version` (from the heartbeat
    response's toolSpecsVersion) differs from what's already cached — cheap enough to
    check every heartbeat since the common case is a no-op. Returns None (caller keeps
    whatever it already has) when nothing changed or the fetch failed, so a transient
    error never blanks out a working catalog."""
    if server_version is not None and server_version == current_version:
        return None
    try:
        r = sess.get(f"{server}/api/v1/agent/tool-specs", timeout=15)
        if r.status_code != 200:
            _log("sync", f"tool-specs fetch failed: HTTP {r.status_code} — keeping cached catalog")
            return None
        specs = r.json() or []
    except requests.RequestException as e:
        _log("sync", f"tool-specs fetch failed: {e} — keeping cached catalog")
        return None
    version = server_version if server_version is not None else 0
    _save_tool_specs_cache(specs, version)
    _sync_custom_builder_modules(sess, server, cfg, specs)
    _log("sync", f"tool-specs catalog refreshed ({len(specs)} tool(s), version={version})")
    return specs, version


def _extract_version_tuple(s: "str | None"):
    if not s:
        return None
    m = _re.search(r"\d+(\.\d+)*", s)
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(0).split("."))
    except ValueError:
        return None


def _version_at_least(detected: "str | None", min_version: "str | None") -> bool:
    """Best-effort — see AgentToolSpec#minVersion's own doc (ares-core). Either side
    failing to parse as leading dot-separated integers is treated as compatible,
    never blocking, since CLI tool version banners aren't reliably semver."""
    if not min_version:
        return True
    dt = _extract_version_tuple(detected)
    mt = _extract_version_tuple(min_version)
    if dt is None or mt is None:
        return True
    return dt >= mt


def probe_capabilities(specs: list[dict], cfg: dict) -> "tuple[list[dict], list[dict]]":
    """For each tool declared in `specs` (the current tool-spec catalog — see
    sync_tool_specs), checks binary presence + minVersion + requiresRoot + (when the
    spec declares a customBuilder) module sync/checksum + local policy
    (allow_agent_plugin_code). A tool is only reported in the returned `capabilities`
    list when every applicable check passes; otherwise it's reported in `unavailable`
    with a human-readable reason — advisory only (see UnavailableToolEntry's own doc,
    ares-core), task dispatch only ever reads `capabilities`."""
    capabilities: list[dict] = []
    unavailable: list[dict] = []
    can_root = (os.name == "posix" and os.geteuid() == 0)
    for spec in specs:
        tool = spec["toolId"]
        binary = spec.get("binary") or tool
        path = shutil.which(binary)
        if not path:
            unavailable.append({"toolId": tool, "reason": f"'{binary}' not found on $PATH"})
            continue
        version = None
        for flag in ("--version", "-V", "-v"):
            try:
                proc = subprocess.run([path, flag], capture_output=True, text=True, timeout=4)
                blob = (proc.stdout or proc.stderr or "").strip().splitlines()
                if blob:
                    version = blob[0][:120]
                    break
            except (subprocess.TimeoutExpired, OSError):
                continue

        min_version = spec.get("minVersion")
        if min_version and not _version_at_least(version, min_version):
            unavailable.append({"toolId": tool,
                                 "reason": f"version {version or 'unknown'} is older than required {min_version}"})
            continue
        if spec.get("requiresRoot") and not can_root:
            unavailable.append({"toolId": tool, "reason": "requires the agent to run as root"})
            continue

        cb = spec.get("customBuilder")
        if cb:
            if not cfg.get("allow_agent_plugin_code"):
                unavailable.append({"toolId": tool,
                                     "reason": "requires allow_agent_plugin_code (disabled on this agent)"})
                continue
            module_path = _custom_builder_module_path(tool)
            if module_path is None:
                unavailable.append({"toolId": tool, "reason": "builder module not yet synced"})
                continue
            try:
                _verify_custom_builder_checksum(tool, spec, module_path)
            except RuntimeError as e:
                unavailable.append({"toolId": tool, "reason": str(e)})
                continue

        capabilities.append({"tool": tool, "path": path, "version": version, "canRoot": can_root})
    return capabilities, unavailable


# ── HTTP helpers ─────────────────────────────────────────────────────────────

try:
    import requests
except ImportError:
    sys.stderr.write("ares-agent requires the 'requests' library. Install with: pip install requests\n")
    sys.exit(1)


def _session(cfg: dict) -> requests.Session:
    s = requests.Session()
    if "token" in cfg:
        s.headers.update({"X-Agent-Token": cfg["token"]})
    s.headers.update({"User-Agent": f"ares-agent/{AGENT_VERSION}"})
    return s


# ── subcommands ──────────────────────────────────────────────────────────────

def cmd_capabilities(_args):
    """Debug/inspection command — best-effort fetches the live tool-spec catalog if this
    host is already enrolled (so the reported capabilities reflect real minVersion/
    requiresRoot/customBuilder gating), otherwise reports nothing (there is no static
    tool list left to fall back to — see probe_capabilities's own doc)."""
    cfg: dict = {}
    specs: list[dict] = []
    try:
        cfg = load_config()
    except SystemExit:
        cfg = {}
    if cfg.get("server") and cfg.get("token"):
        try:
            sess = _session(cfg)
            r = sess.get(f"{cfg['server'].rstrip('/')}/api/v1/agent/tool-specs", timeout=10)
            if r.status_code == 200:
                specs = r.json() or []
        except requests.RequestException:
            pass
    caps, unavailable = probe_capabilities(specs, cfg)
    json.dump({"capabilities": caps, "unavailable": unavailable}, sys.stdout, indent=2)
    sys.stdout.write("\n")


def cmd_version(_args):
    print(AGENT_VERSION)


def cmd_enroll(args):
    server = args.server.rstrip("/")
    # No token yet at this point (that's what this call mints) — GET /agent/tool-specs
    # requires one, so there is no catalog to probe against and this snapshot is always
    # empty. Harmless: the real, validated capability list is reported at the first
    # heartbeat, seconds after `ares-agent run` starts.
    payload = {
        "code": args.code,
        "hostname": socket.gethostname(),
        "platform": platform.system().lower(),
        "arch": platform.machine().lower(),
        "version": AGENT_VERSION,
        "capabilities": probe_capabilities([], {})[0],
    }
    print(f"Enrolling with {server}…")
    r = requests.post(f"{server}/api/v1/agent/enroll", json=payload, timeout=10)
    if r.status_code != 200:
        sys.stderr.write(f"Enrollment failed: HTTP {r.status_code} {r.text}\n")
        sys.exit(1)
    body = r.json()
    cfg = {"server": server, "token": body["token"], "agentId": body["agentId"],
           "allow_agent_plugin_code": bool(getattr(args, "allow_plugin_code", False))}
    save_config(cfg)
    print(f"✓ Enrolled as agent #{body['agentId']} (v{AGENT_VERSION})")
    print(f"  Host:              {payload['hostname']} ({payload['platform']}/{payload['arch']})")
    print(f"  Config:            {config_path()}")
    print(f"  Heartbeat interval: {body.get('heartbeatIntervalSeconds', 30)}s")
    print(f"  Plugin code:       {'allowed' if cfg['allow_agent_plugin_code'] else 'disabled'} "
          f"(toggle with --allow-plugin-code, or edit '{config_path()}' later)")
    print("\nStart the daemon with: ares-agent run")


# ── generic tool-spec interpreter (Fase 2 / Part B) ──────────────────────────
# Replaces the old per-tool build_X_cmd()/TOOL_BUILDERS map entirely. Every scan
# tool's command line is now built the SAME way, driven by its AgentToolSpec
# (fetched from GET /agent/tool-specs — see sync_tool_specs above): walk
# spec['fields'], emit each per its declared type/flag/repeat/valueTemplate,
# emit targets per spec['targetEmission']/['targetFlag'], and prefix
# spec['outputArgs'] (with the {outPath} placeholder substituted) right after
# the binary. A tool whose command genuinely can't be expressed this way
# (ffuf's FUZZ1/FUZZ2 wildcard splitting) instead declares a customBuilder
# module and is routed to run_custom_builder() below.
#
# Defense-in-depth: the server's AgentToolSpecRegistry already rejects an
# unknown/malformed arg before a task is ever created, but every value is
# re-validated here too (the same pattern/min/max/options the spec itself
# declares) so a value that somehow reached this agent malformed still can't
# put anything unexpected on the argv line — a compromised/buggy server is
# not trusted blindly.

def _bin(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"tool '{name}' not found on $PATH")
    return path


def _spec_for_tool(specs: list[dict], tool: str) -> "dict | None":
    for s in specs:
        if s.get("toolId") == tool:
            return s
    return None


def _validate_single_field_value(tool: str, field: dict, value) -> str:
    """Mirrors AgentToolSpecRegistry#validateSingleValue (ares-core, Java) — the same
    rules, re-applied client-side. Returns the value coerced to the exact string that
    will be emitted on the argv line (after valueTemplate substitution, if any)."""
    ftype = field.get("type")
    key = field["key"]
    if ftype == "enum":
        options = field.get("options") or []
        out = str(value)
        if options and out not in options:
            raise RuntimeError(f"{tool}.{key}: must be one of {options}")
    elif ftype == "number":
        try:
            n = float(value)
        except (TypeError, ValueError):
            raise RuntimeError(f"{tool}.{key}: must be a number")
        if field.get("min") is not None and n < field["min"]:
            raise RuntimeError(f"{tool}.{key}: must be >= {field['min']}")
        if field.get("max") is not None and n > field["max"]:
            raise RuntimeError(f"{tool}.{key}: must be <= {field['max']}")
        out = str(int(n)) if n == int(n) else str(n)
    elif ftype in ("string", "server_fetch"):
        out = str(value)
        pattern = field.get("pattern")
        if pattern and not _re.match(pattern, out):
            raise RuntimeError(f"{tool}.{key}: invalid value")
    else:
        out = str(value)
    template = field.get("valueTemplate")
    if template:
        out = template.replace("{value}", out)
    return out


def _resolve_server_fetch_value(cfg: dict, field: dict, raw_value) -> str:
    """Downloads (and caches locally, keyed by the resolved URL) whatever resource
    `urlTemplate` points at — with {value} substituted for this field's own raw value —
    returning the local file path. Generalizes the old KB-wordlist-download special
    case (see AgentToolSpec.Field#type's own doc, ares-core) to any tool/field
    declaring type: "server_fetch", not just ffuf's wordlist."""
    import hashlib as _hashlib
    import urllib.request as _urllib_req
    import urllib.error as _urllib_err

    url_template = field.get("urlTemplate") or ""
    path = url_template.replace("{value}", str(raw_value))
    server_url = cfg.get("server", "").rstrip("/")
    full_url = server_url + path

    _WL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _WL_CACHE_DIR / _hashlib.sha256(full_url.encode()).hexdigest()[:32]
    if cache_path.exists():
        return str(cache_path)

    req = _urllib_req.Request(full_url, headers={"X-Agent-Token": cfg.get("token", "")})
    try:
        with _urllib_req.urlopen(req, timeout=300) as resp:
            data = resp.read()
    except _urllib_err.URLError as e:
        raise RuntimeError(f"failed to fetch '{path}': {e}")
    cache_path.write_bytes(data)
    return str(cache_path)


def _resolve_field_args_value(cfg: dict, field: dict, args: dict):
    """Returns the resolved value for one field out of `args` — a server_fetch field's
    raw value (e.g. a KB wordlist id) is replaced by the downloaded local file path;
    every other type passes through unchanged. None when the field is absent/blank
    and declares no defaultValue (meaning: don't emit it at all)."""
    raw = args.get(field["key"])
    if raw is None or raw == "" or raw == []:
        default = field.get("defaultValue")
        if default is None:
            return None
        raw = default
    if field.get("type") == "server_fetch":
        if field.get("repeat"):
            items = raw if isinstance(raw, list) else [raw]
            return [_resolve_server_fetch_value(cfg, field, v) for v in items]
        return _resolve_server_fetch_value(cfg, field, raw)
    return raw


def _emit_field(cmd: list, tool: str, field: dict, resolved_value) -> None:
    """Appends one field's argv contribution. `resolved_value` is already
    server_fetch-resolved (a local path, not a raw KB id) where applicable."""
    ftype = field.get("type")
    flag = field.get("flag")
    if ftype == "boolean_flag":
        if resolved_value:
            if not flag:
                raise RuntimeError(f"{tool}.{field['key']}: boolean_flag field has no 'flag'")
            cmd.append(flag)
        return
    values = resolved_value if field.get("repeat") else [resolved_value]
    for v in values:
        if v is None:
            continue
        emitted = _validate_single_field_value(tool, field, v)
        if flag:
            cmd += [flag, emitted]
        else:
            cmd.append(emitted)


def build_cmd_from_spec(spec: dict, args: dict, workdir: Path, cfg: dict) -> tuple[list[str], Path]:
    tool = spec["toolId"]
    targets = args.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    if not targets:
        raise RuntimeError(f"{tool}: no targets")

    out = workdir / f"{tool}.out"

    if spec.get("customBuilder"):
        return run_custom_builder(spec, args, targets, workdir, out, cfg)

    emission = spec.get("targetEmission")
    target_flag = spec.get("targetFlag")
    binary = _bin(spec["binary"])
    cmd = [binary]

    def _target_file() -> Path:
        f = workdir / f"{tool}-targets.txt"
        f.write_text("\n".join(str(t).strip() for t in targets) + "\n")
        return f

    # Target-first emission modes put the target flag immediately after the binary,
    # matching every tool that historically did so (httpx/dnsx/nuclei/katana's -l/
    # -list, wpscan's --url) — CLI flag order rarely matters to a getopt-style parser,
    # but matching the exact invocation shape these tools were already tested with is
    # the safer default over an arbitrary new order.
    if emission == "list-file":
        cmd += [target_flag, str(_target_file())]
    elif emission == "single-flag":
        cmd += [target_flag, str(targets[0])]

    for tok in spec.get("outputArgs") or []:
        cmd.append(str(out) if tok == "{outPath}" else tok)

    for field in spec.get("fields") or []:
        resolved = _resolve_field_args_value(cfg, field, args)
        if resolved is None:
            continue
        _emit_field(cmd, tool, field, resolved)

    if emission == "positional":
        cmd += [str(t) for t in targets]
    elif emission == "joined":
        cmd += [target_flag, ",".join(str(t) for t in targets)]

    return cmd, out


def run_custom_builder(spec: dict, args: dict, targets: list, workdir: Path,
                        out: Path, cfg: dict) -> tuple[list[str], Path]:
    """Spawns the tool's customBuilder module (see AgentToolSpec.CustomBuilder's own
    doc, ares-core) as an isolated, short-lived subprocess — never imported into this
    process, never handed this agent's auth token or config. Every declared field's
    resolved value (server_fetch fields already downloaded to a local path) is passed
    in generically; only `binary`, `outPath` and `target` are agent-specific additions
    to the documented stdin contract."""
    tool = spec["toolId"]
    if spec.get("maxTargets") == 1 and len(targets) != 1:
        raise RuntimeError(f"{tool}: exactly one target required")

    module_path = _custom_builder_module_path(tool)
    if module_path is None:
        raise RuntimeError(f"{tool}: builder module not synced "
                            f"(allow_agent_plugin_code disabled, or sync hasn't run yet)")
    _verify_custom_builder_checksum(tool, spec, module_path)

    payload = {"binary": _bin(spec["binary"]), "outPath": str(out), "target": str(targets[0])}
    for field in spec.get("fields") or []:
        payload[field["key"]] = _resolve_field_args_value(cfg, field, args)

    try:
        proc = subprocess.run(
            [sys.executable, str(module_path)],
            input=json.dumps(payload) + "\n", capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{tool}: builder module timed out")
    try:
        response = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError:
        raise RuntimeError(f"{tool}: builder module produced invalid output: {proc.stdout[:500]!r}")
    if "error" in response:
        raise RuntimeError(f"{tool}: {response['error']}")
    cmd = response.get("cmd")
    if not isinstance(cmd, list) or not cmd:
        raise RuntimeError(f"{tool}: builder module returned no command")
    return [str(c) for c in cmd], Path(response.get("outPath") or out)


def _preflight_check(spec: dict, cfg: dict) -> None:
    """Re-verifies binary presence + customBuilder checksum right before executing —
    the heartbeat that reported this tool available may be up to one interval stale
    (binary removed, builder module cache cleared, policy toggled, ...). Raises
    RuntimeError with a clear message on failure, so the task fails fast and cleanly
    instead of attempting to run something broken."""
    tool = spec["toolId"]
    binary = spec.get("binary") or tool
    if not shutil.which(binary):
        raise RuntimeError(f"'{binary}' no longer found on $PATH")
    cb = spec.get("customBuilder")
    if cb:
        if not cfg.get("allow_agent_plugin_code"):
            raise RuntimeError("allow_agent_plugin_code is disabled on this agent")
        module_path = _custom_builder_module_path(tool)
        if module_path is None:
            raise RuntimeError("builder module not synced")
        _verify_custom_builder_checksum(tool, spec, module_path)



# ── task execution ──────────────────────────────────────────────────────────

import ipaddress


def _classify_target(target: str) -> str:
    """
    Returns 'private', 'public', or 'unknown' for the given target. Tries IP/CIDR first;
    falls back to DNS resolution for hostnames. Loopback/link-local count as private.
    """
    if not target:
        return "unknown"
    try:
        net = ipaddress.ip_network(target.strip(), strict=False)
        return "private" if (net.is_private or net.is_loopback or net.is_link_local) else "public"
    except ValueError:
        pass
    try:
        # Strip scheme/path if the user passed a URL
        host = target
        if "://" in host:
            host = host.split("://", 1)[1].split("/", 1)[0]
        host = host.split(":", 1)[0]  # drop port
        addr = socket.gethostbyname(host)
        ip = ipaddress.ip_address(addr)
        return "private" if (ip.is_private or ip.is_loopback or ip.is_link_local) else "public"
    except Exception:
        return "unknown"


def _local_ip_toward(target: str) -> str | None:
    """The local interface IP that would route to `target` (no packet sent)."""
    host = target
    if "://" in host:
        host = host.split("://", 1)[1].split("/", 1)[0]
    host = host.split(":", 1)[0].split("/", 1)[0]  # strip port + CIDR
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def _is_routable_public(ip_str) -> bool:
    """True only if ip_str is a routable public address (not loopback, private, link-local…)."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_loopback or ip.is_private or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


# Plain-text echo services that return only the caller's public IP. Tried in order;
# first routable answer wins. Used when the platform's /my-ip view is degenerate
# (agent and server colocated or behind the same NAT).
PUBLIC_IP_ECHOES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
)


def _query_public_ip_externally() -> str | None:
    """Ask a public echo service for our NAT'd egress IP. Returns None if none answers."""
    for url in PUBLIC_IP_ECHOES:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code != 200:
                continue
            ip = (r.text or "").strip()
            if _is_routable_public(ip):
                return ip
        except requests.RequestException:
            continue
    return None


def determine_source_ip(sess: requests.Session, server: str, targets: list) -> str | None:
    """
    Picks the source IP to report alongside this task's result:
      • Public targets   → server-observed IP (post-NAT public address). If the server's
                           view is degenerate (loopback / RFC1918 — common when the agent
                           and platform share a host or sit on the same LAN), fall back
                           to an external echo service (ipify/ifconfig.me/…). Only if
                           that also fails do we resort to the local interface IP.
      • Private targets  → local interface IP that routes to the target.
      • Nothing usable   → None; the server keeps whatever value was previously stored.
    """
    if not targets:
        return None

    classes = {_classify_target(t) for t in targets if t}

    # Compute the local interface IP — it's the last-resort fallback for both branches.
    local_ip = None
    for t in targets:
        local_ip = _local_ip_toward(t)
        if local_ip:
            break

    if "public" in classes:
        try:
            r = sess.get(f"{server}/api/v1/agent/my-ip", timeout=10)
            if r.status_code == 200:
                server_view = (r.json() or {}).get("ip")
                if _is_routable_public(server_view):
                    return server_view
                # Server saw a loopback / private address (agent & platform colocated, or
                # a reverse-proxy isn't forwarding the real client IP). Fall through to
                # an external echo service.
        except requests.RequestException:
            pass
        external = _query_public_ip_externally()
        if external:
            return external
        return local_ip  # last resort — almost certainly wrong for public targets

    # All targets private — local interface IP is the right answer.
    return local_ip


def execute_task(sess: requests.Session, server: str, task: dict, cfg: dict, specs: list[dict]) -> None:
    """Run one task: build cmd, execute, upload result. Always reports completion or failure."""
    task_id = task["id"]
    tool = task["tool"]
    args = json.loads(task.get("args") or "{}")

    spec = _spec_for_tool(specs, tool)
    if not spec:
        _log("task", f"[{task_id}] unsupported tool '{tool}' — failing")
        sess.post(f"{server}/api/v1/agent/tasks/{task_id}/fail",
                  json={"error": f"unsupported tool '{tool}' (no plugin installed, or catalog not yet synced)"},
                  timeout=10)
        return

    workdir = None
    t_start = time.monotonic()
    try:
        workdir = Path(tempfile.mkdtemp(prefix=f"ares-task-{task_id}-",
                                        dir=_WORKDIR_BASE))
        try:
            # Pre-flight re-check: the heartbeat that reported this tool available may
            # be stale by up to one interval (binary removed, builder cache cleared, …).
            _preflight_check(spec, cfg)
            cmd, out_path = build_cmd_from_spec(spec, args, workdir, cfg)
        except Exception as e:
            _log("task", f"[{task_id}] command build failed for {tool}: {e}")
            sess.post(f"{server}/api/v1/agent/tasks/{task_id}/fail",
                      json={"error": f"could not build command: {e}"}, timeout=10)
            return

        # Resolve source IP BEFORE running the scan so even if the tool changes the
        # routing state (rare), we still report the IP that was used to plan it.
        targets = args.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        source_ip = determine_source_ip(sess, server, targets)

        target_count = len(targets)
        _log("task", f"[{task_id}] starting {tool} — {target_count} target(s)"
             + (f", source_ip={source_ip}" if source_ip else ""))
        _log("task", f"[{task_id}] cmd: {' '.join(cmd)}")

        sess.post(f"{server}/api/v1/agent/tasks/{task_id}/started", timeout=10)

        # Use Popen so we can poll for server-side cancellation every 5 seconds
        # without blocking the thread for the full duration of the scan.
        stdout_file = workdir / "proc.stdout"
        stderr_file = workdir / "proc.stderr"
        timeout_minutes = task.get("timeoutMinutes")
        timeout_seconds = timeout_minutes * 60 if timeout_minutes else 3600  # fall back to 1h if unset
        deadline = t_start + timeout_seconds

        fout = open(stdout_file, "wb")  # noqa: WPS515
        ferr = open(stderr_file, "wb")
        try:
            proc = subprocess.Popen(cmd, stdout=fout, stderr=ferr)
        finally:
            fout.close()
            ferr.close()

        cancelled = False
        timed_out = False
        while proc.poll() is None:
            time.sleep(5)
            if time.monotonic() > deadline:
                timed_out = True
                _log("task", f"[{task_id}] exceeded {timeout_seconds}s time limit — killing process (pid={proc.pid})")
                try:
                    proc.kill()
                except OSError:
                    pass
                break
            try:
                cr = sess.get(f"{server}/api/v1/agent/tasks/{task_id}/cancelled", timeout=5)
                if cr.status_code == 200 and cr.json().get("cancelled"):
                    cancelled = True
                    _log("task", f"[{task_id}] cancelled by server — killing process (pid={proc.pid})")
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    break
            except requests.RequestException:
                pass  # network hiccup — keep running

        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        exit_code = proc.returncode
        elapsed = time.monotonic() - t_start

        if timed_out:
            _log("task", f"[{task_id}] timed out after {elapsed:.0f}s — failing")
            sess.post(f"{server}/api/v1/agent/tasks/{task_id}/fail",
                      json={"error": f"task exceeded {timeout_seconds}s time limit"}, timeout=10)
            return

        if cancelled:
            _log("task", f"[{task_id}] stopped after {elapsed:.1f}s (cancelled — no upload)")
            return  # server already set status=cancelled; no further API call needed

        stderr_text = stderr_file.read_text(errors="replace") if stderr_file.exists() else ""
        # All tools write results to a dedicated output file (-o flag). stdout only ever
        # contains progress messages or error text — never valid scan output. If the output
        # file is missing (e.g. tool crashed before creating it), upload 0 bytes so the
        # backend treats it as a zero-findings run rather than trying to parse error text.
        result_bytes = out_path.read_bytes() if out_path.exists() else b""
        result_source = out_path.name if out_path.exists() else "no-output-file"
        _log("task", f"[{task_id}] {tool} done in {elapsed:.1f}s — exit={exit_code}, "
             f"output={len(result_bytes)}B ({result_source})")
        if exit_code != 0 and stderr_text:
            _log("task", f"[{task_id}] stderr (last 1500 chars):\n{stderr_text.strip()[-1500:]}")

        files = {"file": (out_path.name if out_path.exists() else "output.bin", result_bytes,
                          "application/octet-stream")}
        data = {"exitCode": str(exit_code), "stderr": stderr_text[:4000]}
        if source_ip:
            data["sourceIp"] = source_ip
        sess.post(f"{server}/api/v1/agent/tasks/{task_id}/complete",
                  files=files, data=data, timeout=120)
        _log("task", f"[{task_id}] result uploaded")
    except Exception as e:
        elapsed = time.monotonic() - t_start
        _log("task", f"[{task_id}] unexpected error after {elapsed:.1f}s: {e}")
        try:
            sess.post(f"{server}/api/v1/agent/tasks/{task_id}/fail",
                      json={"error": str(e)}, timeout=10)
        except Exception:
            pass
    finally:
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)


def maybe_self_update(server: str, latest_version: str) -> None:
    """
    Download the new agent script, overwrite the running script on disk, then replace
    the current process via os.execv() so the new version starts immediately — no
    dependency on a supervisor restart policy.

    If anything fails the error is logged and this function returns normally; the
    caller continues running on the current version until the next heartbeat cycle.

    No signature verification yet (deferred until v2 — TUF/cosign). The agent already
    trusts the server it heartbeats against; if that is compromised the agent is toast
    regardless.
    """
    url = f"{server}/api/v1/agent/dist/ares_agent.py"
    _log("update", f"downloading v{latest_version} from {url}")
    try:
        r = requests.get(url, timeout=30)
        if r.status_code != 200 or not r.content:
            _log("update", f"download failed: HTTP {r.status_code} — will retry next heartbeat")
            return
        here = Path(__file__).resolve()
        if not here.exists() or not os.access(here.parent, os.W_OK):
            _log("update", f"cannot write to {here} — skipping (check file permissions)")
            return
        size_kb = len(r.content) / 1024
        _log("update", f"downloaded {size_kb:.1f} KB — writing to {here}")
        tmp = here.with_suffix(".new")
        tmp.write_bytes(r.content)
        os.replace(tmp, here)
        _log("update", f"script replaced with v{latest_version} — re-execing now…")
        sys.stderr.flush()
        # Replace the current process image with a fresh invocation of the new script.
        # On POSIX this is atomic: the new Python process reads the updated file.
        # On Windows os.execv spawns a new process and exits the current one.
        os.execv(sys.executable, sys.argv)
        # execv never returns on success — reaching here only if execv raised
    except OSError as e:
        _log("update", f"re-exec failed ({e}) — please restart the agent manually to load v{latest_version}")
    except Exception as e:
        _log("update", f"update failed: {e}")


def cmd_run(args):
    global _WORKDIR_BASE
    cfg = load_config()
    server = cfg["server"].rstrip("/")
    # Env var override — lets an operator toggle this for a single run without
    # re-enrolling (same CLI-flag > env-var > persisted-default precedence as
    # --workdir/ARES_WORKDIR and --max-concurrent-tasks/ARES_MAX_CONCURRENT_TASKS
    # above). Never written back to the config file.
    if os.environ.get("ARES_ALLOW_PLUGIN_CODE") == "1":
        cfg["allow_agent_plugin_code"] = True

    # Max concurrent tasks: CLI flag > env var > default 1.
    max_concurrent = (
        getattr(args, "max_concurrent_tasks", None)
        or int(os.environ.get("ARES_MAX_CONCURRENT_TASKS", "1"))
    )
    max_concurrent = max(1, int(max_concurrent))

    # Workdir base: CLI flag > env var > system temp.
    workdir_arg = getattr(args, "workdir", None) or os.environ.get("ARES_WORKDIR")
    _log("start", f"ARES_WORKDIR env:      {os.environ.get('ARES_WORKDIR')!r}")
    if workdir_arg:
        try:
            _WORKDIR_BASE = Path(workdir_arg)
            _WORKDIR_BASE.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            _log("start", f"WARNING: cannot use workdir '{workdir_arg}': {e} — falling back to system temp")
            _WORKDIR_BASE = None
    else:
        _WORKDIR_BASE = None  # tempfile default (usually /tmp)

    # When the home directory is read-only (e.g. systemd ProtectHome=read-only),
    # tools that rely on XDG_CACHE_HOME for browser caching (nuclei headless via
    # rod) will fail trying to create ~/.cache/rod. Always redirect to the writable
    # workdir when one is configured, regardless of any inherited value.
    if _WORKDIR_BASE:
        xdg_cache = _WORKDIR_BASE / ".cache"
        try:
            xdg_cache.mkdir(parents=True, exist_ok=True)
            os.environ["XDG_CACHE_HOME"] = str(xdg_cache)
            _log("start", f"XDG_CACHE_HOME → {xdg_cache}")
        except OSError as e:
            _log("start", f"WARNING: could not set XDG_CACHE_HOME to '{xdg_cache}': {e}")

    # go-rod (used by nuclei -headless/-dast) tries to download a browser into
    # ~/.cache/rod when it can't find one. ROD_BROWSER_BIN bypasses this entirely:
    # rod uses the pointed binary directly without touching the cache directory.
    #
    # In systemd-hardened environments (ProtectHome, NoNewPrivileges, etc.) Chrome
    # segfaults if it tries to set up its own sandbox. We create a tiny wrapper
    # script that injects --no-sandbox so Chrome skips sandboxing entirely.
    #
    # IMPORTANT: always rebuild the wrapper regardless of what ROD_BROWSER_BIN
    # is currently set to. When the agent auto-updates via execv(), the child
    # inherits the parent's env and would skip this block if guarded by
    # "not in os.environ" — leaving the old wrapper in place even after we
    # change its contents in a new release.
    _browser_found = None
    for _browser in [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        "/usr/bin/microsoft-edge",
        "/usr/bin/microsoft-edge-stable",
    ]:
        if os.path.isfile(_browser) and os.access(_browser, os.X_OK):
            _browser_found = _browser
            break

    if _browser_found:
        # Rebuild the wrapper every startup so flag changes in new releases take effect.
        _wrapper_dir = _WORKDIR_BASE if _WORKDIR_BASE else _pathlib.Path("/tmp")
        _wrapper_path = _wrapper_dir / "chrome-no-sandbox.sh"
        try:
            _wrapper_path.write_text(
                f"#!/bin/sh\nexec {_browser_found}"
                f" --no-sandbox --disable-setuid-sandbox"
                f" --disable-dev-shm-usage --disable-crashpad"
                f" \"$@\"\n"
            )
            _wrapper_path.chmod(0o755)
            os.environ["ROD_BROWSER_BIN"] = str(_wrapper_path)
            _log("start", f"ROD_BROWSER_BIN → {_wrapper_path} (wraps {_browser_found} with --no-sandbox --disable-crashpad)")
        except OSError as e:
            os.environ["ROD_BROWSER_BIN"] = _browser_found
            _log("start", f"ROD_BROWSER_BIN → {_browser_found} (wrapper creation failed: {e})")
    else:
        _log("start", "WARNING: no browser binary found — nuclei -headless/-dast tasks will fail")

    _cleanup_orphaned_workdirs(_WORKDIR_BASE)

    _log("start", f"ares-agent v{AGENT_VERSION} (pid={os.getpid()})")
    _log("start", f"server:              {server}")
    _log("start", f"max concurrent tasks: {max_concurrent}")
    _log("start", f"workdir base:         {_WORKDIR_BASE or 'system temp (usually /tmp)'}")
    _log("start", f"config:              {config_path()}")
    free_mb = _disk_free_bytes(_WORKDIR_BASE) // (1024 * 1024)
    _log("start", f"disk free:           {free_mb} MB")

    # Tool-spec catalog: start from whatever's cached on disk from a previous run (so
    # a task recovered below — see "Recover in-flight tasks" — has something to look
    # up immediately), then force a fresh fetch now that we have a token.
    specs, tool_specs_version = _load_tool_specs_cache()
    synced = sync_tool_specs(_session(cfg), server, cfg, tool_specs_version, None)
    if synced is not None:
        specs, tool_specs_version = synced

    caps, unavail = probe_capabilities(specs, cfg)
    if caps:
        tool_list = ", ".join(
            f"{c['tool']}{'@' + c['version'].split()[0][:20] if c.get('version') else ''}"
            for c in caps
        )
        _log("start", f"detected tools: {tool_list}")
    else:
        _log("start", "no scan tools detected — tasks requiring tools will fail")
    if unavail:
        _log("start", "unavailable: " + ", ".join(f"{u['toolId']} ({u['reason']})" for u in unavail))

    active_lock = threading.Lock()
    active_tasks: set = set()  # task IDs currently running
    task_done_event = threading.Event()  # signals heartbeat to claim next task immediately

    def _task_done(task_id):
        with active_lock:
            active_tasks.discard(task_id)
            remaining = len(active_tasks)
        _log("task", f"[{task_id}] worker done — active: {remaining}/{max_concurrent}")
        task_done_event.set()  # wake up heartbeat loop to claim next task without delay

    def _run_task(task: dict):
        task_id = task["id"]
        # Each worker gets its own session so concurrent HTTP calls don't race.
        task_sess = _session(cfg)
        try:
            # `specs` is rebound (never mutated in place) by the heartbeat loop below
            # whenever the catalog changes, so each new task always sees the latest
            # version without needing a lock — reading a plain name is atomic in
            # CPython, and a task that's already running keeps whatever cmd/spec it
            # built at start regardless of a later rebind.
            execute_task(task_sess, server, task, cfg, specs)
        finally:
            _task_done(task_id)

    executor = ThreadPoolExecutor(max_workers=max_concurrent, thread_name_prefix="ares-task")

    # ── Recover in-flight tasks from before restart ──────────────────────────
    # On startup (including after a self-update restart) the agent asks the server
    # for tasks that were dispatched/running to it but never completed. Those tasks
    # are re-submitted to the executor before claiming any new work.
    _log("start", "checking for tasks to recover from previous run…")
    try:
        r = _session(cfg).get(f"{server}/api/v1/agent/tasks/assigned", timeout=10)
        if r.status_code == 200:
            assigned = r.json() or []
            if assigned:
                _log("start", f"recovering {len(assigned)} task(s) from previous run")
                for task in assigned:
                    task_id = task["id"]
                    tool = task.get("tool", "?")
                    with active_lock:
                        active_tasks.add(task_id)
                        n_active = len(active_tasks)
                    _log("task", f"[{task_id}] recovering {tool} — active: {n_active}/{max_concurrent}")
                    executor.submit(_run_task, task)
            else:
                _log("start", "no tasks to recover")
        else:
            _log("start", f"task recovery check returned HTTP {r.status_code} — proceeding normally")
    except requests.RequestException as e:
        _log("start", f"task recovery check failed: {e} — proceeding normally")
    # ─────────────────────────────────────────────────────────────────────────

    # heartbeat loop runs in the main thread; tasks run in the pool.
    interval = 30
    backoff = 5
    heartbeat_count = 0
    # Version to apply once all active tasks finish. Set when an update is detected
    # while tasks are running; cleared after a failed attempt (heartbeat will re-set it).
    pending_update_version: str | None = None
    try:
        while True:
            try:
                with active_lock:
                    current_active = list(active_tasks)

                # Deferred update: apply now that the task queue is empty.
                if pending_update_version and not current_active:
                    _log("update", f"all tasks done — applying deferred update to v{pending_update_version}")
                    maybe_self_update(server, pending_update_version)
                    # execv never returns on success; reaching here means the attempt failed.
                    pending_update_version = None

                free_bytes = _disk_free_bytes(_WORKDIR_BASE)
                caps, unavail = probe_capabilities(specs, cfg)
                payload = {
                    "version": AGENT_VERSION,
                    "capabilities": caps,
                    "activeTaskIds": current_active,
                    "maxConcurrentTasks": max_concurrent,
                    "diskFreeBytes": free_bytes,
                    "unavailableTools": unavail,
                }
                r = _session(cfg).post(f"{server}/api/v1/agent/heartbeat", json=payload, timeout=10)
                heartbeat_count += 1

                if r.status_code == 200:
                    body = r.json()
                    interval = int(body.get("heartbeatIntervalSeconds", 30))
                    backoff = 5

                    # Refresh the tool-spec catalog only when the server's version counter
                    # actually moved — the common case is a cheap no-op comparison.
                    synced = sync_tool_specs(_session(cfg), server, cfg, tool_specs_version,
                                              body.get("toolSpecsVersion"))
                    if synced is not None:
                        specs, tool_specs_version = synced

                    # Periodic alive message every ~5 minutes (10 × 30s intervals).
                    if heartbeat_count % 10 == 1:
                        disk_warn = (f", disk: {free_bytes // (1024*1024)} MB ⚠"
                                     if free_bytes < _DISK_WARN_FREE_BYTES else "")
                        _log("heartbeat", f"ok — active: {len(current_active)}/{max_concurrent}, "
                             f"cycle: {heartbeat_count}, interval: {interval}s{disk_warn}")

                    # Periodic stale-workdir cleanup (every 5 heartbeats ≈ every 2.5 min).
                    # Reclaims disk from dirs left by tasks that were SIGKILL'd mid-run.
                    if heartbeat_count % 5 == 0:
                        with active_lock:
                            _active_ids = set(active_tasks)
                        _removed = _cleanup_stale_workdirs(_WORKDIR_BASE, _active_ids)
                        if _removed:
                            _free_after = _disk_free_bytes(_WORKDIR_BASE) // (1024 * 1024)
                            _log("cleanup", f"removed {_removed} stale task workdir(s); "
                                 f"disk free now: {_free_after} MB")

                    latest = body.get("latestAgentVersion")
                    if latest and _is_newer_version(latest, AGENT_VERSION):
                        if current_active:
                            # Tasks running — defer so we don't interrupt in-flight scans.
                            if pending_update_version != latest:
                                _log("update", f"newer version available: {latest} — waiting for "
                                     f"{len(current_active)} active task(s) to finish; "
                                     f"not accepting new tasks until updated")
                                pending_update_version = latest
                        else:
                            _log("update", f"newer version available: {latest} (running: {AGENT_VERSION})")
                            maybe_self_update(server, latest)
                            # execv never returns on success; reaching here means the attempt failed.

                    # Claim as many tasks as we have capacity for in this heartbeat cycle.
                    # Skip when disk is critically low — tasks would likely fail anyway.
                    # NOTE: do NOT skip when pending_update_version is set — updates apply
                    # opportunistically when all slots are naturally empty (see deferred
                    # update block above). Blocking claim here causes multi-minute idle
                    # gaps on long-running tasks (nmap/katana) while queues pile up.
                    if free_bytes < _DISK_MIN_FREE_BYTES:
                        _log("heartbeat",
                             f"low disk space ({free_bytes // (1024*1024)} MB free, "
                             f"need {_DISK_MIN_FREE_BYTES // (1024*1024)} MB) — skipping task claim")
                    elif body.get("tasksAvailable"):
                        with active_lock:
                            capacity = max_concurrent - len(active_tasks)
                        if capacity > 0:
                            # Try batch endpoint first (one round-trip for all free slots);
                            # fall back to the legacy single-claim loop for older servers.
                            batch_r = _session(cfg).post(
                                f"{server}/api/v1/agent/tasks/claim-batch",
                                params={"count": capacity}, timeout=10)
                            if batch_r.status_code == 200:
                                claimed = batch_r.json() or []
                                for task in claimed:
                                    task_id = task["id"]
                                    tool = task.get("tool", "?")
                                    with active_lock:
                                        active_tasks.add(task_id)
                                        n_active = len(active_tasks)
                                    _log("task", f"[{task_id}] claimed {tool} — active: {n_active}/{max_concurrent}")
                                    executor.submit(_run_task, task)
                            else:
                                # Legacy fallback: server does not yet have /claim-batch
                                while True:
                                    with active_lock:
                                        capacity = max_concurrent - len(active_tasks)
                                    if capacity <= 0:
                                        _log("heartbeat", "at capacity — deferring next claim to next cycle")
                                        break
                                    claim = _session(cfg).post(f"{server}/api/v1/agent/tasks/claim", timeout=10)
                                    if claim.status_code == 204 or not claim.content:
                                        break
                                    if claim.status_code != 200:
                                        _log("heartbeat", f"claim returned HTTP {claim.status_code}")
                                        break
                                    task = claim.json()
                                    task_id = task["id"]
                                    tool = task.get("tool", "?")
                                    with active_lock:
                                        active_tasks.add(task_id)
                                        n_active = len(active_tasks)
                                    _log("task", f"[{task_id}] claimed {tool} — active: {n_active}/{max_concurrent}")
                                    executor.submit(_run_task, task)

                elif r.status_code in (401, 403):
                    _log("error", f"auth rejected (HTTP {r.status_code}) — re-enroll the agent")
                    sys.exit(1)
                else:
                    _log("heartbeat", f"unexpected HTTP {r.status_code} from server")

            except requests.RequestException as e:
                _log("heartbeat", f"connection error: {e} — retrying in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue

            # Wait for the next heartbeat interval, but wake up immediately if
            # a task finishes and frees a slot — so we can claim the next one
            # without waiting up to 30 s.
            task_done_event.wait(timeout=interval)
            task_done_event.clear()

    finally:
        executor.shutdown(wait=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ares-agent", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("enroll", help="One-time setup against an Ares platform")
    e.add_argument("--server", required=True, help="Ares server base URL, e.g. https://ares.example.com")
    e.add_argument("--code",   required=True, help="Enrollment code (shown once in the admin UI)")
    e.add_argument(
        "--allow-plugin-code",
        action="store_true",
        dest="allow_plugin_code",
        help="Allow downloading and running a plugin's customBuilder module (e.g. ffuf) — "
             "off by default. See AgentToolSpec.CustomBuilder's execution model. Can also be "
             "toggled later by editing 'allow_agent_plugin_code' in the saved config file.",
    )
    e.set_defaults(func=cmd_enroll)

    r = sub.add_parser("run", help="Daemon mode")
    r.add_argument(
        "--workdir",
        metavar="DIR",
        dest="workdir",
        help="Base directory for task working files (default: ARES_WORKDIR env var or system temp)",
    )
    r.add_argument(
        "--max-concurrent-tasks",
        type=int,
        default=None,
        metavar="N",
        dest="max_concurrent_tasks",
        help="Maximum number of tasks to run simultaneously (default: ARES_MAX_CONCURRENT_TASKS env var or 1)",
    )
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("capabilities", help="Print detected tools as JSON")
    c.set_defaults(func=cmd_capabilities)

    v = sub.add_parser("version", help="Print agent version")
    v.set_defaults(func=cmd_version)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
