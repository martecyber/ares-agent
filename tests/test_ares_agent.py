"""Unit tests for the Fase 2 / Part B generic tool-spec interpreter in ares_agent.py.

No real scan binaries are available in this environment (see the migration plan's own
Verification section) — every test here mocks shutil.which/subprocess instead of
shelling out to a real tool, and checks the constructed argv / validation behavior
directly. Run with: `pytest tests/` from the ares-agent directory.
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ares_agent as aa


# ── fixtures: representative specs (trimmed to what each test needs) ────────

NMAP_SPEC = {
    "toolId": "nmap", "binary": "nmap", "targetEmission": "positional",
    "outputArgs": ["-oX", "{outPath}"], "maxTargets": None,
    "fields": [
        {"key": "scanType", "type": "enum", "flag": None, "options": ["-sS", "-sT", "-sn"]},
        {"key": "ports", "type": "string", "flag": "-p", "pattern": r"^[0-9,\-]+$"},
        {"key": "minRate", "type": "number", "flag": "--min-rate", "min": 1, "max": 1000000},
        {"key": "detectVersion", "type": "boolean_flag", "flag": "-sV"},
    ],
}

NAABU_SPEC = {
    "toolId": "naabu", "binary": "naabu", "targetEmission": "joined", "targetFlag": "-host",
    "outputArgs": ["-json", "-o", "{outPath}", "-silent"], "maxTargets": None,
    "fields": [{"key": "ports", "type": "string", "flag": "-p", "pattern": r"^[0-9,\-]+$"}],
}

HTTPX_SPEC = {
    "toolId": "httpx", "binary": "httpx", "targetEmission": "list-file", "targetFlag": "-l",
    "outputArgs": ["-json", "-o", "{outPath}", "-silent"], "maxTargets": None,
    "fields": [
        {"key": "userAgent", "type": "string", "flag": "-H", "valueTemplate": "User-Agent: {value}",
         "pattern": r"^[\x20-\x7e]+$"},
        {"key": "headers", "type": "string", "flag": "-H", "repeat": True,
         "pattern": r"^[A-Za-z0-9_\-]{1,64}: [\x20-\x7e]{1,2048}$"},
    ],
}

DNSX_SPEC = {
    "toolId": "dnsx", "binary": "dnsx", "targetEmission": "list-file", "targetFlag": "-l",
    "outputArgs": ["-json", "-o", "{outPath}", "-silent"], "maxTargets": None,
    "fields": [
        {"key": "recordTypes", "type": "enum", "flag": None, "repeat": True,
         "options": ["-a", "-aaaa", "-mx"]},
    ],
}

WPSCAN_SPEC = {
    "toolId": "wpscan", "binary": "wpscan", "targetEmission": "single-flag", "targetFlag": "--url",
    "outputArgs": ["-o", "{outPath}", "--format", "json", "--no-banner"], "maxTargets": 1,
    "fields": [{"key": "apiToken", "type": "string", "flag": "--api-token", "pattern": r"^[A-Za-z0-9_\-]{1,100}$"}],
}

FFUF_SPEC = {
    "toolId": "ffuf", "binary": "ffuf", "targetEmission": "single-flag", "targetFlag": "-u",
    "maxTargets": 1, "customBuilder": {"module": "builder.py", "sha256": "deadbeef" * 8},
    "fields": [
        {"key": "wordlist", "type": "server_fetch", "urlTemplate": "/api/v1/kb/wordlists/{value}/content"},
        {"key": "rate", "type": "number", "flag": "-rate", "min": 1, "max": 10000},
    ],
}


@pytest.fixture(autouse=True)
def _isolated_caches(tmp_path, monkeypatch):
    """Every test gets its own wordlist/builder-module cache dirs — never touch the
    real ~/.ares-agent on the machine running the tests."""
    monkeypatch.setattr(aa, "_WL_CACHE_DIR", tmp_path / "wordlist-cache")
    monkeypatch.setattr(aa, "_BUILDER_MODULE_CACHE_DIR", tmp_path / "builder-modules")
    yield


@pytest.fixture
def workdir(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    return d


def _which_only(name_ok: str):
    def fake_which(name):
        return f"/usr/bin/{name}" if name == name_ok else None
    return fake_which


# ── build_cmd_from_spec: emission modes + output args ────────────────────────

def test_nmap_positional_emission_and_output_args(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")):
        cmd, out = aa.build_cmd_from_spec(
            NMAP_SPEC, {"targets": ["10.0.0.1", "10.0.0.2"], "scanType": "-sS", "ports": "80,443",
                        "detectVersion": True}, workdir, {})
    assert cmd[0] == "/usr/bin/nmap"
    assert cmd[1:3] == ["-oX", str(out)]
    assert "-sS" in cmd
    assert cmd[cmd.index("-p") + 1] == "80,443"
    assert "-sV" in cmd
    # positional: targets are the trailing bare argv entries
    assert cmd[-2:] == ["10.0.0.1", "10.0.0.2"]


def test_naabu_joined_emission(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("naabu")):
        cmd, out = aa.build_cmd_from_spec(
            NAABU_SPEC, {"targets": ["a.com", "b.com"], "ports": "1-1000"}, workdir, {})
    assert cmd[-2:] == ["-host", "a.com,b.com"]
    assert "-json" in cmd and str(out) in cmd


def test_httpx_list_file_emission_writes_target_file(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("httpx")):
        cmd, out = aa.build_cmd_from_spec(HTTPX_SPEC, {"targets": ["https://a.com"]}, workdir, {})
    assert cmd[1] == "-l"
    target_file = Path(cmd[2])
    assert target_file.exists()
    assert target_file.read_text().strip() == "https://a.com"


def test_httpx_user_agent_value_template(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("httpx")):
        cmd, _ = aa.build_cmd_from_spec(
            HTTPX_SPEC, {"targets": ["https://a.com"], "userAgent": "MyBot/1.0"}, workdir, {})
    idx = cmd.index("-H")
    assert cmd[idx + 1] == "User-Agent: MyBot/1.0"


def test_httpx_repeated_headers_each_get_their_own_flag(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("httpx")):
        cmd, _ = aa.build_cmd_from_spec(
            HTTPX_SPEC, {"targets": ["https://a.com"],
                         "headers": ["X-Foo: bar", "X-Baz: qux"]}, workdir, {})
    h_indexes = [i for i, v in enumerate(cmd) if v == "-H"]
    values = [cmd[i + 1] for i in h_indexes]
    assert "X-Foo: bar" in values and "X-Baz: qux" in values


def test_httpx_rejects_a_malformed_header_value(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("httpx")):
        with pytest.raises(RuntimeError):
            aa.build_cmd_from_spec(
                HTTPX_SPEC, {"targets": ["https://a.com"], "headers": ["not-a-header"]}, workdir, {})


def test_dnsx_repeated_enum_with_null_flag_emits_bare_tokens(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("dnsx")):
        cmd, _ = aa.build_cmd_from_spec(
            DNSX_SPEC, {"targets": ["a.com"], "recordTypes": ["-a", "-mx"]}, workdir, {})
    assert "-a" in cmd and "-mx" in cmd


def test_dnsx_rejects_an_unlisted_record_type(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("dnsx")):
        with pytest.raises(RuntimeError):
            aa.build_cmd_from_spec(DNSX_SPEC, {"targets": ["a.com"], "recordTypes": ["-evil"]}, workdir, {})


def test_wpscan_single_flag_emission_puts_target_right_after_binary(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("wpscan")):
        cmd, out = aa.build_cmd_from_spec(WPSCAN_SPEC, {"targets": ["https://wp.example.com"]}, workdir, {})
    assert cmd[1:3] == ["--url", "https://wp.example.com"]
    assert "--no-banner" in cmd
    assert cmd[cmd.index("--format") + 1] == "json"


def test_missing_binary_raises(workdir):
    with patch.object(aa.shutil, "which", return_value=None):
        with pytest.raises(RuntimeError, match="not found on \\$PATH"):
            aa.build_cmd_from_spec(NMAP_SPEC, {"targets": ["1.2.3.4"]}, workdir, {})


def test_no_targets_raises(workdir):
    with pytest.raises(RuntimeError, match="no targets"):
        aa.build_cmd_from_spec(NMAP_SPEC, {}, workdir, {})


# ── field value validation (defense in depth) ────────────────────────────────

def test_number_field_out_of_range_raises(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")):
        with pytest.raises(RuntimeError):
            aa.build_cmd_from_spec(NMAP_SPEC, {"targets": ["1.1.1.1"], "minRate": 99999999}, workdir, {})


def test_string_field_pattern_violation_raises(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")):
        with pytest.raises(RuntimeError):
            aa.build_cmd_from_spec(NMAP_SPEC, {"targets": ["1.1.1.1"], "ports": "80; rm -rf /"}, workdir, {})


def test_enum_field_outside_options_raises(workdir):
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")):
        with pytest.raises(RuntimeError):
            aa.build_cmd_from_spec(NMAP_SPEC, {"targets": ["1.1.1.1"], "scanType": "-sX"}, workdir, {})


# ── server_fetch resolution ───────────────────────────────────────────────────

def test_server_fetch_downloads_and_caches(tmp_path):
    cfg = {"server": "https://ares.example.com", "token": "tok"}
    field = {"key": "wordlist", "type": "server_fetch", "urlTemplate": "/api/v1/kb/wordlists/{value}/content"}

    fake_response = MagicMock()
    fake_response.read.return_value = b"admin\nroot\n"
    fake_cm = MagicMock()
    fake_cm.__enter__.return_value = fake_response
    fake_cm.__exit__.return_value = False

    with patch("urllib.request.urlopen", return_value=fake_cm) as mock_open:
        path1 = aa._resolve_server_fetch_value(cfg, field, 42)
        path2 = aa._resolve_server_fetch_value(cfg, field, 42)  # second call: cache hit
    assert Path(path1).read_bytes() == b"admin\nroot\n"
    assert path1 == path2
    assert mock_open.call_count == 1  # not re-fetched on the cache hit


def test_ffuf_wordlist_field_is_resolved_before_reaching_the_builder(tmp_path, workdir):
    """ffuf's customBuilder must receive an already-downloaded LOCAL PATH for
    'wordlist', never the raw KB id — this is exactly the bug class the pre-Part-B
    spec/Python mismatch audit flagged (ffuf's wordlist server_fetch field)."""
    cfg = {"server": "https://ares.example.com", "token": "tok"}
    module_dir = aa._BUILDER_MODULE_CACHE_DIR
    module_dir.mkdir(parents=True)
    module_path = module_dir / "ffuf.py"
    module_path.write_text(
        "import json, sys\n"
        "req = json.loads(sys.stdin.readline())\n"
        "sys.stdout.write(json.dumps({'cmd': ['ffuf', '-w', req['wordlist']], 'outPath': req['outPath']}))\n"
    )
    import hashlib
    sha = hashlib.sha256(module_path.read_bytes()).hexdigest()
    spec = dict(FFUF_SPEC, customBuilder={"module": "builder.py", "sha256": sha})

    fake_response = MagicMock()
    fake_response.read.return_value = b"seclist-content"
    fake_cm = MagicMock()
    fake_cm.__enter__.return_value = fake_response
    fake_cm.__exit__.return_value = False

    with patch.object(aa.shutil, "which", side_effect=_which_only("ffuf")), \
         patch("urllib.request.urlopen", return_value=fake_cm):
        cmd, out = aa.build_cmd_from_spec(
            spec, {"targets": ["https://x.com/FUZZ"], "wordlist": 7}, workdir, cfg)

    resolved_path = Path(cmd[cmd.index("-w") + 1])
    assert resolved_path.exists()
    assert resolved_path.read_bytes() == b"seclist-content"


# ── customBuilder execution / error handling ─────────────────────────────────

def test_run_custom_builder_missing_module_raises(workdir):
    with pytest.raises(RuntimeError, match="not synced"):
        aa.build_cmd_from_spec(FFUF_SPEC, {"targets": ["https://x.com"], "wordlist": 1}, workdir,
                                {"server": "https://s", "token": "t"})


def test_run_custom_builder_checksum_mismatch_raises(tmp_path, workdir):
    module_dir = aa._BUILDER_MODULE_CACHE_DIR
    module_dir.mkdir(parents=True)
    (module_dir / "ffuf.py").write_text("print('whatever')")  # sha won't match FFUF_SPEC's placeholder
    with patch.object(aa.shutil, "which", side_effect=_which_only("ffuf")):
        with pytest.raises(RuntimeError, match="checksum mismatch"):
            aa.build_cmd_from_spec(FFUF_SPEC, {"targets": ["https://x.com"], "wordlist": 1}, workdir,
                                    {"server": "https://s", "token": "t"})


def test_run_custom_builder_surfaces_module_reported_error(tmp_path, workdir):
    module_dir = aa._BUILDER_MODULE_CACHE_DIR
    module_dir.mkdir(parents=True)
    module_path = module_dir / "ffuf.py"
    module_path.write_text(
        "import json, sys\n"
        "sys.stdin.readline()\n"
        "sys.stdout.write(json.dumps({'error': 'boom'}))\n"
    )
    import hashlib
    sha = hashlib.sha256(module_path.read_bytes()).hexdigest()
    spec = dict(FFUF_SPEC, customBuilder={"module": "builder.py", "sha256": sha})

    fake_response = MagicMock()
    fake_response.read.return_value = b"wordlist-bytes"
    fake_cm = MagicMock()
    fake_cm.__enter__.return_value = fake_response
    fake_cm.__exit__.return_value = False

    with patch.object(aa.shutil, "which", side_effect=_which_only("ffuf")), \
         patch("urllib.request.urlopen", return_value=fake_cm):
        with pytest.raises(RuntimeError, match="boom"):
            aa.build_cmd_from_spec(spec, {"targets": ["https://x.com"], "wordlist": 1}, workdir,
                                    {"server": "https://s", "token": "t"})


def test_run_custom_builder_maxtargets_one_enforced(tmp_path, workdir):
    module_dir = aa._BUILDER_MODULE_CACHE_DIR
    module_dir.mkdir(parents=True)
    module_path = module_dir / "ffuf.py"
    module_path.write_text("import sys; sys.stdin.readline(); sys.stdout.write('{}')")
    import hashlib
    sha = hashlib.sha256(module_path.read_bytes()).hexdigest()
    spec = dict(FFUF_SPEC, customBuilder={"module": "builder.py", "sha256": sha})
    with patch.object(aa.shutil, "which", side_effect=_which_only("ffuf")):
        with pytest.raises(RuntimeError, match="exactly one target"):
            aa.build_cmd_from_spec(spec, {"targets": ["a", "b"], "wordlist": 1}, workdir,
                                    {"server": "https://s", "token": "t"})


# ── probe_capabilities: binary / version / root / customBuilder gating ───────

def _fake_version_proc(text):
    proc = MagicMock()
    proc.stdout = text
    proc.stderr = ""
    return proc


def test_probe_capabilities_reports_a_present_binary():
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")), \
         patch.object(aa.subprocess, "run", return_value=_fake_version_proc("Nmap version 7.94")):
        caps, unavail = aa.probe_capabilities([dict(NMAP_SPEC, minVersion=None, requiresRoot=False)], {})
    assert unavail == []
    assert caps[0]["tool"] == "nmap"
    assert caps[0]["version"].startswith("Nmap version 7.94")


def test_probe_capabilities_reports_a_missing_binary_as_unavailable():
    with patch.object(aa.shutil, "which", return_value=None):
        caps, unavail = aa.probe_capabilities([NMAP_SPEC], {})
    assert caps == []
    assert unavail[0]["toolId"] == "nmap"
    assert "not found" in unavail[0]["reason"]


def test_probe_capabilities_blocks_on_min_version():
    spec = dict(NMAP_SPEC, minVersion="9.0")
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")), \
         patch.object(aa.subprocess, "run", return_value=_fake_version_proc("Nmap version 7.94")):
        caps, unavail = aa.probe_capabilities([spec], {})
    assert caps == []
    assert "older than required" in unavail[0]["reason"]


def test_probe_capabilities_unparseable_version_is_treated_as_compatible():
    spec = dict(NMAP_SPEC, minVersion="9.0")
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")), \
         patch.object(aa.subprocess, "run", return_value=_fake_version_proc("banner with no digits")):
        caps, unavail = aa.probe_capabilities([spec], {})
    assert unavail == []
    assert caps[0]["tool"] == "nmap"


def test_probe_capabilities_blocks_on_requires_root():
    spec = dict(NMAP_SPEC, requiresRoot=True)
    with patch.object(aa.shutil, "which", side_effect=_which_only("nmap")), \
         patch.object(aa.subprocess, "run", return_value=_fake_version_proc("v1")), \
         patch.object(aa.os, "geteuid", return_value=1000, create=True):
        caps, unavail = aa.probe_capabilities([spec], {})
    assert caps == []
    assert "root" in unavail[0]["reason"]


def test_probe_capabilities_customBuilder_blocked_when_plugin_code_disallowed():
    with patch.object(aa.shutil, "which", side_effect=_which_only("ffuf")), \
         patch.object(aa.subprocess, "run", return_value=_fake_version_proc("v1")):
        caps, unavail = aa.probe_capabilities([FFUF_SPEC], {"allow_agent_plugin_code": False})
    assert caps == []
    assert "allow_agent_plugin_code" in unavail[0]["reason"]


def test_probe_capabilities_customBuilder_available_once_synced_and_verified(tmp_path):
    module_dir = aa._BUILDER_MODULE_CACHE_DIR
    module_dir.mkdir(parents=True)
    module_path = module_dir / "ffuf.py"
    module_path.write_bytes(b"whatever")
    import hashlib
    sha = hashlib.sha256(module_path.read_bytes()).hexdigest()
    spec = dict(FFUF_SPEC, customBuilder={"module": "builder.py", "sha256": sha})
    with patch.object(aa.shutil, "which", side_effect=_which_only("ffuf")), \
         patch.object(aa.subprocess, "run", return_value=_fake_version_proc("v1")):
        caps, unavail = aa.probe_capabilities([spec], {"allow_agent_plugin_code": True})
    assert unavail == []
    assert caps[0]["tool"] == "ffuf"


# ── version comparison helper ────────────────────────────────────────────────

@pytest.mark.parametrize("detected,min_version,expected", [
    ("7.94", "7.90", True),
    ("Nmap version 7.10 ( https://nmap.org )", "7.90", False),
    (None, "7.90", True),           # unknown detected version -> best-effort compatible
    ("garbage", "7.90", True),      # unparseable detected -> compatible
    ("7.94", "garbage", True),      # unparseable min -> compatible
    ("7.94", None, True),           # no constraint at all
])
def test_version_at_least(detected, min_version, expected):
    assert aa._version_at_least(detected, min_version) is expected


# ── sync_tool_specs ───────────────────────────────────────────────────────────

def test_sync_tool_specs_skips_fetch_when_version_unchanged():
    sess = MagicMock()
    result = aa.sync_tool_specs(sess, "https://s", {}, current_version=5, server_version=5)
    assert result is None
    sess.get.assert_not_called()


def test_sync_tool_specs_fetches_when_version_changed():
    sess = MagicMock()
    resp = MagicMock(status_code=200)
    resp.json.return_value = [NMAP_SPEC]
    sess.get.return_value = resp
    specs, version = aa.sync_tool_specs(sess, "https://s", {}, current_version=5, server_version=6)
    assert specs == [NMAP_SPEC]
    assert version == 6
    sess.get.assert_called_once()


def test_sync_tool_specs_keeps_old_catalog_on_fetch_failure():
    sess = MagicMock()
    resp = MagicMock(status_code=500)
    sess.get.return_value = resp
    result = aa.sync_tool_specs(sess, "https://s", {}, current_version=5, server_version=6)
    assert result is None
