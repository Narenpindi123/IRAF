#!/usr/bin/env python3
"""
IRAF - Linux Incident Response & Forensics Automation Toolkit (Final)

Kali-friendly:
- Collects auth evidence from systemd journal (journalctl -u ssh)
- Also collects standard files when available
- Filters pam_winbind noise for cleaner auth-failure detection
- Avoids SUID/SGID find timeouts by scanning standard binary paths only

Outputs:
- report.json
- report.html
- hash_manifest.sha256.json
- artifacts/commands/*
- artifacts/files/*
- artifacts/journal/*
"""

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from jinja2 import Template


# -----------------------------
# Utilities (timezone-aware UTC)
# -----------------------------

UTC = dt.timezone.utc

def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)

def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd: List[str], timeout: int = 25) -> Tuple[int, str, str]:
    """Run a command safely and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"TIMEOUT: {e}"
    except Exception as e:
        return 127, "", f"ERROR: {e}"

def write_text(p: Path, content: str) -> None:
    p.write_text(content, encoding="utf-8", errors="replace")

def sha256_file(p: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def copy_if_exists(src: Path, dst: Path) -> bool:
    try:
        if src.exists() and src.is_file():
            safe_mkdir(dst.parent)
            shutil.copy2(src, dst)
            return True
        return False
    except Exception:
        return False

def list_files_recursive(root: Path, max_files: int = 8000) -> List[Path]:
    files: List[Path] = []
    try:
        for p in root.rglob("*"):
            if p.is_file():
                files.append(p)
                if len(files) >= max_files:
                    break
    except Exception:
        pass
    return files


# -----------------------------
# Data models
# -----------------------------

@dataclasses.dataclass
class CommandArtifact:
    name: str
    command: List[str]
    rc: int
    stdout_path: str
    stderr_path: str

@dataclasses.dataclass
class FileArtifact:
    name: str
    source_path: str
    saved_path: str
    sha256: Optional[str]

@dataclasses.dataclass
class Finding:
    title: str
    severity: str  # low/medium/high
    details: str


# -----------------------------
# HTML report template
# -----------------------------

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>IRAF Report - {{ report.case_name }}</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f0f0f; color:#eaeaea; margin: 20px; }
    h1,h2,h3 { color:#ffffff; }
    .meta { background:#161616; padding: 12px; border-radius: 10px; }
    .card { background:#161616; padding: 12px; border-radius: 10px; margin-top: 12px; }
    .sev-high { color: #ff6b6b; font-weight: bold; }
    .sev-medium { color: #ffd166; font-weight: bold; }
    .sev-low { color: #8ecae6; font-weight: bold; }
    code, pre { background:#0b0b0b; padding: 10px; border-radius: 8px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #333; padding: 6px; font-size: 12px; vertical-align: top; }
    th { background:#222; }
    tr:nth-child(even) { background: #141414; }
    .small { font-size: 12px; color:#cfcfcf; }
  </style>
</head>
<body>

<h1>IRAF Forensic Report</h1>

<div class="meta">
  <div><b>Case:</b> {{ report.case_name }}</div>
  <div><b>Generated (UTC):</b> {{ report.generated_utc }}</div>
  <div><b>Host:</b> {{ report.host.hostname }} ({{ report.host.os }})</div>
  <div><b>Kernel:</b> {{ report.host.kernel }}</div>
  <div><b>Case Directory:</b> <span class="small">{{ report.case_dir }}</span></div>
</div>

<div class="card">
  <h2>Findings</h2>
  {% if report.findings|length == 0 %}
    <p>No findings triggered.</p>
  {% else %}
    <ul>
      {% for f in report.findings %}
        <li>
          {% if f.severity == "high" %}
            <span class="sev-high">[HIGH]</span>
          {% elif f.severity == "medium" %}
            <span class="sev-medium">[MEDIUM]</span>
          {% else %}
            <span class="sev-low">[LOW]</span>
          {% endif %}
          <b>{{ f.title }}</b> — {{ f.details }}
        </li>
      {% endfor %}
    </ul>
  {% endif %}
</div>

<div class="card">
  <h2>Collected Commands</h2>
  <table>
    <thead>
      <tr><th>Name</th><th>Command</th><th>RC</th><th>stdout</th><th>stderr</th></tr>
    </thead>
    <tbody>
      {% for c in report.commands %}
      <tr>
        <td>{{ c.name }}</td>
        <td><code>{{ " ".join(c.command) }}</code></td>
        <td>{{ c.rc }}</td>
        <td class="small">{{ c.stdout_path }}</td>
        <td class="small">{{ c.stderr_path }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="card">
  <h2>Collected Evidence Files</h2>
  <table>
    <thead>
      <tr><th>Name</th><th>Source</th><th>Saved</th><th>SHA-256</th></tr>
    </thead>
    <tbody>
      {% for f in report.files %}
      <tr>
        <td>{{ f.name }}</td>
        <td class="small">{{ f.source_path }}</td>
        <td class="small">{{ f.saved_path }}</td>
        <td class="small"><code>{{ f.sha256 or "N/A" }}</code></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="card">
  <h2>Quick Triage</h2>
  <h3>Auth Failures (cleaned)</h3>
  <pre>{{ report.triage.failed_logins or "N/A" }}</pre>

  <h3>Sudo usage</h3>
  <pre>{{ report.triage.sudo_usage or "N/A" }}</pre>

  <h3>Top CPU processes</h3>
  <pre>{{ report.triage.top_cpu or "N/A" }}</pre>
</div>

</body>
</html>
"""


# -----------------------------
# Log path detection (best-effort)
# -----------------------------

def detect_auth_log_path() -> Optional[Path]:
    for p in [Path("/var/log/auth.log"), Path("/var/log/secure")]:
        if p.exists() and p.is_file():
            return p
    return None

def detect_syslog_path() -> Optional[Path]:
    for p in [Path("/var/log/syslog"), Path("/var/log/messages")]:
        if p.exists() and p.is_file():
            return p
    return None


# -----------------------------
# Collect journal auth (Kali/systemd)
# -----------------------------

def collect_journal_auth(case_dir: Path) -> Optional[Path]:
    out_dir = case_dir / "artifacts" / "journal"
    safe_mkdir(out_dir)
    out_path = out_dir / "auth_journal.txt"

    cmd = [
        "bash", "-lc",
        "journalctl -u ssh --no-pager -n 800 2>/dev/null || "
        "journalctl _COMM=sshd --no-pager -n 800 2>/dev/null || "
        "journalctl --no-pager | grep -i 'pam_unix\\|failed password\\|authentication failure\\|password check failed' | tail -n 800"
    ]
    rc, out, err = run_cmd(cmd, timeout=25)
    write_text(out_dir / "auth_journal.err.txt", err)

    if out.strip():
        write_text(out_path, out)
        return out_path
    return None


# -----------------------------
# Collect commands + files
# -----------------------------

def collect_commands(case_dir: Path) -> List[CommandArtifact]:
    out_dir = case_dir / "artifacts" / "commands"
    safe_mkdir(out_dir)

    # FIX: faster SUID/SGID scan (avoid timeouts)
    suid_fast_cmd = (
        "find /bin /usr/bin /usr/sbin /sbin -type f "
        "\\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | head -n 500 || true"
    )

    cmds = [
        ("system_uname", ["uname", "-a"]),
        ("system_uptime", ["uptime"]),
        ("system_date_utc", ["date", "-u"]),
        ("users_who", ["who"]),
        ("users_w", ["w"]),
        ("users_last_50", ["last", "-n", "50"]),
        ("users_lastb_50", ["bash", "-lc", "lastb -n 50 2>/dev/null || true"]),
        ("accounts_passwd", ["cat", "/etc/passwd"]),
        ("accounts_group", ["cat", "/etc/group"]),
        ("accounts_shadow_head", ["bash", "-lc", "head -n 10 /etc/shadow 2>/dev/null || true"]),
        ("sudoers_list", ["bash", "-lc", "ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null || true"]),
        ("cron_system", ["bash", "-lc", "ls -la /etc/cron* /var/spool/cron 2>/dev/null || true"]),
        ("cron_user", ["bash", "-lc", "crontab -l 2>/dev/null || true"]),
        ("services_systemctl_head", ["bash", "-lc", "systemctl list-unit-files --type=service --no-pager 2>/dev/null | head -n 250 || true"]),
        ("process_ps_topcpu", ["bash", "-lc", "ps auxww --sort=-%cpu | head -n 50"]),
        ("process_tree_head", ["bash", "-lc", "pstree -ap 2>/dev/null | head -n 250 || true"]),
        ("network_listen", ["bash", "-lc", "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true"]),
        ("network_connections", ["bash", "-lc", "ss -ntup 2>/dev/null | head -n 250 || true"]),
        ("network_ip_addr", ["ip", "addr"]),
        ("network_ip_route", ["ip", "route"]),
        ("dns_resolv_conf", ["bash", "-lc", "cat /etc/resolv.conf 2>/dev/null || true"]),
        ("kernel_lsmod_head", ["bash", "-lc", "lsmod 2>/dev/null | head -n 250 || true"]),
        ("recently_modified_bin_2d", ["bash", "-lc", "find /bin /usr/bin -type f -mtime -2 2>/dev/null | head -n 300 || true"]),
        ("suid_sgid_files_head", ["bash", "-lc", suid_fast_cmd]),  # FIXED
        ("hidden_files_home", ["bash", "-lc", "find /home -maxdepth 3 -type f -name '.*' 2>/dev/null | head -n 300 || true"]),
    ]

    artifacts: List[CommandArtifact] = []
    for name, cmd in cmds:
        stdout_path = out_dir / f"{name}.out.txt"
        stderr_path = out_dir / f"{name}.err.txt"
        rc, out, err = run_cmd(cmd, timeout=30)
        write_text(stdout_path, out)
        write_text(stderr_path, err)
        artifacts.append(CommandArtifact(
            name=name,
            command=cmd,
            rc=rc,
            stdout_path=str(stdout_path.relative_to(case_dir)),
            stderr_path=str(stderr_path.relative_to(case_dir)),
        ))
    return artifacts


def collect_files(case_dir: Path) -> List[FileArtifact]:
    out_dir = case_dir / "artifacts" / "files"
    safe_mkdir(out_dir)

    files_to_collect: List[Tuple[str, Path]] = []

    auth_log = detect_auth_log_path()
    syslog = detect_syslog_path()

    if auth_log:
        files_to_collect.append(("auth_log", auth_log))
    if syslog:
        files_to_collect.append(("syslog", syslog))

    files_to_collect += [
        ("passwd", Path("/etc/passwd")),
        ("group", Path("/etc/group")),
        ("shadow", Path("/etc/shadow")),
        ("sudoers", Path("/etc/sudoers")),
        ("hosts", Path("/etc/hosts")),
        ("resolv_conf", Path("/etc/resolv.conf")),
        ("crontab_system", Path("/etc/crontab")),
    ]

    artifacts: List[FileArtifact] = []
    for name, src in files_to_collect:
        safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)
        dst = out_dir / f"{safe_name}{src.suffix or '.txt'}"
        copied = copy_if_exists(src, dst)
        if copied:
            artifacts.append(FileArtifact(
                name=name,
                source_path=str(src),
                saved_path=str(dst.relative_to(case_dir)),
                sha256=sha256_file(dst),
            ))
        else:
            artifacts.append(FileArtifact(
                name=name,
                source_path=str(src),
                saved_path="NOT_COLLECTED",
                sha256=None,
            ))
    return artifacts


def compute_hash_manifest(case_dir: Path) -> Dict[str, str]:
    manifest: Dict[str, str] = {}
    artifacts_root = case_dir / "artifacts"
    for p in list_files_recursive(artifacts_root):
        h = sha256_file(p)
        if h:
            manifest[str(p.relative_to(case_dir))] = h
    return manifest


# -----------------------------
# Findings / triage
# -----------------------------

def load_text(case_dir: Path, rel: str) -> str:
    try:
        return (case_dir / rel).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

def extract_failed_logins(text: str, limit: int = 60) -> str:
    """
    Extract auth failure indicators and FILTER pam_winbind noise.
    """
    indicators = (
        "failed password",
        "authentication failure",
        "pam_unix",
        "password check failed",
        "pam 2 more authentication failures",
    )

    lines = []
    for ln in text.splitlines():
        low = ln.lower()

        # FIX: drop Kali winbind noise (not relevant for SSH brute force demo)
        if "pam_winbind" in low:
            continue

        if any(ind in low for ind in indicators):
            lines.append(ln)

    return "\n".join(lines[-limit:]) if lines else ""

def extract_sudo_usage(text: str, limit: int = 60) -> str:
    lines = [ln for ln in text.splitlines() if "sudo" in ln.lower()]
    return "\n".join(lines[-limit:]) if lines else ""

def generate_findings(case_dir: Path) -> Tuple[List[Finding], Dict[str, str]]:
    findings: List[Finding] = []

    top_cpu = load_text(case_dir, "artifacts/commands/process_ps_topcpu.out.txt")
    suid_list = load_text(case_dir, "artifacts/commands/suid_sgid_files_head.out.txt")
    modified_bin = load_text(case_dir, "artifacts/commands/recently_modified_bin_2d.out.txt")
    journal_text = load_text(case_dir, "artifacts/journal/auth_journal.txt")

    combined_auth = journal_text.strip()

    failed_lines = extract_failed_logins(combined_auth, limit=500)
    failed_count = len(failed_lines.splitlines()) if failed_lines else 0

    if failed_count >= 10:
        findings.append(Finding(
            title="High volume of authentication failures",
            severity="high",
            details=f"Detected {failed_count} auth-failure indicator lines in journal logs (pam_winbind filtered). Possible brute force/password spraying.",
        ))
    elif 4 <= failed_count < 10:
        findings.append(Finding(
            title="Authentication failures present",
            severity="medium",
            details=f"Detected {failed_count} auth-failure indicator lines. Review source IPs, usernames, and time window.",
        ))
    elif 1 <= failed_count < 4:
        findings.append(Finding(
            title="Some authentication failures observed",
            severity="low",
            details=f"Detected {failed_count} auth-failure indicator lines. Likely testing but validate.",
        ))

    suid_count = len([ln for ln in suid_list.splitlines() if ln.strip().startswith("/")])
    if suid_count >= 80:
        findings.append(Finding(
            title="Large number of SUID/SGID binaries (truncated)",
            severity="medium",
            details=f"Found ~{suid_count} SUID/SGID entries in standard binary paths. Review for unusual binaries.",
        ))
    elif 1 <= suid_count < 80:
        findings.append(Finding(
            title="SUID/SGID binaries present (truncated)",
            severity="low",
            details=f"Found ~{suid_count} SUID/SGID entries in standard binary paths. Confirm against expected baseline.",
        ))

    mod_count = len([ln for ln in modified_bin.splitlines() if ln.strip().startswith("/")])
    if mod_count >= 10:
        findings.append(Finding(
            title="Recently modified system binaries",
            severity="high",
            details=f"Found {mod_count} binaries modified within last 2 days under /bin or /usr/bin (truncated). Validate updates vs tampering.",
        ))
    elif 1 <= mod_count < 10:
        findings.append(Finding(
            title="Some recently modified system binaries",
            severity="medium",
            details=f"Found {mod_count} binaries modified within last 2 days under /bin or /usr/bin (truncated). Confirm update activity.",
        ))

    # High CPU heuristic
    cpu_alert = False
    for ln in top_cpu.splitlines()[1:12]:
        parts = ln.split()
        if len(parts) > 2:
            try:
                cpu = float(parts[2])
                if cpu >= 80.0:
                    cpu_alert = True
                    break
            except Exception:
                continue

    if cpu_alert:
        findings.append(Finding(
            title="High CPU process observed",
            severity="medium",
            details="A process in the top CPU list shows >= 80% CPU. Investigate for suspicious execution (miners/runaway jobs).",
        ))

    triage = {
        "failed_logins": extract_failed_logins(combined_auth, limit=60),
        "sudo_usage": extract_sudo_usage(combined_auth, limit=60),
        "top_cpu": top_cpu.strip(),
    }

    return findings, triage


# -----------------------------
# Host metadata
# -----------------------------

def build_host_metadata() -> Dict[str, str]:
    return {
        "hostname": platform.node(),
        "os": platform.platform(),
        "kernel": platform.release(),
    }


# -----------------------------
# Main
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="IRAF - Linux Incident Response & Forensics Automation Toolkit (Final)")
    parser.add_argument("--case-name", required=True, help="Case name (e.g., case2_clean)")
    parser.add_argument("--out", default="./cases", help="Output base directory")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. Some artifacts may not be collected.", file=sys.stderr)

    ts = utc_now().strftime("%Y%m%dT%H%M%SZ")
    base = Path(args.out).expanduser().resolve()
    case_dir = base / f"{args.case_name}_{ts}"
    safe_mkdir(case_dir)

    print(f"[*] Case directory: {case_dir}")

    # Collect artifacts
    commands = collect_commands(case_dir)
    files = collect_files(case_dir)

    journal_auth_path = collect_journal_auth(case_dir)
    if journal_auth_path:
        files.append(FileArtifact(
            name="journal_auth",
            source_path="journalctl (ssh/auth)",
            saved_path=str(journal_auth_path.relative_to(case_dir)),
            sha256=sha256_file(journal_auth_path),
        ))
    else:
        files.append(FileArtifact(
            name="journal_auth",
            source_path="journalctl (ssh/auth)",
            saved_path="NOT_COLLECTED",
            sha256=None,
        ))

    # Hash manifest
    hash_manifest = compute_hash_manifest(case_dir)

    # Findings
    findings, triage = generate_findings(case_dir)

    report = {
        "case_name": args.case_name,
        "generated_utc": utc_now_iso(),
        "case_dir": str(case_dir),
        "host": build_host_metadata(),
        "commands": [dataclasses.asdict(c) for c in commands],
        "files": [dataclasses.asdict(f) for f in files],
        "hash_manifest": hash_manifest,
        "findings": [dataclasses.asdict(f) for f in findings],
        "triage": triage,
    }

    # Write outputs
    report_json = case_dir / "report.json"
    report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[*] Wrote: {report_json}")

    report_html = case_dir / "report.html"
    report_html.write_text(Template(HTML_TEMPLATE).render(report=report), encoding="utf-8", errors="replace")
    print(f"[*] Wrote: {report_html}")

    manifest_path = case_dir / "hash_manifest.sha256.json"
    manifest_path.write_text(json.dumps(hash_manifest, indent=2), encoding="utf-8")
    print(f"[*] Wrote: {manifest_path}")

    print("[*] Done.")
    print(f"    Open: {report_html}")


if __name__ == "__main__":
    main()
