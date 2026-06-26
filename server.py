#!/usr/bin/env python3
"""
mcp-fw: MCP Firewall Manager
Fail2ban + CrowdSec + nftables — fleet-wide control via SSH

Uses FastMCP for SSE transport.
Run: python server.py  (defaults to port 8700)
"""

import subprocess
from typing import Any

from mcp.server.fastmcp import FastMCP

# ─── Fleet Configuration ───────────────────────────────────────────
FLEET = {
    "dgxmain":    {"host": "100.124.217.84", "user": "bitonx"},
    "dgxsec":     {"host": "100.78.185.72",  "user": "bitonx"},
    "gama-2":     {"host": "100.122.148.62", "user": "bitbit"},
    "arcai":      {"host": "100.81.132.108",  "user": "bitonx"},
    "storai":     {"host": "100.92.89.14",   "user": "bitonx"},
    "openwebui-vps": {"host": "100.115.82.76", "user": "bitonx"},
    "5060ihome":  {"host": "100.90.81.47",   "user": "bitonx"},
}

SSH_TIMEOUT = 15

# ─── MCP Server ─────────────────────────────────────────────────────
mcp = FastMCP("mcp-fw")


def ssh(server: str, cmd: str, timeout: int = SSH_TIMEOUT) -> dict[str, Any]:
    """Execute command on server via SSH."""
    if server not in FLEET:
        return {"ok": False, "error": f"Unknown server: {server}"}

    info = FLEET[server]
    ssh_cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",
        f"{info['user']}@{info['host']}",
        cmd
    ]

    try:
        result = subprocess.run(
            ssh_cmd, capture_output=True, text=True, timeout=timeout
        )
        return {
            "ok": result.returncode == 0,
            "rc": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "server": server,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"SSH timeout after {timeout}s", "server": server}
    except Exception as e:
        return {"ok": False, "error": str(e), "server": server}


def ssh_sudo(server: str, cmd: str, timeout: int = SSH_TIMEOUT) -> dict[str, Any]:
    return ssh(server, f"sudo {cmd}", timeout)


# ─── Tools ──────────────────────────────────────────────────────────

@mcp.tool()
async def fw_fleet_summary() -> str:
    """סיכום חומת אש לכל הצי — Fail2ban + CrowdSec + nftables."""
    results = {}
    for name in FLEET:
        r = ssh(name, "echo OK; systemctl is-active fail2ban 2>/dev/null; systemctl is-active crowdsec 2>/dev/null; sudo nft list table ip filter 2>/dev/null | head -1")
        results[name] = r

    lines = ["## 🔥 Fleet Firewall Summary\n"]
    lines.append("| Server | Fail2ban | CrowdSec | nftables |")
    lines.append("|---|---|---|---|")

    for name, r in results.items():
        if r.get("ok"):
            out = r["stdout"]
            parts = out.split("\n")
            fb = parts[1].strip() if len(parts) > 1 else "?"
            cs = parts[2].strip() if len(parts) > 2 else "?"
            nf = "✅ active" if "table ip filter" in out else "❌"
            fb_icon = "✅" if fb == "active" else "❌"
            cs_icon = "✅" if cs == "active" else "❌"
            lines.append(f"| **{name}** | {fb_icon} | {cs_icon} | {nf} |")
        else:
            lines.append(f"| **{name}** | ⚠️ {r.get('error', 'unreachable')} | | |")

    return "\n".join(lines)


@mcp.tool()
async def fw_fail2ban_status(server: str = "all") -> str:
    """מצב Fail2ban: jails, IPs חסומים. server=שם שרת או all."""
    servers = list(FLEET.keys()) if server == "all" else [server]
    lines = ["## 🛡️ Fail2ban Status\n"]

    for srv in servers:
        if srv not in FLEET:
            lines.append(f"❌ Unknown: {srv}\n")
            continue
        r = ssh(srv, "fail2ban-client status 2>/dev/null")
        if r.get("ok") and r["stdout"]:
            lines.append(f"### {srv}\n```\n{r['stdout']}\n```\n")
            for jail in ["sshd", "asterisk"]:
                r2 = ssh(srv, f"fail2ban-client status {jail} 2>/dev/null")
                if r2.get("ok") and r2["stdout"]:
                    lines.append(f"**{jail}:**\n```\n{r2['stdout']}\n```\n")
        else:
            lines.append(f"### {srv}\n❌ unreachable\n")
    return "\n".join(lines)


@mcp.tool()
async def fw_fail2ban_ban(server: str, jail: str, ip: str) -> str:
    """חסום IP ב-Fail2ban. server=שרת, jail=sshd/asterisk, ip=כתובת."""
    r = ssh_sudo(server, f"fail2ban-client set {jail} banip {ip}")
    if r.get("ok"):
        return f"✅ {ip} נחסם ב-{jail} על {server}"
    return f"❌ כשל: {r.get('stderr', r.get('error'))}"


@mcp.tool()
async def fw_fail2ban_unban(server: str, jail: str, ip: str) -> str:
    """שחרר IP מ-Fail2ban."""
    r = ssh_sudo(server, f"fail2ban-client set {jail} unbanip {ip}")
    if r.get("ok"):
        return f"✅ {ip} שוחרר מ-{jail} על {server}"
    return f"❌ כשל: {r.get('stderr', r.get('error'))}"


@mcp.tool()
async def fw_crowdsec_decisions(server: str = "all") -> str:
    """הצג החלטות CrowdSec פעילות. server=שם שרת או all."""
    servers = list(FLEET.keys()) if server == "all" else [server]
    lines = ["## 🧠 CrowdSec Decisions\n"]

    for srv in servers:
        if srv not in FLEET:
            continue
        r = ssh_sudo(srv, "cscli decisions list 2>/dev/null")
        if r.get("ok"):
            if r["stdout"] and "No active decisions" not in r["stdout"]:
                lines.append(f"### {srv}\n```\n{r['stdout']}\n```\n")
            else:
                lines.append(f"### {srv}\n✅ No active decisions\n")
        else:
            lines.append(f"### {srv}\n⚠️ unreachable\n")
    return "\n".join(lines)


@mcp.tool()
async def fw_crowdsec_remove_decision(server: str, ip: str) -> str:
    """הסר החלטת CrowdSec — שחרר IP."""
    r = ssh_sudo(server, f"cscli decisions delete --ip {ip}")
    if r.get("ok"):
        return f"✅ {ip} שוחרר מ-CrowdSec על {server}"
    return f"❌ כשל: {r.get('stderr', r.get('error'))}"


@mcp.tool()
async def fw_nft_rules(server: str) -> str:
    """הצג חוקי nftables מלאים על שרת."""
    r = ssh_sudo(server, "nft list ruleset 2>/dev/null")
    if r.get("ok"):
        return f"## 🔥 nftables — {server}\n```\n{r['stdout'][:5000]}\n```"
    return f"❌ nft unreachable: {r.get('error')}"


@mcp.tool()
async def fw_nft_allow_port(server: str, port: int, protocol: str = "tcp", comment: str = "") -> str:
    """הוסף חוק ACCEPT לפורט ב-nftables INPUT."""
    comment_str = f' comment "{comment}"' if comment else ""
    rule = f"tcp dport {port}" if protocol == "tcp" else f"udp dport {port}"

    check = ssh_sudo(server, f"nft list chain ip filter INPUT 2>/dev/null | grep -c 'dport {port}'")
    if check.get("ok") and check["stdout"].strip() != "0":
        return f"⚠️ פורט {port}/{protocol} כבר קיים ב-nftables על {server}"

    r = ssh_sudo(server, f"nft add rule ip filter INPUT {rule} accept{comment_str}")
    if r.get("ok"):
        return f"✅ פורט {port}/{protocol} נוסף ל-nftables על {server}"
    return f"❌ כשל: {r.get('stderr', r.get('error'))}"


@mcp.tool()
async def fw_block_ip_global(server: str, ip: str, reason: str = "manual block") -> str:
    """חסום IP — CrowdSec + nftables."""
    results = []

    r_cs = ssh_sudo(server, f"cscli decisions add --ip {ip} --reason '{reason}'")
    if r_cs.get("ok"):
        results.append(f"✅ CrowdSec: {ip} חסום")
    else:
        results.append(f"⚠️ CrowdSec: {r_cs.get('stderr', 'fail')}")

    r_nft = ssh_sudo(server, f"nft add rule ip filter INPUT ip saddr {ip} drop comment \\\"{reason}\\\"")
    if r_nft.get("ok"):
        results.append(f"✅ nftables: {ip} drop")
    else:
        results.append(f"⚠️ nftables: {r_nft.get('stderr', 'fail')}")

    return f"## 🔒 Block {ip} on {server}\n" + "\n".join(results)


@mcp.tool()
async def fw_unblock_ip_global(server: str, ip: str) -> str:
    """שחרר IP — CrowdSec + nftables."""
    results = []

    r_cs = ssh_sudo(server, f"cscli decisions delete --ip {ip}")
    if r_cs.get("ok"):
        results.append(f"✅ CrowdSec: {ip} שוחרר")
    else:
        results.append(f"⚠️ CrowdSec: {r_cs.get('stderr', 'no decision')}")

    r_find = ssh_sudo(server, f"nft -a list chain ip filter INPUT 2>/dev/null | grep '{ip}'")
    if r_find.get("ok") and r_find["stdout"]:
        for line in r_find["stdout"].split("\n"):
            if "handle" in line:
                handle = line.split("handle")[-1].strip()
                r_del = ssh_sudo(server, f"nft delete rule ip filter INPUT handle {handle}")
                if r_del.get("ok"):
                    results.append(f"✅ nftables: rule deleted (handle {handle})")
                break
    else:
        results.append(f"ℹ️ nftables: no rule for {ip}")

    return f"## 🔓 Unblock {ip} on {server}\n" + "\n".join(results)


@mcp.tool()
async def fw_policy_check(server: str) -> str:
    """בדיקת מדיניות — INPUT policy, פורטים, bouncers, fail2ban."""
    lines = [f"## 🔍 Firewall Policy — {server}\n"]

    r = ssh_sudo(server, "nft list chain ip filter INPUT 2>/dev/null | head -3")
    if r.get("ok"):
        lines.append(f"**nftables INPUT:**\n```\n{r['stdout']}\n```")
        if "policy drop" in r["stdout"]:
            lines.append("⚠️ **Policy=DROP** — פורטים חדשים נחסמים!")
        elif "policy accept" in r["stdout"]:
            lines.append("✅ Policy=ACCEPT")

    r2 = ssh(server, "ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u")
    if r2.get("ok") and r2["stdout"]:
        lines.append(f"\n**LISTEN ports:**\n```\n{r2['stdout']}\n```")

    r3 = ssh_sudo(server, "cscli bouncers list 2>/dev/null")
    if r3.get("ok") and r3["stdout"]:
        lines.append(f"\n**CrowdSec Bouncers:**\n```\n{r3['stdout']}\n```")

    r4 = ssh(server, "fail2ban-client status 2>/dev/null")
    if r4.get("ok") and r4["stdout"]:
        lines.append(f"\n**Fail2ban:**\n```\n{r4['stdout']}\n```")

    return "\n".join(lines)


@mcp.tool()
async def fw_add_asterisk_protection(server: str) -> str:
    """הוסף הגנות Asterisk — SIP+RTP ports + fail2ban jail."""
    results = []

    for proto, port, desc in [("udp", 5060, "SIP"), ("tcp", 5060, "SIP TCP"), ("udp", "10000-20000", "RTP")]:
        r = ssh_sudo(server, f"nft add rule ip filter INPUT {proto} dport {port} accept comment \\\"{desc}\\\" 2>/dev/null")
        if r.get("ok"):
            results.append(f"✅ nftables: {desc} ({port}/{proto})")
        else:
            results.append(f"ℹ️ nftables: {desc} — already exists?")

    r_fb = ssh(server, "fail2ban-client status asterisk 2>/dev/null")
    if r_fb.get("ok") and "asterisk" in r_fb.get("stdout", ""):
        results.append("✅ fail2ban asterisk jail active")
    else:
        results.append("ℹ️ fail2ban: asterisk jail not configured")

    return f"## 🛡️ Asterisk Protection — {server}\n" + "\n".join(results)


@mcp.tool()
async def fw_ssh_status() -> str:
    """בדיקת SSH לכל הצי."""
    lines = ["## 🔗 SSH Connectivity\n"]
    lines.append("| Server | Status | Hostname | Uptime |")
    lines.append("|---|---|---|---|")

    for name in FLEET:
        r = ssh(name, "hostname; uptime -p 2>/dev/null")
        if r.get("ok") and r["stdout"]:
            parts = r["stdout"].split("\n")
            hn = parts[0].strip() if parts else "?"
            up = parts[1].strip() if len(parts) > 1 else "?"
            lines.append(f"| **{name}** | ✅ | {hn} | {up} |")
        else:
            lines.append(f"| **{name}** | ❌ | {r.get('error', 'unreachable')} | |")

    return "\n".join(lines)


# ─── Main ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8700)
