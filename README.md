# mcp-fw 🔥

**MCP Firewall Manager** — Fail2ban + CrowdSec + nftables fleet-wide control for yohay.ai

## Tools

| Tool | Description |
|---|---|
| `fw_fleet_summary` | סיכום צי — איזה שכבות FW רצות על כל שרת |
| `fw_fail2ban_status` | מצב fail2ban — jails, IPs חסומים |
| `fw_fail2ban_ban` | חסום IP ב-fail2ban |
| `fw_fail2ban_unban` | שחרר IP מ-fail2ban |
| `fw_crowdsec_decisions` | הצג החלטות CrowdSec |
| `fw_crowdsec_remove_decision` | הסר החלטת CrowdSec |
| `fw_nft_rules` | הצג חוקי nftables |
| `fw_nft_allow_port` | הוסף ACCEPT לפורט ב-nftables |
| `fw_block_ip_global` | חסום IP — CrowdSec + nftables |
| `fw_unblock_ip_global` | שחרר IP — CrowdSec + nftables |
| `fw_policy_check` | בדיקת מדיניות — policy, פורטים, bouncers |
| `fw_add_asterisk_protection` | הוסף הגנות Asterisk — SIP + RTP + fail2ban |
| `fw_ssh_status` | בדיקת SSH לכל הצי |

## Fleet

dgxmain, dgxsec, gama-2, arcai, storai, openwebui-vps, 5060ihome
