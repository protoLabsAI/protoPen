"""Incident response toolkit — log correlation, IOC matching, timeline reconstruction."""

from __future__ import annotations

import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class IrToolkitTool(BasePentestTool):
    """Blue team incident response — log analysis, IOC detection, timeline building."""

    name = "ir_toolkit"
    description = (
        "Incident response — log correlation across sources, IOC matching "
        "against threat intel, timeline reconstruction, containment recommendations."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "log_search": {
            "cmd": [
                "python3",
                "-c",
                "import json,subprocess,re; "
                "r=subprocess.run(['grep','-rn','-i','{pattern}','{log_path}','--include=*.log','--include=*.txt'],capture_output=True,text=True,timeout=30); "
                "lines=r.stdout.strip().splitlines()[:100]; "
                "results=[]; "
                "for line in lines:\n"
                "  parts=line.split(':',2)\n"
                "  if len(parts)>=3: results.append({{'file':parts[0],'line_num':parts[1],'content':parts[2][:300]}})\n"
                "print(json.dumps({{'pattern':'{pattern}','log_path':'{log_path}','match_count':len(results),'matches':results}}))",
            ],
            "timeout": 30,
            "description": "Search logs for a pattern across multiple log files",
        },
        "ioc_scan": {
            "cmd": [
                "python3",
                "-c",
                "import json,re,os; "
                "iocs={iocs}; "
                "findings=[]; "
                "log_path='{log_path}'; "
                "for root,dirs,files in os.walk(log_path):\n"
                "  for f in files:\n"
                "    if not f.endswith(('.log','.txt','.json')): continue\n"
                "    fp=os.path.join(root,f)\n"
                "    try:\n"
                "      with open(fp,'r',errors='replace') as fh:\n"
                "        for i,line in enumerate(fh,1):\n"
                "          for ioc in iocs:\n"
                "            if ioc.get('value','') in line:\n"
                "              findings.append({{'ioc_type':ioc.get('type','unknown'),'ioc_value':ioc['value'],'file':fp,'line':i,'context':line.strip()[:200]}})\n"
                "    except: pass\n"
                "print(json.dumps({{'ioc_count':len(iocs),'log_path':log_path,'findings':findings[:50],'total_hits':len(findings)}}))",
            ],
            "timeout": 60,
            "description": "Scan logs for known IOCs (IPs, domains, hashes, user agents)",
        },
        "auth_log_analyze": {
            "cmd": [
                "python3",
                "-c",
                "import json,re,collections; "
                "failed=collections.Counter(); success=collections.Counter(); "
                "brute_force=[]; "
                "with open('{log_path}','r',errors='replace') as f:\n"
                "  for line in f:\n"
                "    if 'Failed password' in line or 'authentication failure' in line:\n"
                "      m=re.search(r'from (\\S+)',line)\n"
                "      if m: failed[m.group(1)]+=1\n"
                "    elif 'Accepted' in line:\n"
                "      m=re.search(r'from (\\S+)',line)\n"
                "      if m: success[m.group(1)]+=1\n"
                "brute_force=[{{'ip':ip,'attempts':count,'severity':'critical' if count>100 else 'high'}} for ip,count in failed.most_common(20) if count>10]; "
                "success_after_fail=[ip for ip in success if ip in failed]; "
                "print(json.dumps({{'log_path':'{log_path}',"
                "'failed_auth_total':sum(failed.values()),'successful_auth_total':sum(success.values()),"
                "'top_failed_sources':dict(failed.most_common(20)),"
                "'brute_force_detected':brute_force,"
                "'success_after_brute_force':success_after_fail,"
                "'compromised_likely':len(success_after_fail)>0}}))",
            ],
            "timeout": 30,
            "description": "Analyze auth logs for brute force, successful compromise indicators",
        },
        "timeline_build": {
            "cmd": [
                "python3",
                "-c",
                "import json,re,os,heapq; "
                "log_path='{log_path}'; keyword='{keyword}'; "
                "events=[]; "
                "ts_patterns=[r'(\\d{{4}}-\\d{{2}}-\\d{{2}}[T ]\\d{{2}}:\\d{{2}}:\\d{{2}})',r'(\\w{{3}} \\d{{1,2}} \\d{{2}}:\\d{{2}}:\\d{{2}})']; "
                "for root,dirs,files in os.walk(log_path):\n"
                "  for f in files:\n"
                "    if not f.endswith(('.log','.txt','.json')): continue\n"
                "    fp=os.path.join(root,f)\n"
                "    try:\n"
                "      with open(fp,'r',errors='replace') as fh:\n"
                "        for i,line in enumerate(fh,1):\n"
                "          if keyword and keyword.lower() not in line.lower(): continue\n"
                "          ts=''\n"
                "          for pat in ts_patterns:\n"
                "            m=re.search(pat,line)\n"
                "            if m: ts=m.group(1); break\n"
                "          if ts: events.append({{'timestamp':ts,'source':f,'line':i,'event':line.strip()[:300]}})\n"
                "    except: pass\n"
                "events.sort(key=lambda e:e['timestamp']); "
                "print(json.dumps({{'keyword':keyword,'log_path':log_path,'event_count':len(events),'timeline':events[:100]}}))",
            ],
            "timeout": 60,
            "description": "Build chronological timeline of events from multiple log sources",
        },
        "containment_recommend": {
            "cmd": [],  # Pure Python
            "timeout": 5,
            "description": "Generate containment recommendations based on attack indicators",
        },
    }

    async def execute(
        self,
        action: str,
        log_path: str = "/var/log",
        pattern: str = "",
        keyword: str = "",
        iocs: str = "[]",
        attack_type: str = "",
        compromised_hosts: str = "[]",
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        if action == "containment_recommend":
            return self._containment_recommend(attack_type, compromised_hosts)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                log_path=log_path,
                pattern=pattern,
                keyword=keyword,
                iocs=iocs,
                timeout=timeout,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", 60)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=log_path,
        )

    def _containment_recommend(self, attack_type: str, compromised_hosts: str) -> str:
        """Generate containment recommendations based on attack indicators."""
        try:
            hosts = json.loads(compromised_hosts) if compromised_hosts else []
        except json.JSONDecodeError:
            hosts = []

        recommendations = {
            "immediate": [],
            "short_term": [],
            "long_term": [],
        }

        # Universal immediate actions
        recommendations["immediate"].extend(
            [
                "Isolate compromised hosts from the network (VLAN quarantine or firewall block)",
                "Preserve volatile evidence: memory dumps, running processes, network connections",
                "Rotate all credentials that may have been exposed",
            ]
        )

        attack_playbooks = {
            "brute_force": {
                "immediate": [
                    "Block attacker IP(s) at perimeter firewall",
                    "Lock affected accounts and force password reset",
                ],
                "short_term": [
                    "Enable account lockout policy (e.g., 5 failed attempts → 30 min lock)",
                    "Deploy fail2ban or equivalent on exposed services",
                    "Enable MFA on all remote access services",
                ],
                "long_term": [
                    "Implement IP reputation scoring at WAF/firewall",
                    "Move to certificate-based authentication where possible",
                ],
            },
            "malware": {
                "immediate": [
                    "Disconnect infected hosts from the network immediately",
                    "Identify and block C2 domains/IPs at DNS and firewall",
                    "Capture memory dump before remediation",
                ],
                "short_term": [
                    "Run full AV/EDR scan across all endpoints",
                    "Check for lateral movement indicators in adjacent hosts",
                    "Review scheduled tasks and startup items",
                ],
                "long_term": [
                    "Deploy EDR solution with behavioral detection",
                    "Implement network segmentation to limit lateral movement",
                    "Establish application whitelisting",
                ],
            },
            "data_exfil": {
                "immediate": [
                    "Block exfiltration destination (IP/domain) at firewall and DNS",
                    "Identify scope of data accessed",
                    "Enable enhanced logging on affected data stores",
                ],
                "short_term": [
                    "Audit all outbound connections from affected hosts",
                    "Check for DNS tunneling activity",
                    "Review DLP alerts for the past 30 days",
                ],
                "long_term": [
                    "Deploy DLP solution with content inspection",
                    "Implement egress filtering (deny-by-default outbound)",
                    "Encrypt sensitive data at rest and in transit",
                ],
            },
            "privilege_escalation": {
                "immediate": [
                    "Revoke escalated privileges immediately",
                    "Audit recent actions performed with elevated privileges",
                ],
                "short_term": [
                    "Patch the vulnerability used for escalation",
                    "Review SUID binaries and sudoers configuration",
                    "Audit service accounts for excessive permissions",
                ],
                "long_term": [
                    "Implement least privilege across all accounts",
                    "Deploy privileged access management (PAM) solution",
                    "Regular privilege audits with automated alerting",
                ],
            },
        }

        if attack_type in attack_playbooks:
            playbook = attack_playbooks[attack_type]
            for phase in ("immediate", "short_term", "long_term"):
                recommendations[phase].extend(playbook.get(phase, []))

        if hosts:
            recommendations["immediate"].insert(
                0, f"Priority hosts to isolate: {', '.join(str(h) for h in hosts[:10])}"
            )

        return json.dumps(
            {
                "attack_type": attack_type or "generic",
                "compromised_hosts": hosts,
                "recommendations": recommendations,
            },
            indent=2,
        )
