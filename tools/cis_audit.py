"""Defensive scanning — CIS benchmarks, config audits, patch assessment, port baselines."""
from __future__ import annotations

import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class CisAuditTool(BasePentestTool):
    """Blue team defensive scanning and configuration auditing."""

    name = "cis_audit"
    description = (
        "Defensive scanning — CIS benchmark checks, SSH/TLS/firewall config audits, "
        "patch level assessment, open port baseline comparison."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "ssh_audit": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json,re; "
                "r=subprocess.run(['ssh','-G','{target}'],capture_output=True,text=True,timeout=5); "
                "cfg={{}}; "
                "[cfg.__setitem__(parts[0],parts[1]) for line in r.stdout.splitlines() "
                "if (parts:=line.split(None,1)) and len(parts)==2]; "
                "issues=[]; "
                "if cfg.get('passwordauthentication','')=='yes': issues.append({{'severity':'high','check':'PasswordAuthentication','value':'yes','recommendation':'Set to no, use key-based auth'}}); "
                "if cfg.get('permitrootlogin','')!='no': issues.append({{'severity':'high','check':'PermitRootLogin','value':cfg.get('permitrootlogin','unset'),'recommendation':'Set to no'}}); "
                "if cfg.get('protocol','')=='1': issues.append({{'severity':'critical','check':'Protocol','value':'1','recommendation':'Use Protocol 2 only'}}); "
                "if cfg.get('x11forwarding','')=='yes': issues.append({{'severity':'medium','check':'X11Forwarding','value':'yes','recommendation':'Disable unless needed'}}); "
                "if cfg.get('permitemptypasswords','')=='yes': issues.append({{'severity':'critical','check':'PermitEmptyPasswords','value':'yes','recommendation':'Set to no'}}); "
                "print(json.dumps({{'target':'{target}','checks_run':5,'issues':issues,'pass_count':5-len(issues),'fail_count':len(issues)}}))",
            ],
            "timeout": 15,
            "description": "Audit SSH server configuration against CIS benchmarks",
        },
        "tls_audit": {
            "cmd": [
                "python3", "-c",
                "import ssl,socket,json,datetime; "
                "ctx=ssl.create_default_context(); "
                "issues=[]; "
                "try:\n"
                "  with ctx.wrap_socket(socket.socket(),server_hostname='{target}') as s:\n"
                "    s.settimeout(5); s.connect(('{target}',{port})); "
                "    cert=s.getpeercert(); ver=s.version(); cipher=s.cipher();\n"
                "    if 'TLSv1.0' in ver or 'TLSv1.1' in ver or 'SSLv' in ver:\n"
                "      issues.append({{'severity':'critical','check':'Protocol Version','value':ver,'recommendation':'Use TLS 1.2+ only'}})\n"
                "    na=cert.get('notAfter',''); "
                "    exp=datetime.datetime.strptime(na,'%b %d %H:%M:%S %Y %Z') if na else None;\n"
                "    if exp and exp < datetime.datetime.utcnow():\n"
                "      issues.append({{'severity':'critical','check':'Certificate Expiry','value':na,'recommendation':'Renew certificate'}})\n"
                "    elif exp and (exp - datetime.datetime.utcnow()).days < 30:\n"
                "      issues.append({{'severity':'high','check':'Certificate Expiry','value':f'Expires in {{(exp-datetime.datetime.utcnow()).days}} days','recommendation':'Renew soon'}})\n"
                "    if cipher and cipher[2] < 128:\n"
                "      issues.append({{'severity':'high','check':'Cipher Strength','value':f'{{cipher[0]}} ({{cipher[2]}} bits)','recommendation':'Use 128-bit+ ciphers'}})\n"
                "    print(json.dumps({{'target':'{target}','port':{port},'protocol':ver,'cipher':cipher[0] if cipher else '','cert_subject':dict(x[0] for x in cert.get('subject',())) if cert else {{}},'issues':issues}}))\n"
                "except Exception as e:\n"
                "  print(json.dumps({{'target':'{target}','port':{port},'error':str(e),'issues':[{{'severity':'info','check':'TLS Connection','value':str(e)}}]}}))\n",
            ],
            "timeout": 15,
            "description": "Audit TLS/SSL configuration (protocol version, cipher strength, cert expiry)",
        },
        "firewall_audit": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json,platform; "
                "os_type=platform.system(); issues=[]; rules=''; "
                "if os_type=='Linux':\n"
                "  r=subprocess.run(['iptables','-L','-n','--line-numbers'],capture_output=True,text=True,timeout=5)\n"
                "  rules=r.stdout; "
                "  if 'ACCEPT' in rules and 'DROP' not in rules and 'REJECT' not in rules:\n"
                "    issues.append({{'severity':'high','check':'Default Policy','value':'No deny rules found','recommendation':'Set default policy to DROP'}})\n"
                "  if not rules.strip() or 'Chain INPUT (policy ACCEPT)' in rules:\n"
                "    issues.append({{'severity':'critical','check':'Input Policy','value':'ACCEPT (default)','recommendation':'Set INPUT policy to DROP, whitelist needed ports'}})\n"
                "elif os_type=='Darwin':\n"
                "  r=subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw','--getglobalstate'],capture_output=True,text=True,timeout=5)\n"
                "  rules=r.stdout; "
                "  if 'disabled' in rules.lower():\n"
                "    issues.append({{'severity':'high','check':'macOS Firewall','value':'Disabled','recommendation':'Enable application firewall'}})\n"
                "print(json.dumps({{'os':os_type,'rules_snippet':rules[:500],'issues':issues}}))",
            ],
            "timeout": 15,
            "description": "Audit firewall rules and default policies",
        },
        "patch_check": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json,platform; "
                "os_type=platform.system(); packages=[]; "
                "if os_type=='Linux':\n"
                "  r=subprocess.run(['apt','list','--upgradable'],capture_output=True,text=True,timeout=30)\n"
                "  if r.returncode==0:\n"
                "    for line in r.stdout.splitlines()[1:]:\n"
                "      if '/' in line: packages.append(line.split('/')[0])\n"
                "  else:\n"
                "    r=subprocess.run(['yum','check-update','--quiet'],capture_output=True,text=True,timeout=30)\n"
                "    for line in r.stdout.splitlines():\n"
                "      parts=line.split()\n"
                "      if len(parts)>=2: packages.append(parts[0])\n"
                "elif os_type=='Darwin':\n"
                "  r=subprocess.run(['softwareupdate','-l'],capture_output=True,text=True,timeout=30)\n"
                "  for line in r.stdout.splitlines():\n"
                "    if '*' in line: packages.append(line.strip().lstrip('* '))\n"
                "severity='critical' if len(packages)>20 else 'high' if len(packages)>5 else 'medium' if packages else 'info'; "
                "print(json.dumps({{'os':os_type,'pending_updates':len(packages),'packages':packages[:30],'severity':severity}}))",
            ],
            "timeout": 60,
            "description": "Check for pending security patches and updates",
        },
        "port_baseline": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json; "
                "r=subprocess.run(['nmap','-sT','-p-','--min-rate=1000','-T4','{target}','-oX','-'],capture_output=True,text=True,timeout={timeout}); "
                "import xml.etree.ElementTree as ET; "
                "ports=[]; "
                "try:\n"
                "  root=ET.fromstring(r.stdout)\n"
                "  for p in root.iter('port'):\n"
                "    state=p.find('state')\n"
                "    svc=p.find('service')\n"
                "    if state is not None and state.get('state')=='open':\n"
                "      ports.append({{'port':int(p.get('portid',0)),'protocol':p.get('protocol',''),'service':svc.get('name','') if svc is not None else ''}})\n"
                "except: pass\n"
                "expected={expected_ports}; "
                "open_set={{p['port'] for p in ports}}; "
                "unexpected=[p for p in ports if p['port'] not in expected]; "
                "missing=[ep for ep in expected if ep not in open_set]; "
                "print(json.dumps({{'target':'{target}','open_ports':ports,'expected':expected,"
                "'unexpected':unexpected,'missing_expected':missing,"
                "'issues':[{{'severity':'high','check':'Unexpected port','port':p['port'],'service':p['service']}} for p in unexpected]}}))",
            ],
            "timeout": 300,
            "description": "Compare open ports against expected baseline",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "localhost",
        port: int = 443,
        expected_ports: str = "[22,80,443]",
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target, port=port,
                expected_ports=expected_ports, timeout=timeout,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 60))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
