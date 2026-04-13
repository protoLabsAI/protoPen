"""Hardening validation — per-service checklists with remediation recommendations."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)

_SCRIPTS_DIR = Path(__file__).parent / "scripts"


class HardeningCheckTool(BasePentestTool):
    """Blue team hardening checklist validation with remediation."""

    name = "hardening_check"
    description = (
        "Hardening validation — per-service security checklists, "
        "baseline comparison, remediation recommendations with specific config changes."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "ssh_harden": {
            "cmd": ["python3", str(_SCRIPTS_DIR / "ssh_harden.py"), "{target}"],
            "timeout": 15,
            "description": "Validate SSH hardening against security baseline",
        },
        "nginx_harden": {
            "cmd": [
                "python3", "-c",
                "import json,subprocess; "
                "checks=[]; "
                "r=subprocess.run(['nginx','-T'],capture_output=True,text=True,timeout=5); "
                "conf=r.stdout.lower(); "
                "rules=["
                "('server_tokens','server_tokens off' in conf,'high','Add: server_tokens off;'),"
                "('X-Frame-Options','add_header x-frame-options' in conf,'high','Add: add_header X-Frame-Options DENY;'),"
                "('X-Content-Type-Options','x-content-type-options' in conf,'medium','Add: add_header X-Content-Type-Options nosniff;'),"
                "('ssl_protocols','ssl_protocols' in conf and 'tlsv1 ' not in conf,'high','Set: ssl_protocols TLSv1.2 TLSv1.3;'),"
                "('ssl_prefer_server_ciphers','ssl_prefer_server_ciphers on' in conf,'medium','Add: ssl_prefer_server_ciphers on;'),"
                "('HSTS','strict-transport-security' in conf,'high','Add: add_header Strict-Transport-Security \"max-age=31536000\";'),"
                "('CSP','content-security-policy' in conf,'medium','Add: add_header Content-Security-Policy \"default-src self\";'),"
                "]; "
                "result=[];\n"
                "for name,passed,severity,fix in rules:\n"
                "  result.append({'check':name,'passed':passed,'severity':severity,'remediation':fix})\n"
                "passed=sum(1 for c in result if c['passed']); "
                "print(json.dumps({'service':'nginx','total_checks':len(result),'passed':passed,'failed':len(result)-passed,'checks':result}))",
            ],
            "timeout": 15,
            "description": "Validate Nginx hardening (headers, TLS, info leaks)",
        },
        "apache_harden": {
            "cmd": [
                "python3", "-c",
                "import json,subprocess; "
                "r=subprocess.run(['apachectl','-t','-D','DUMP_CONFIG'],capture_output=True,text=True,timeout=5); "
                "conf=r.stdout.lower()+r.stderr.lower(); "
                "rules=["
                "('ServerTokens','servertokens prod' in conf,'high','Set: ServerTokens Prod'),"
                "('ServerSignature','serversignature off' in conf,'medium','Set: ServerSignature Off'),"
                "('TraceEnable','traceenable off' in conf,'high','Set: TraceEnable Off'),"
                "('Directory Listing','options -indexes' in conf or 'options none' in conf,'medium','Set: Options -Indexes in directory blocks'),"
                "]; "
                "result=[];\n"
                "for name,passed,severity,fix in rules:\n"
                "  result.append({'check':name,'passed':passed,'severity':severity,'remediation':fix})\n"
                "passed=sum(1 for c in result if c['passed']); "
                "print(json.dumps({'service':'apache','total_checks':len(result),'passed':passed,'failed':len(result)-passed,'checks':result}))",
            ],
            "timeout": 15,
            "description": "Validate Apache hardening (info disclosure, directory listing, TRACE)",
        },
        "docker_harden": {
            "cmd": [
                "python3", "-c",
                "import json,subprocess; "
                "checks=[]; "
                "try:\n"
                "  r=subprocess.run(['docker','info','--format','{{json .}}'],capture_output=True,text=True,timeout=10)\n"
                "  info=json.loads(r.stdout)\n"
                "  checks.append({'check':'User Namespaces','passed':info.get('SecurityOptions') and 'userns' in str(info['SecurityOptions']),'severity':'high','remediation':'Enable user namespaces in /etc/docker/daemon.json'})\n"
                "  checks.append({'check':'Live Restore','passed':info.get('LiveRestoreEnabled',False),'severity':'medium','remediation':'Set live-restore:true in /etc/docker/daemon.json'})\n"
                "except Exception: pass\n"
                "try:\n"
                "  r2=subprocess.run(['docker','ps','--format','{{json .}}'],capture_output=True,text=True,timeout=10)\n"
                "  for line in r2.stdout.splitlines():\n"
                "    c=json.loads(line)\n"
                "    if '--privileged' in c.get('Command',''):\n"
                "      checks.append({'check':'Container '+c.get('Names','')+' privileged','passed':False,'severity':'critical','remediation':'Remove --privileged flag'})\n"
                "except Exception: pass\n"
                "passed=sum(1 for c in checks if c.get('passed')); "
                "print(json.dumps({'service':'docker','total_checks':len(checks),'passed':passed,'failed':len(checks)-passed,'checks':checks}))",
            ],
            "timeout": 20,
            "description": "Validate Docker daemon and container hardening",
        },
        "k8s_harden": {
            "cmd": [
                "python3", "-c",
                "import json,subprocess; "
                "checks=[]; "
                "try:\n"
                "  r=subprocess.run(['kubectl','get','pods','--all-namespaces','-o','json'],capture_output=True,text=True,timeout=15)\n"
                "  data=json.loads(r.stdout)\n"
                "  for pod in data.get('items',[]):\n"
                "    name=pod['metadata']['name']; ns=pod['metadata']['namespace']\n"
                "    for c in pod['spec'].get('containers',[]):\n"
                "      sc=c.get('securityContext',{})\n"
                "      if sc.get('privileged'):\n"
                "        checks.append({'check':ns+'/'+name+' privileged','passed':False,'severity':'critical','remediation':'Remove privileged:true'})\n"
                "      if sc.get('runAsUser',1)==0 or not sc.get('runAsNonRoot'):\n"
                "        checks.append({'check':ns+'/'+name+' runs as root','passed':False,'severity':'high','remediation':'Set runAsNonRoot:true'})\n"
                "      if not c.get('resources',{}).get('limits'):\n"
                "        checks.append({'check':ns+'/'+name+' no resource limits','passed':False,'severity':'medium','remediation':'Set CPU/memory limits'})\n"
                "except Exception as e:\n"
                "  checks.append({'check':'K8s API access','passed':False,'severity':'info','remediation':str(e)})\n"
                "passed=sum(1 for c in checks if c.get('passed')); "
                "print(json.dumps({'service':'kubernetes','total_checks':len(checks),'passed':passed,'failed':len(checks)-passed,'checks':checks}))",
            ],
            "timeout": 30,
            "description": "Validate Kubernetes pod security (privileged, root, resource limits)",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "localhost",
        timeout: int = 30,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [c.format(target=target) for c in spec["cmd"]]
        effective_timeout = min(timeout, spec.get("timeout", 30))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
