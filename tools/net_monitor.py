"""Network monitoring — passive traffic baselines, anomaly detection, DNS monitoring."""
from __future__ import annotations

import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class NetMonitorTool(BasePentestTool):
    """Blue team network monitoring and anomaly detection."""

    name = "net_monitor"
    description = (
        "Network monitoring — passive traffic baselines, host/service anomaly "
        "detection, DNS exfiltration and tunneling detection."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "traffic_baseline": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json,collections; "
                "r=subprocess.run(['tshark','-i','{interface}','-a','duration:{duration}',"
                "'-T','fields','-e','ip.src','-e','ip.dst','-e','ip.proto','-e','tcp.dstport',"
                "'-e','udp.dstport','-e','frame.len'],capture_output=True,text=True,timeout={duration}+10); "
                "hosts=collections.Counter(); protocols=collections.Counter(); ports=collections.Counter(); "
                "total_bytes=0; pkt_count=0; "
                "for line in r.stdout.splitlines():\n"
                "  fields=line.split('\\t')\n"
                "  if len(fields)>=4:\n"
                "    pkt_count+=1\n"
                "    hosts[fields[0]]+=1; hosts[fields[1]]+=1\n"
                "    protocols[fields[2]]+=1\n"
                "    port=fields[3] or fields[4] if len(fields)>4 else ''\n"
                "    if port: ports[port]+=1\n"
                "    if len(fields)>5 and fields[5].isdigit(): total_bytes+=int(fields[5])\n"
                "print(json.dumps({{'interface':'{interface}','duration_sec':{duration},"
                "'packet_count':pkt_count,'total_bytes':total_bytes,"
                "'top_hosts':dict(hosts.most_common(20)),"
                "'protocol_distribution':dict(protocols.most_common(10)),"
                "'top_ports':dict(ports.most_common(20))}}))",
            ],
            "timeout": 120,
            "description": "Capture passive traffic baseline (host counts, protocols, port distribution)",
        },
        "host_discovery": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json; "
                "r=subprocess.run(['nmap','-sn','{network}','-oX','-'],capture_output=True,text=True,timeout=60); "
                "import xml.etree.ElementTree as ET; "
                "hosts=[]; "
                "try:\n"
                "  root=ET.fromstring(r.stdout)\n"
                "  for h in root.iter('host'):\n"
                "    addr=h.find('address')\n"
                "    hn=h.find('hostnames/hostname')\n"
                "    if addr is not None:\n"
                "      hosts.append({{'ip':addr.get('addr',''),'hostname':hn.get('name','') if hn is not None else ''}})\n"
                "except: pass\n"
                "known={known_hosts}; "
                "known_ips={{h['ip'] for h in known}} if isinstance(known,list) else set(known); "
                "new_hosts=[h for h in hosts if h['ip'] not in known_ips]; "
                "print(json.dumps({{'network':'{network}','total_hosts':len(hosts),'hosts':hosts,"
                "'known_count':len(known_ips),'new_hosts':new_hosts,"
                "'anomaly':len(new_hosts)>0}}))",
            ],
            "timeout": 120,
            "description": "Discover hosts on network and flag unknown ones against baseline",
        },
        "service_diff": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json; "
                "r=subprocess.run(['nmap','-sV','--top-ports','1000','{target}','-oX','-'],capture_output=True,text=True,timeout=120); "
                "import xml.etree.ElementTree as ET; "
                "services=[]; "
                "try:\n"
                "  root=ET.fromstring(r.stdout)\n"
                "  for p in root.iter('port'):\n"
                "    state=p.find('state')\n"
                "    svc=p.find('service')\n"
                "    if state is not None and state.get('state')=='open':\n"
                "      services.append({{'port':int(p.get('portid',0)),'service':svc.get('name','') if svc is not None else '','version':svc.get('version','') if svc is not None else ''}})\n"
                "except: pass\n"
                "baseline={baseline_services}; "
                "baseline_ports={{s['port'] for s in baseline}} if isinstance(baseline,list) else set(); "
                "current_ports={{s['port'] for s in services}}; "
                "new_services=[s for s in services if s['port'] not in baseline_ports]; "
                "removed=[s for s in baseline if isinstance(s,dict) and s.get('port') not in current_ports]; "
                "print(json.dumps({{'target':'{target}','current_services':services,"
                "'new_services':new_services,'removed_services':removed,"
                "'anomaly':len(new_services)>0 or len(removed)>0}}))",
            ],
            "timeout": 180,
            "description": "Compare current services against baseline, flag new/removed services",
        },
        "dns_monitor": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json,collections; "
                "r=subprocess.run(['tshark','-i','{interface}','-a','duration:{duration}',"
                "'-f','port 53','-T','fields','-e','dns.qry.name','-e','dns.qry.type',"
                "'-e','ip.src','-e','dns.resp.type','-e','dns.txt'],capture_output=True,text=True,timeout={duration}+10); "
                "queries=collections.Counter(); src_hosts=collections.Counter(); "
                "suspicious=[]; txt_records=[]; "
                "for line in r.stdout.splitlines():\n"
                "  fields=line.split('\\t')\n"
                "  if not fields[0]: continue\n"
                "  domain=fields[0]; queries[domain]+=1\n"
                "  if len(fields)>2: src_hosts[fields[2]]+=1\n"
                "  labels=domain.split('.')\n"
                "  if any(len(l)>40 for l in labels):\n"
                "    suspicious.append({{'type':'long_label','domain':domain,'note':'Possible DNS tunneling/exfil'}})\n"
                "  if len(labels)>6:\n"
                "    suspicious.append({{'type':'deep_subdomain','domain':domain,'note':'Unusual subdomain depth'}})\n"
                "  if len(fields)>4 and fields[4]: txt_records.append({{'domain':domain,'txt':fields[4][:200]}})\n"
                "high_volume=[{{'domain':d,'count':c}} for d,c in queries.most_common(5) if c>50]; "
                "if high_volume: suspicious.extend([{{**h,'type':'high_volume','note':'Unusually high query rate'}} for h in high_volume]); "
                "print(json.dumps({{'interface':'{interface}','duration_sec':{duration},"
                "'total_queries':sum(queries.values()),"
                "'unique_domains':len(queries),"
                "'top_queried':dict(queries.most_common(20)),"
                "'top_sources':dict(src_hosts.most_common(10)),"
                "'suspicious':suspicious,'txt_records':txt_records[:10],"
                "'anomaly':len(suspicious)>0}}))",
            ],
            "timeout": 120,
            "description": "Monitor DNS traffic for exfiltration, tunneling, and suspicious queries",
        },
        "protocol_anomaly": {
            "cmd": [
                "python3", "-c",
                "import subprocess,json,collections; "
                "r=subprocess.run(['tshark','-i','{interface}','-a','duration:{duration}',"
                "'-T','fields','-e','frame.protocols','-e','ip.src','-e','ip.dst'],capture_output=True,text=True,timeout={duration}+10); "
                "protocols=collections.Counter(); flows=collections.Counter(); "
                "for line in r.stdout.splitlines():\n"
                "  fields=line.split('\\t')\n"
                "  if fields[0]: protocols[fields[0]]+=1\n"
                "  if len(fields)>=3: flows[fields[1]+'->'+fields[2]]+=1\n"
                "allowed={allowed_protocols}; "
                "unexpected=[{{'protocol':p,'count':c}} for p,c in protocols.items() if not any(a in p for a in allowed)]; "
                "print(json.dumps({{'interface':'{interface}','duration_sec':{duration},"
                "'protocol_counts':dict(protocols.most_common(20)),"
                "'top_flows':dict(flows.most_common(20)),"
                "'unexpected_protocols':unexpected,"
                "'anomaly':len(unexpected)>0}}))",
            ],
            "timeout": 120,
            "description": "Detect unexpected protocols on the network",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        network: str = "192.168.1.0/24",
        interface: str = "eth0",
        duration: int = 30,
        known_hosts: str = "[]",
        baseline_services: str = "[]",
        expected_ports: str = "[22,80,443]",
        allowed_protocols: str = '["eth","ip","tcp","udp","dns","http","tls"]',
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target, network=network, interface=interface,
                duration=duration, known_hosts=known_hosts,
                baseline_services=baseline_services,
                expected_ports=expected_ports,
                allowed_protocols=allowed_protocols,
                timeout=timeout,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 120))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target or network,
        )
