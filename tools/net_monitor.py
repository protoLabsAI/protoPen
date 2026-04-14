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
                "python3",
                "-c",
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
                "python3",
                "-c",
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
                "python3",
                "-c",
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
                "python3",
                "-c",
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
                "python3",
                "-c",
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
        "arp_watch": {
            "cmd": [
                "python3",
                "-c",
                "import subprocess,json,collections; "
                "r=subprocess.run(['tshark','-i','{interface}','-a','duration:{duration}',"
                "'-f','arp','-T','fields',"
                "'-e','arp.src.proto_ipv4','-e','arp.src.hw_mac',"
                "'-e','arp.opcode','-e','frame.time_epoch'],"
                "capture_output=True,text=True,timeout={duration}+10); "
                "ip_to_macs=collections.defaultdict(set); "
                "mac_reply_times=collections.defaultdict(list); "
                "arp_events=[]; "
                "for line in r.stdout.splitlines():\n"
                "  fields=line.split('\\t')\n"
                "  if len(fields)<4: continue\n"
                "  src_ip,src_mac,opcode,ts=fields[0],fields[1],fields[2],fields[3]\n"
                "  if not src_ip or not src_mac: continue\n"
                "  ip_to_macs[src_ip].add(src_mac)\n"
                "  if opcode=='2':\n"
                "    try: mac_reply_times[src_mac].append(float(ts))\n"
                "    except: pass\n"
                "suspicious=[]; "
                "for ip,macs in ip_to_macs.items():\n"
                "  count=len(macs)\n"
                "  arp_events.append({{'ip':ip,'mac':','.join(sorted(macs)),'event_type':'ip_mac_mapping','count':count}})\n"
                "  if count>1:\n"
                "    suspicious.append({{'ip':ip,'mac':','.join(sorted(macs)),'event_type':'duplicate_ip_mac','count':count}})\n"
                "for mac,times in mac_reply_times.items():\n"
                "  if len(times)>10:\n"
                "    times_sorted=sorted(times)\n"
                "    window=times_sorted[-1]-times_sorted[0] if len(times_sorted)>1 else 1\n"
                "    rate=len(times)/max(window,1)\n"
                "    if rate>2:\n"
                "      suspicious.append({{'ip':'','mac':mac,'event_type':'gratuitous_arp_flood','count':len(times)}})\n"
                "anomaly=len(suspicious)>0; "
                "print(json.dumps({{'interface':'{interface}','duration_sec':{duration},"
                "'arp_events':arp_events,'suspicious':suspicious,'anomaly':anomaly}}))",
            ],
            "timeout": 120,
            "description": "Detect ARP spoofing/poisoning — duplicate IP-MAC mappings and gratuitous ARP floods",
        },
        "responder_detect": {
            "cmd": [
                "python3",
                "-c",
                "import subprocess,json,collections; "
                "r=subprocess.run(['tshark','-i','{interface}','-a','duration:{duration}',"
                "'-f','udp port 5355 or udp port 137 or udp port 5353',"
                "'-T','fields',"
                "'-e','ip.src','-e','udp.dstport',"
                "'-e','llmnr.qry.name','-e','nbns.name',"
                "'-e','dns.qry.name','-e','llmnr.type',"
                "'-e','nbns.flags.response','-e','dns.flags.response',"
                "'-e','dns.ptr.domain_name'],"
                "capture_output=True,text=True,timeout={duration}+10); "
                "llmnr_resp=collections.Counter(); "
                "nbns_resp=collections.Counter(); "
                "mdns_ptr=collections.Counter(); "
                "for line in r.stdout.splitlines():\n"
                "  fields=(line.split('\\t')+['','','','','','','','',''])[:9]\n"
                "  src_ip,dstport,llmnr_name,nbns_name,dns_name,llmnr_type,nbns_flag,dns_flag,ptr=fields\n"
                "  if dstport=='5355' and llmnr_type=='32800':\n"
                "    key=(src_ip,llmnr_name or dns_name)\n"
                "    llmnr_resp[key]+=1\n"
                "  if dstport=='137' and nbns_flag=='1':\n"
                "    key=(src_ip,nbns_name)\n"
                "    nbns_resp[key]+=1\n"
                "  if dstport=='5353' and dns_flag=='1' and ptr:\n"
                "    key=(src_ip,ptr)\n"
                "    mdns_ptr[key]+=1\n"
                "llmnr_responses=[{{'src_ip':k[0],'domain':k[1],'count':v}} for k,v in llmnr_resp.items()]; "
                "nbns_responses=[{{'src_ip':k[0],'domain':k[1],'count':v}} for k,v in nbns_resp.items()]; "
                "suspicious_hosts=list({{r['src_ip'] for r in llmnr_responses+nbns_responses}}); "
                "anomaly=len(suspicious_hosts)>0; "
                "print(json.dumps({{'interface':'{interface}','duration_sec':{duration},"
                "'llmnr_responses':llmnr_responses,'nbns_responses':nbns_responses,"
                "'suspicious_hosts':suspicious_hosts,'anomaly':anomaly}}))",
            ],
            "timeout": 120,
            "description": "Detect Responder/LLMNR poisoning — flag hosts sending LLMNR/NBT-NS responses",
        },
        "rogue_dhcp_detect": {
            "cmd": [
                "python3",
                "-c",
                "import subprocess,json,collections; "
                "r=subprocess.run(['tshark','-i','{interface}','-a','duration:{duration}',"
                "'-f','udp port 67 or udp port 68',"
                "'-T','fields',"
                "'-e','ip.src','-e','eth.src',"
                "'-e','bootp.option.dhcp','-e','bootp.ip.server'],"
                "capture_output=True,text=True,timeout={duration}+10); "
                "server_counts=collections.Counter(); "
                "server_macs=dict(); "
                "for line in r.stdout.splitlines():\n"
                "  fields=(line.split('\\t')+['','','',''])[:4]\n"
                "  src_ip,src_mac,dhcp_type,srv_ip=fields\n"
                "  if dhcp_type in ('2','5'):\n"
                "    key=src_ip or srv_ip\n"
                "    if not key: continue\n"
                "    server_counts[key]+=1\n"
                "    if key not in server_macs and src_mac:\n"
                "      server_macs[key]=src_mac\n"
                "dhcp_servers=[{{'ip':ip,'mac':server_macs.get(ip,''),'count':cnt}} for ip,cnt in server_counts.items()]; "
                "known={known_dhcp_servers}; "
                "known_set=set(known) if isinstance(known,list) else set(); "
                "rogue_servers=[{{'ip':s['ip'],'mac':s['mac']}} for s in dhcp_servers if s['ip'] not in known_set]; "
                "anomaly=len(rogue_servers)>0; "
                "print(json.dumps({{'interface':'{interface}','duration_sec':{duration},"
                "'dhcp_servers':dhcp_servers,'rogue_servers':rogue_servers,'anomaly':anomaly}}))",
            ],
            "timeout": 120,
            "description": "Detect rogue DHCP servers — flag any DHCP OFFER/ACK source not in the trusted list",
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
        known_dhcp_servers: str = "[]",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                network=network,
                interface=interface,
                duration=duration,
                known_hosts=known_hosts,
                baseline_services=baseline_services,
                expected_ports=expected_ports,
                allowed_protocols=allowed_protocols,
                known_dhcp_servers=known_dhcp_servers,
                timeout=timeout,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", 120)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target or network,
        )
