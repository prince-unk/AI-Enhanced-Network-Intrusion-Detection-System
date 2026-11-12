#!/usr/bin/env python3
import argparse,json,sys
from pathlib import Path
from nids_core import load_events,enrich_alert

def main():
    p=argparse.ArgumentParser(description="AI-Enhanced NIDS terminal interface")
    p.add_argument("--input",default="/var/log/suricata/eve.json")
    p.add_argument("--demo",action="store_true")
    p.add_argument("--limit",type=int,default=2000)
    p.add_argument("--json-out",default="")
    a=p.parse_args()
    events=load_events(a.input,demo=a.demo,limit=max(1,a.limit))
    alerts=[e for e in events if e.get("event_type")=="alert" or e.get("alert")]
    if not alerts:
        print("No alerts found. Use --demo to preview the pipeline or supply EVE JSON.")
        return 1
    results=[enrich_alert(e) for e in alerts]
    counts={s:sum(x["triage"]["severity"]==s for x in results) for s in ("HIGH","MEDIUM","LOW")}
    print("\\nAI-Enhanced Network Intrusion Detection System")
    print("="*45)
    print("Source:", "DEMO FIXTURES (synthetic)" if a.demo else a.input)
    print(f"Alerts processed: {len(results)}")
    print(f"HIGH {counts['HIGH']} | MEDIUM {counts['MEDIUM']} | LOW {counts['LOW']}\\n")
    for i,x in enumerate(results,1):
        print(f"[{i}] {x['triage']['severity']} — {x.get('alert',{}).get('signature','Unknown')}")
        print(f"    {x.get('src_ip','?')} -> {x.get('dest_ip','?')} {x.get('proto','')}")
        print("    "+x["triage"]["summary"])
        print("    Action: "+x["triage"]["recommended_action"]+"\\n")
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(results,indent=2),encoding="utf-8")
        print("Saved:",Path(a.json_out).resolve())
    return 0
if __name__=="__main__": sys.exit(main())
