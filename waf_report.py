#!/usr/bin/env python3
"""
waf_report.py - Rapport d'analyse des logs de MiniWAF.

Lit waf.log (et ses archives waf.log.1, waf.log.2...) et affiche :
  - la periode couverte et le nombre d'evenements par type
  - les categories d'attaques, les IP les plus agressives, les chemins les plus vises
  - les regles les plus declenchees et les outils de scan reperes
  - une chronologie heure par heure

Usage :
  python3 waf_report.py                     # rapport texte
  python3 waf_report.py --top 5 --ip 1.2.3.4
  python3 waf_report.py --json > rapport.json
"""

import argparse
import glob
import json
import os
import re
from collections import Counter

ATTACK_ACTIONS = {"blocked", "detected", "trap", "leak_blocked"}


def read_events(log_path):
    """Lit le log courant et ses archives, du plus ancien au plus recent.

    RotatingFileHandler renomme waf.log en waf.log.1, puis waf.log.1 en waf.log.2... :
    plus le numero est grand, plus le fichier est ancien.
    """
    archives = [f for f in glob.glob(log_path + ".*") if f.rsplit(".", 1)[-1].isdigit()]
    archives.sort(key=lambda f: int(f.rsplit(".", 1)[-1]), reverse=True)
    files = archives + [log_path]
    events, bad_lines = [], 0
    for path in files:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    bad_lines += 1   # ligne corrompue : on la saute sans planter
                    continue
                if isinstance(event, dict):
                    events.append(event)
    return events, bad_lines


def analyze(events, top=10):
    attacks = [e for e in events if e.get("action") in ATTACK_ACTIONS]
    times = sorted(e["time"] for e in events if "time" in e)
    rules, scanners, hours = Counter(), Counter(), Counter()
    for e in attacks:
        for rule in e.get("rules", []):
            rules[rule.rsplit(" (", 1)[0]] += 1      # "2001 Balise script (url)" -> "2001 Balise script"
            match = re.search(r"Outil detecte : (\S+)", rule)
            if match:
                scanners[match.group(1)] += 1
        if "time" in e:
            hours[e["time"][:13] + "h"] += 1          # "2026-11-19 14"
    return {
        "period": {"start": times[0] if times else None, "end": times[-1] if times else None},
        "total_events": len(events),
        "total_attacks": len(attacks),
        "actions": dict(Counter(e.get("action", "?") for e in events).most_common()),
        "categories": dict(Counter(c for e in attacks for c in e.get("categories", [])).most_common(top)),
        "top_ips": Counter(e.get("ip", "?") for e in attacks).most_common(top),
        "top_paths": Counter((e.get("path") or "(inconnu)").split("?")[0]
                             for e in attacks).most_common(top),
        "top_rules": rules.most_common(top),
        "scanners": dict(scanners.most_common(top)),
        "bans": sum(1 for e in events if e.get("action") == "banned"),
        "traps": Counter(e.get("path") or "(inconnu)" for e in events
                         if e.get("action") == "trap").most_common(top),
        "timeline": dict(sorted(hours.items())),
    }


def bar(value, maximum, width=30):
    return "#" * max(1, round(value / maximum * width)) if maximum else ""


def print_table(title, rows):
    print(f"\n== {title} ==")
    if not rows:
        print("  (aucun)")
        return
    maximum = max(v for _, v in rows)
    for name, value in rows:
        print(f"  {str(name)[:45]:<45} {value:>6}  {bar(value, maximum)}")


def print_report(r, bad_lines):
    print("=" * 70)
    print(" RAPPORT MINIWAF")
    print("=" * 70)
    print(f"  Periode         : {r['period']['start']}  ->  {r['period']['end']}")
    print(f"  Evenements      : {r['total_events']}")
    print(f"  Attaques        : {r['total_attacks']}")
    print(f"  Bannissements   : {r['bans']}")
    if bad_lines:
        print(f"  Lignes ignorees : {bad_lines} (format invalide)")
    print_table("Evenements par type", list(r["actions"].items()))
    print_table("Categories d'attaques", list(r["categories"].items()))
    print_table("IP les plus agressives", r["top_ips"])
    print_table("Chemins les plus vises", r["top_paths"])
    print_table("Regles les plus declenchees", r["top_rules"])
    print_table("Outils de scan reperes", list(r["scanners"].items()))
    print_table("Pieges declenches", r["traps"])
    print_table("Chronologie des attaques (par heure)", list(r["timeline"].items()))


def main():
    parser = argparse.ArgumentParser(description="Rapport d'analyse des logs MiniWAF")
    parser.add_argument("--log", default="waf.log", help="fichier de log (defaut : waf.log)")
    parser.add_argument("--top", type=int, default=10, help="nombre de lignes par classement")
    parser.add_argument("--ip", help="ne garder que les evenements de cette IP")
    parser.add_argument("--json", action="store_true", help="sortie JSON (pour un SIEM ou un script)")
    args = parser.parse_args()

    events, bad_lines = read_events(args.log)
    if args.ip:
        events = [e for e in events if e.get("ip") == args.ip]
    if not events:
        print(f"Aucun evenement trouve dans {args.log}.")
        return
    report = analyze(events, args.top)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report, bad_lines)


if __name__ == "__main__":
    main()
