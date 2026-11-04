#!/usr/bin/env python3
"""Local half of the Shodan-to-CERT skill. Searching happens in the user's logged-in Shodan tab (see SKILL.md),
so no API key and no query credits are used. This script never contacts a host it is told about.

  shodan_cert.py self [--ip IP] [--allow 443,51820] [--json]   is my own connection on Shodan? (InternetDB, free)
  shodan_cert.py import HOSTS.json [--downloads DIR]           store the browser's host check + its screenshots
  shodan_cert.py draft BODY --to ADDR --subject S              write an .eml with Shodan's screenshots inline

`self` exits 0 when nothing unexpected is open, 1 when Shodan lists open ports or vulnerabilities outside --allow,
2 on errors, so cron, Home Assistant or anything else can alert on it.
Output: $SHODAN_CERT_OUT, else ~/.local/state/shodan-cert-report/. Findings stay there, never in a repository.
Standard library only, Python 3.9 or newer.
"""
import argparse
import html
import json
import os
import re
import shutil
import sys
from datetime import date
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

INTERNETDB = os.environ.get("INTERNETDB_BASE", "https://internetdb.shodan.io")
MYIP = os.environ.get("MYIP_URL", "https://api.ipify.org")
TINY_SHOT = 2500  # bytes; a screenshot this small is usually a black or empty screen
# Ports of industrial and building-automation protocols. A host that answers on three or more of them is most likely
# a honeypot that imitates several vendors at once.
ICS_PORTS = {102, 502, 789, 1911, 1962, 2404, 2455, 4800, 4911, 5007, 9600, 18245, 20000, 20256, 44818, 47808}
CLOUD = re.compile(r"amazon|\baws\b|oracle|linode|akamai|vultr|digitalocean|microsoft|azure|google|hosthatch|aeza"
                   r"|hetzner|\bovh|contabo|scaleway|alibaba|tencent", re.I)
LINK_HOSTS = ("shodan.io", "www.shodan.io")  # the only links a report gets; never a link to the host itself


def out_dir(*parts):
    base = Path(os.environ.get("SHODAN_CERT_OUT") or Path.home() / ".local/state/shodan-cert-report")
    path = base.joinpath(*parts)
    path.mkdir(parents=True, exist_ok=True)
    return path


def slug(text, limit=60):
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:limit] or "draft"


def http_get(url):
    with urlopen(Request(url, headers={"User-Agent": "shodan-cert-report"}), timeout=20) as resp:
        return resp.read().decode()


# ---------------------------------------------------------------- self

def cmd_self(args):
    try:
        ip = args.ip or http_get(MYIP).strip()
    except (URLError, OSError) as err:
        print(f"could not find the public IP: {err}", file=sys.stderr)
        return 2
    try:
        data = json.loads(http_get(f"{INTERNETDB}/{ip}"))
    except HTTPError as err:
        if err.code == 404:
            data = {"ip": ip, "ports": [], "vulns": [], "tags": [], "hostnames": [], "cpes": []}
        else:
            print(f"InternetDB answered {err.code}", file=sys.stderr)
            return 2
    except (URLError, OSError, ValueError) as err:
        print(f"InternetDB unreachable: {err}", file=sys.stderr)
        return 2
    allowed = {int(p) for p in args.allow.split(",") if p.strip()} if args.allow else set()
    unexpected = sorted(set(data.get("ports") or []) - allowed)
    vulns = sorted(data.get("vulns") or [])
    found = bool(unexpected or vulns)
    if args.json:
        print(json.dumps({**data, "ip": ip, "unexpected_ports": unexpected, "found": found}))
    elif not data.get("ports") and not vulns:
        print(f"{ip}: Shodan lists nothing open.")
    else:
        print(f"{ip}: Shodan lists ports {data.get('ports')}" + (f", allowed {sorted(allowed)}" if allowed else ""))
        if unexpected:
            print(f"  unexpected open ports: {unexpected}")
        if vulns:
            print(f"  vulnerabilities by version: {', '.join(vulns[:20])}" + (" …" if len(vulns) > 20 else ""))
        if data.get("tags"):
            print(f"  tags: {', '.join(data['tags'])}")
        print(f"  details: https://www.shodan.io/host/{ip}")
        print("  For mail when this changes, add the IP in Shodan Monitor: https://monitor.shodan.io")
    return 1 if found else 0


# ---------------------------------------------------------------- import

def as_list(text):
    """Accept what the browser printed: {ip: {...}}, [{...}], or that object as a JSON string."""
    data = json.loads(text)
    if isinstance(data, str):
        data = json.loads(data)
    if isinstance(data, dict):
        return [{"ip": ip, **v} for ip, v in data.items()]
    return list(data)


def summarise(d):
    """The facts a report needs from the browser's host check, plus the reasons to doubt the host is real."""
    tags = sorted(set(d.get("tags") or []))
    ports = sorted({int(p) for p in d.get("ports") or []})
    ics = [p for p in ports if p in ICS_PORTS]
    org = " / ".join(x for x in (d.get("org"), d.get("isp")) if x)
    honeypot = bool(d.get("honeypot")) or "honeypot" in tags
    doubts = []
    if honeypot:
        doubts.append("tagged honeypot by Shodan")
    if len(ics) >= 3:
        doubts.append(f"{len(ics)} industrial protocols on one IP ({', '.join(map(str, ics))})")
    if CLOUD.search(org):
        doubts.append("cloud or hosting range")
    return {
        "ip": d["ip"], "org": d.get("org", ""), "isp": d.get("isp", ""), "asn": d.get("asn", ""),
        "city": d.get("city", ""), "country": d.get("country", ""),
        "hostnames": d.get("hostnames") or [], "domains": d.get("domains") or [],
        "ports": ports, "tags": tags, "last_seen": d.get("lastSeen", ""),
        "honeypot": honeypot, "compromised": "compromised" in tags, "doubts": doubts, "screenshots": [],
    }


def cmd_import(args):
    downloads = Path(args.downloads).expanduser()
    shots_dir = out_dir("shots")
    for d in as_list(Path(args.file).read_text()):
        if d.get("err"):
            print(f"{d['ip']}  ERROR {d['err']}")
            continue
        info = summarise(d)
        ip = info["ip"]
        for src in sorted(downloads.glob(f"shodan-{ip}-*")):
            if src.suffix.lower() not in (".jpg", ".jpeg", ".png"):
                continue
            dest = shots_dir / src.name
            shutil.move(str(src), dest)
            size = dest.stat().st_size
            info["screenshots"].append({"path": str(dest), "bytes": size, "maybe_blank": size < TINY_SHOT})
        (out_dir("hosts") / f"{ip}.json").write_text(json.dumps(info, indent=1))
        verdict = "HONEYPOT" if info["honeypot"] else ("DOUBT" if info["doubts"] else "looks real")
        print(f"{ip}  {verdict}  {info['org'] or '-'}  {info['city'] or '-'}  seen {info['last_seen'] or '?'}")
        print(f"   ports {info['ports'] or '?'}  tags {info['tags'] or '-'}")
        if info["hostnames"] or info["domains"]:
            print(f"   names {', '.join(info['hostnames'] + info['domains'])[:200]}")
        for doubt in info["doubts"]:
            print(f"   doubt: {doubt}")
        for s in info["screenshots"]:
            print(f"   screenshot {s['path']}" + ("  (tiny, maybe blank)" if s["maybe_blank"] else ""))
        if d.get("screenshots") and not info["screenshots"]:
            print(f"   {d['screenshots']} screenshot(s) on Shodan, none found in {downloads}")


# ---------------------------------------------------------------- draft

HOST_TOKEN = re.compile(r"\{\{host:([0-9a-fA-F.:]+?)\}\}")
URL = re.compile(r"https?://[^\s<>\"]+")


def load_host(ip):
    path = out_dir("hosts") / f"{ip}.json"
    if not path.is_file():
        raise SystemExit(f"No host check for {ip}. Run shodan-hostcheck.js for it and `shodan_cert.py import` first.")
    return json.loads(path.read_text())


def linkify(text_html):
    def one(m):
        url = html.unescape(m.group(0))
        if urlparse(url).hostname not in LINK_HOSTS:
            print(f"warning: left unlinked, not a Shodan link: {url}", file=sys.stderr)
            return m.group(0)
        return f'<a href="{html.escape(url)}">{m.group(0)}</a>'
    return URL.sub(one, text_html)


def build_draft(body, to, subject, sender=None, allow_doubtful=False):
    """Return an EmailMessage from a plain-text body.

    Body rules: paragraphs are separated by blank lines, a line that is only **text** is a bold heading, and
    {{host:IP}} becomes the Shodan host link with that host's screenshots inline below it.
    """
    images, problems = [], []

    def expand(m, as_html):
        ip = m.group(1)
        info = load_host(ip)
        if info["honeypot"]:
            problems.append(f"{ip} is tagged honeypot")
        elif info["doubts"] and not allow_doubtful:
            problems.append(f"{ip}: {'; '.join(info['doubts'])}")
        link = f"https://www.shodan.io/host/{ip}"
        if not as_html:
            return link
        out = f'<a href="{link}">{link}</a>'
        for s in info["screenshots"]:
            if s["maybe_blank"]:
                continue
            cid = make_msgid(domain="shodan-cert-report")[1:-1]
            images.append((cid, Path(s["path"])))
            out += f'<br><img src="cid:{cid}" alt="Shodan screenshot {ip}" style="max-width:100%">'
        return out

    text = HOST_TOKEN.sub(lambda m: expand(m, False), body)
    paragraphs = []
    for para in re.split(r"\n\s*\n", body.strip()):
        lines = []
        for line in para.splitlines():
            bold = re.fullmatch(r"\s*\*\*(.+)\*\*\s*", line)
            safe = linkify(html.escape(bold.group(1) if bold else line))
            safe = HOST_TOKEN.sub(lambda m: expand(m, True), safe)
            lines.append(f"<b>{safe}</b>" if bold else safe)
        paragraphs.append("<p>" + "<br>\n".join(lines) + "</p>")
    if problems:
        raise SystemExit("Not drafted:\n  " + "\n  ".join(dict.fromkeys(problems))
                         + "\nRemove these hosts, or pass --allow-doubtful for doubts you have checked by hand."
                         + " A honeypot tag is never allowed.")

    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject
    if sender:
        msg["From"] = sender
    msg["Date"] = formatdate(localtime=True)
    msg["X-Unsent"] = "1"  # Outlook and some other clients open the file as an unsent draft
    msg.set_content(re.sub(r"^\s*\*\*(.+)\*\*\s*$", r"\1", text, flags=re.M))
    msg.add_alternative("<html><body>\n" + "\n".join(paragraphs) + "\n</body></html>", subtype="html")
    html_part = msg.get_payload()[1]
    for cid, path in images:
        sub = "png" if path.suffix == ".png" else "jpeg"
        html_part.add_related(path.read_bytes(), "image", sub, cid=f"<{cid}>", filename=path.name)
    return msg


def cmd_draft(args):
    msg = build_draft(Path(args.body).read_text(), args.to, args.subject, args.sender, args.allow_doubtful)
    path = out_dir("drafts") / f"{date.today()}-{slug(args.subject, 40)}.eml"
    path.write_bytes(bytes(msg))
    print(f"draft written: {path}\nIt is not sent. Open it, read it, and send it yourself.")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("self", help="is my own connection on Shodan?")
    s.add_argument("--ip", help="check this IP instead of the current public one")
    s.add_argument("--allow", help="ports you expect to be open, e.g. 443,51820")
    s.add_argument("--json", action="store_true", help="one JSON line, for Home Assistant or scripts")
    s.set_defaults(func=cmd_self)
    i = sub.add_parser("import", help="store the browser's host check and screenshots")
    i.add_argument("file", help="JSON printed by shodan-hostcheck.js (window.__hp)")
    i.add_argument("--downloads", default="~/Downloads", help="where the browser saved shodan-<ip>-<n>.jpg")
    i.set_defaults(func=cmd_import)
    d = sub.add_parser("draft", help="write an .eml report")
    d.add_argument("body", help="plain-text body file with {{host:IP}} placeholders")
    d.add_argument("--to", required=True)
    d.add_argument("--subject", required=True)
    d.add_argument("--from", dest="sender")
    d.add_argument("--allow-doubtful", action="store_true")
    d.set_defaults(func=cmd_draft)
    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
