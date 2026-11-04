---
name: shodan-cert-report
description: Find exposed industrial control systems, HMIs and already-compromised services in one country on Shodan through the user's logged-in Shodan tab in the browser (no API key, no query credits), weed out honeypots, judge severity, and draft reports to the national CERT (CERT-SE, cert@cert.se, for Sweden) with Shodan's screenshots embedded - passive only, never touching the hosts, never sending. Also checks whether the user's own connection is on Shodan. Use this whenever the user mentions Shodan, CERT-SE or another national CERT, exposed PLCs/SCADA/HMI/VNC, critical infrastructure on the internet, "kolla shodan", "sök fler på shodan", "rapportera till cert", "är det här riktiga findings", "syns min server/mitt hem på shodan", or wants a follow-up on a CERT ticket.
---

# Shodan to a national CERT

Find control systems and other urgent exposures in one country on Shodan, sort out the honeypots, and write a report the national CERT can act on. The examples use Sweden (`country:SE`, CERT-SE); swap the country code and the CERT for another country.

## Hard rules

- **Passive only.** Read Shodan's own pages and nothing else. Never connect to, ping, scan, open the web page of, or log in to any host found, not even "just to check": not with curl, not in the browser, not through a hostname link on a Shodan page (that link is the host). Passive reading of a search engine is research; touching an unprotected control system can be unauthorised access in most countries (in Sweden, BrB 4 kap. 9 c §).
- **No API key.** Searches run in the user's logged-in Shodan tab, which uses the website's allowance instead of API query credits. Do not ask for or look for a Shodan API key.
- Every report says the sender has not connected to or tested the systems and cannot confirm more than Shodan shows.
- **Draft, never send.** The script writes an `.eml` file. The user reads it and sends it.
- Do not compile who owns a private host (names in a KNX "Friendly Name", villa names). Report the IP, operator and what it is; the CERT and the operator find the subscriber.
- Findings never go in a repository or a public post. The script keeps them under `~/.local/state/shodan-cert-report/` (or `$SHODAN_CERT_OUT`).
- Go at a human pace: the scripts wait about a second between pages, and a session is a few dozen queries, not thousands.

## Check your own connection first

```sh
python3 scripts/shodan_cert.py self                 # current public IP against Shodan's free InternetDB
python3 scripts/shodan_cert.py self --allow 443     # ports you expect open do not count
python3 scripts/shodan_cert.py self --json          # one line, for Home Assistant or scripts
```

It asks api.ipify.org for the public IP (or takes `--ip`) and looks it up in `internetdb.shodan.io`, which needs no account. Exit code 0: nothing unexpected; 1: open ports outside `--allow` or known vulnerabilities; 2: error. Run it from cron, a Home Assistant `command_line` sensor or anything that can alert on an exit code. For mail without running anything, add the IP in Shodan Monitor (monitor.shodan.io); a home IP that changes must be updated there.

## Reaching Shodan through the browser

The user must be logged in to shodan.io in the browser. A free account sees little; the one-time Membership unlocks filters such as `country:`, `port:` and `has_screenshot:` on the website. `tag:` and `vuln:` need higher plans.

The two page scripts do the reading: `scripts/shodan-batch.js` runs a list of searches, `scripts/shodan-hostcheck.js` reads the host page of each IP. Both start in the background and are polled, because browser tools time out on calls longer than about 25 seconds. How to run them depends on the agent:

| Agent | How |
|---|---|
| Claude Code with Claude in Chrome | Open a shodan.io tab in the user's Chrome. Paste a script's text into the JavaScript tool, then call `window.__run([...])` and poll `window.__done && JSON.stringify(window.__res)` in later calls with a wait under 25 s. If the extension drops ("Browser extension is not connected"), ask the user to reconnect it; after a reconnect, open a new tab. Navigating the tab mid-run aborts the script. The JavaScript tool cuts its output at about 1,000 characters and blanks output that looks like cookies or query strings, so for a full batch save `window.__res` as a file through a Blob link with `download` set, then read it from the download folder with a shell. Download that JSON before running `__check(…, true)`: after a burst of screenshot downloads Chrome silently blocks further automatic downloads from the tab. |
| Any agent with a shell on macOS (Codex, Gemini CLI, Claude Code without Chrome) | `scripts/browser_js.sh safari FILE-or-CODE` (or `chrome`) runs JavaScript in the front tab and prints the result. The user must open shodan.io as the front tab and allow it once: Safari > Settings > Advanced > "Show features for web developers", then Develop > "Allow JavaScript from Apple Events"; Chrome: View > Developer > "Allow JavaScript from Apple Events". Tell the user in plain words that while this is on, any app allowed to automate the browser can run code in every logged-in tab, and that they should turn it off afterwards. |
| Agents with computer use only | Open `https://www.shodan.io/search?query=<urlencoded>` and `https://www.shodan.io/host/<IP>` in the user's browser and read the pages: total results, each result's IP, operator, city, product, tags, and on the host page the Tags, open ports, hostnames and last-seen date. Save VNC screenshots with the browser's "Save image as" into the download folder as `shodan-<IP>-<n>.jpg`. Write what you read as the same JSON `shodan-hostcheck.js` produces (see its header) and import it. |

```sh
B=scripts/browser_js.sh
$B safari scripts/shodan-batch.js
$B safari 'window.__run(["country:SE port:20256 unitronics", "country:SE \"3S-Smart\""]); "started"'
$B safari 'window.__done && JSON.stringify(window.__res)'      # repeat until it is not "false"
$B safari scripts/shodan-hostcheck.js
$B safari 'window.__check(["192.0.2.10", "192.0.2.11"], true); "started"'   # true: download screenshots
$B safari 'window.__hpdone && JSON.stringify(window.__hp)' > hp.json
python3 scripts/shodan_cert.py import hp.json                 # moves shodan-<ip>-<n>.jpg from ~/Downloads
```

The first run of the screenshot download may make the browser ask whether shodan.io may download several files; the user allows it.

## Queries worth running

Raw port counts are useless: hosts that answer on every port and cloud ranges inflate `country:SE port:102` into the thousands. Always add a product or banner string.

| Query | What | What it usually turns out to be |
|---|---|---|
| `country:SE port:5900 "authentication disabled" has_screenshot:true` | VNC with no password, with Shodan's screenshot | Heating and heat-pump panels, boiler HMIs. The most urgent class: anyone can operate the screen |
| `country:SE port:20256 unitronics` | Unitronics PCOM, the vector in the 2023 attacks on US water utilities (CISA AA23-335A) | A handful of real ones |
| `country:SE port:2404 asdu` | IEC 60870-5-104 that answers (power and utility telecontrol) | Mostly honeypots, now and then a real one behind a 4G router |
| `country:SE port:102 "PLC name"` | Siemens S7-300/400 | A few real ones |
| `country:SE "3S-Smart"` | CODESYS v2 runtimes, no authentication | Several |
| `country:SE port:4800 moxa` | Moxa NPort serial servers; look for "Authentication disabled" | A few with auth off |
| `country:SE port:44818 "Product name"` | EtherNet/IP (Rockwell, Omron, OPTO 22) | Several |
| `country:SE port:1962 pcworx` | Phoenix Contact PLCs | Mostly honeypots |
| `country:SE port:47808 "Instance ID"`, `port:1911,4911 fox`, `port:502 "Device Identification"` | Building automation (BACnet, Niagara, Modbus) | Hundreds; mention as volume only |
| `country:SE port:502 "Phoenix"` | EV-charger controllers | Low to medium |
| `country:SE port:3671` | KNX home automation | Hundreds of homes; privacy, not infrastructure |

Searches that came back empty or all honeypots in Sweden (late 2026): water and sewage words in titles or banners, ABB RTU560, SICAM, PcVue, Citect, iFIX, wind-turbine vendors, Kamstrup, Hirschmann, DNP3, Omron FINS, Red Lion, fuel tank gauges (`"IN-TANK INVENTORY"`).

### Queries that fit on one page

A free or Membership account sees only the first page of results (10 hits), so the best queries narrow a class down to one or a few pages. These gave 4 to 50 hits in Sweden on 2026-11-04, with real finds on page 1:

| Query | Hits | What came up |
|---|---|---|
| `country:SE port:5900 "authentication disabled" has_screenshot:true` | 9 | Heating plants, heat pumps, pellet boilers, an HMI |
| `country:SE "authentication disabled" has_screenshot:true -port:5900` | 48 | VNC on other ports, with screenshot |
| `country:SE port:5901 "authentication disabled"` | 7 | Servers and a heating plant panel |
| `country:SE "authentication disabled" port:5902,5903,5904,5905,5906,5800` | 9 | Mostly the same hosts again; check for new ones |
| `country:SE "authentication disabled" "RFB 003.007"` | 5 | Old embedded VNC servers, often HMIs (Beijer iX, Mitsubishi GOT) |
| `country:SE "authentication disabled" "Server Name: touch_"` | 4 | Pellet-boiler touch panels (`touch_002496…`) |
| `country:SE port:9200 "read_me"` | 5 | Elasticsearch already emptied, tagged `compromised` |
| `country:SE port:445 "Authentication: disabled" backup` | 7 | Home NAS boxes with open SMB |
| `country:SE port:873 "@RSYNCD" backup` | 25 | rsync modules named backup; whether they need a password does not show |
| `country:SE port:2375 "Docker"` | 10 | Docker API, almost all cloud |
| `country:SE port:11211 "STAT pid"` | 33 | Memcached, cloud and honeypots |
| `country:SE http.title:"Kibana"` | 32 | Mostly honeypots and mislabelled devices |

Too broad to read on one page (hundreds or thousands of hits, volume only): `port:10250`, `port:5985`, `port:6443 "kubernetes"`, `port:5938`, `port:1883 "MQTT Connection Code: 0"`, `http.title:"Home Assistant"`, `"Grafana"`, `"Portainer"`, `"Node-RED"`, `"phpMyAdmin"`, `port:631 "CUPS"`, `port:548 "Netatalk"`. Narrow them with a banner string before reading. Empty in Sweden: `http.title:"Apache Guacamole"`, `port:9200 "cluster_name"`, `port:2049 "nfs"`, `"Dashboard [Jenkins]"`, `"read_me"` on 27017 and 5432, `"iX T"`.

Hosting ranges full of fake VNC screens (dozens of ports, many screenshots, joke server names) are traps or honeypots even without the tag; skip them.

### General (non-ICS) exposures

Shodan prints its own tags in results and on host pages even on plans where the `tag:` filter is closed. **`compromised`** is the strongest general signal: an open database that has already been emptied, usually with a `read_me` index or collection holding a ransom note. That class is worth its own short report.

| Query | Worth reporting |
|---|---|
| `country:SE port:9200 "read_me"` (narrow) or `country:SE port:9200 elastic -"security_exception"` (wide) | the ones tagged `compromised` |
| `country:SE port:6379 "redis_version"` | only if compromised and locally run, not cloud |
| `country:SE "MongoDB Server Information"` | rarely |
| `country:SE port:445 "Authentication: disabled" -"IPC$"` | maybe, as volume |
| Anonymous FTP, end-of-life IIS/RDP/OpenSSH, Docker, Jupyter, Jenkins, DICOM | no: intentional, mass, cloud or honeypots |

A national CERT already gets bulk feeds of open services (Shadowserver and the like). A report adds value when the system is compromised, controls something physical, or names an owner they would not find themselves.

## Sorting out honeypots

The search list can lack the honeypot tag that the host page has; one early run nearly reported two PLCs that were tagged honeypot only on their host pages. So:

1. Run the host check on every IP before it goes in a report, and `import` the result. `draft` refuses a host that has not been imported or is tagged honeypot, and refuses other doubts unless `--allow-doubtful` is passed after checking them by hand.
2. Treat as honeypot even without the tag: a host that claims several vendors at once (Phoenix and Rockwell and IEC-104 on one IP; `import` flags three or more industrial ports), and cloud or hosting ranges with default-looking plant names like `Plant_8F1B`.
3. Real ones look like: residential or mobile operators and municipal networks, live dates and plausible values in the screenshot, hostnames that tie to a real organisation.

The host-page parsing reads Shodan's HTML, which Shodan can change. As of November 2026, General Information is `<label>Name</label><div>value</div>` pairs (not a table), tags are `.tag` elements next to number badges that must be filtered out, and small favicons in `.favicon` sit beside the real VNC screenshot. A check on a public host (`/host/1.1.1.1`) should give its operator, city, ASN, ports and tags `pqc`, `vpn`; if `import` shows empty fields for a host whose page clearly has them, look at the page and fix the selectors in `shodan-hostcheck.js`.

## Judging severity

Say plainly what is known and what is not. Order: open HMI with control and no password (VNC) > protocols with no authentication that take commands (IEC-104, Unitronics PCOM, S7, CODESYS v2) > serial servers with auth off > login pages > building automation in bulk. Whether it is critical infrastructure is usually unknown: write "we do not know what it controls", list what it could be, and keep "urgent" out of the subject. One device of unknown purpose is not a crisis; phone the CERT if it must be seen the same day (CERT-SE listed 010-382 80 00 in late 2026; check cert.se for the current number, and cite the ticket).

Location: Shodan's city for mobile operators' addresses is unreliable (one Swedish mobile range shows the same city wherever the device is). Say so in the report.

Reverse DNS, hostnames and the plant or device names in banners often name the owner better than the operator does. Put them in the report; that is exactly what the CERT cannot get from a bulk feed.

## Writing the report

Write the body as plain text in the user's language (Swedish for CERT-SE). `{{host:IP}}` becomes the Shodan host link with that host's screenshots inline under it. A line that is only `**text**` becomes a bold heading. Links are kept only when they point to shodan.io; anything else is left as plain text, so the report never links to an exposed host.

```
Hej!

<En mening: vad, hur det hittades (Shodan), varför det spelar roll.>

Sökning:
https://www.shodan.io/search?query=<urlencoded query>

**<Rubrik per grupp, i fallande allvar>**
- <IP> (<operatör>, <ort eller "plats osäker">): <vad Shodan visar>. Senast sedd <datum>.
  {{host:<IP>}}

Bilderna är Shodans egna skärmdumpar. Jag har bara använt Shodans befintliga data.
Jag har inte anslutit till eller testat något av systemen, så jag kan inte bekräfta
mer än det Shodan visar.

Med vänliga hälsningar
<Namn>
```

```sh
python3 scripts/shodan_cert.py draft body.txt --to cert@cert.se --subject 'Exponerade styrsystem i Sverige'
```

- Send separate reports per class when one class is clearly more urgent (open control panels on their own, the rest as a follow-up).
- **Follow-ups go on the ticket.** The CERT answers with a ticket tag in the subject (CERT-SE: `[CERT-SE #NNNNNN]`). Reply on that thread with the tag in the subject. CERT-SE's normal reply is a ticket number and "we will come back if we have follow-up questions"; that is not a brush-off.
- Correct earlier claims openly in a follow-up when new data changes them (owner, honeypot, location).

Opening the `.eml`: Outlook and Thunderbird open it as an editable draft (`X-Unsent: 1`). In Apple Mail, open it and use Message > Send Again. Gmail's web client cannot import an `.eml`; see below.

### Gmail web compose (only for agents that drive the browser)

When the user wants the draft in Gmail:

- Gmail's Insert photo dialog is a cross-origin picker browser tools cannot reach, and the compose file input only attaches. What works: add a hidden `<input type=file>` to the Gmail page, upload the screenshots from `~/.local/state/shodan-cert-report/shots/` into it, put the caret after the host's link, `insertParagraph`, then dispatch a `ClipboardEvent('paste')` whose `DataTransfer` holds the File. Gmail inlines it as `cid:`.
- A draft made through the Gmail API and then opened in web compose shows links as `https://www.google.com/url?q=…`, and that text would be sent. Fix each `a` to the decoded `q` and drop `data-saferedirecturl`.
- Updating a draft that has inline images through the Gmail API drops the images. Edit those in the compose; Gmail saves only after a real keystroke.

## Files

- `scripts/shodan-batch.js`: page script, `window.__run(queries)` fills `window.__res` with the total and the first page of results per query.
- `scripts/shodan-hostcheck.js`: page script, `window.__check(ips, download)` fills `window.__hp` with honeypot flag, tags, ports, operator, city, hostnames and last seen per host, and optionally downloads the screenshots.
- `scripts/browser_js.sh`: runs a page script or expression in Safari's or Chrome's front tab on macOS.
- `scripts/shodan_cert.py`: `self`, `import`, `draft`. Keeps host checks in `hosts/`, screenshots in `shots/` and drafts in `drafts/` under the output folder.
- `tests/test_shodan_cert.py`: offline tests, including one that fails if a real IP lands in the repository.
