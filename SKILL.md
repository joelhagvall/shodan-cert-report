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
- **Everything is saved locally, at once.** Every search batch, host check, screenshot and report goes into that folder: `batch/<date>-<label>.json` (save `window.__res` right after each batch, before the tab navigates or the next batch overwrites it), `hosts/` and `shots/` (through `import`), and `drafts/` (also a copy of any report written straight in a mail client or Gmail, as `.eml` or `.txt`). Results that live only in the browser tab are lost on the next navigation.
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
| Any agent with a shell and Chrome (no Apple Events setting needed) | Start a separate Chrome window with its own profile and a debugging port: `open -na "Google Chrome" --args --user-data-dir="$HOME/.local/state/shodan-cert-report/chrome-profile" --remote-debugging-port=9333 --no-first-run https://account.shodan.io/login`. The user logs in there once; the profile keeps the login. Then `node scripts/cdp_eval.mjs FILE-or-CODE` (or `bun`) runs JavaScript in that window's shodan.io tab and prints the result, with no output limit. A headless browser that an agent's own browser tool starts is not logged in and the user cannot see it, so use this window instead. Tell the user that while the window is open, any program on the Mac can control it through the port, and that they should close it when done. |
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

`shodan-batch.js` reports `unique` (distinct IPs on page 1) and `real` (distinct IPs tagged neither honeypot nor cloud) per query; judge a query by `real`, not by Shodan's total: honeypots repeat on page 1 and inflate it. A free or Membership account sees only the first page of results (10 hits), so the best queries narrow a class down to one or a few pages. These gave 1 to 50 hits in Sweden on 2026-11-04, with real finds on page 1:

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
| `country:SE port:161 "public"` | 75 | Advantech ICR industrial 4G routers (pump stations, substations) answering SNMP community `public`, some on 2021 firmware; report as a class |
| `country:SE port:8291 "MikroTik" "6.4"` | 19 | RouterOS 6.40–6.42 with Winbox open; old, volume only |
| `country:SE http.title:"Jupyter Notebook"` | 7 | Login pages (an open notebook has the title "Home Page…", which gave 0) |
| `country:SE http.title:"VMware ESXi"` | 11 | Cloud and honeypots |
| `"Regin" country:SE` | 633 | Regin building controllers (Rego 5200) answering Modbus with no login; too many for one page, report as volume |
| `"Siemens, SIMATIC" country:SE` | 33 | Half honeypots (university ranges); the rest Siemens SCALANCE M industrial 4G routers on mobile operators answering SNMP, same class as the Advantech ICRs |
| `http.title:"HMI" country:SE` | 35 | Login pages on mobile ranges: Siemens SIMATIC HMI web, Kaeser Sigma Air Manager; low |
| `country:SE port:20000 "Source address"` | 8 | DNP3 that answers (`"DNP3"` matches nothing); one real RTU on a mobile operator, the rest cloud and honeypots |
| `country:SE port:4840 "OPC UA"` | 1 | A PLC whose OPC UA node tree (`PLC_1`, maker, serial) is browsable without login; bare `port:4840` is 1,174 empty answers |
| `country:SE "Phoenix Contact"` | 13 | Phoenix Contact CHARX SEC EV-charging controllers with their firmware version (`EV-SEC-1.x`); the same hosts as the open MQTT `loadmanagement` brokers. Best query for this class |
| `country:SE port:1883 "loadmanagement"` | 9 | EV-charging load management on an open MQTT broker (topics for fuses, max current, `ocpp16`); `"ocpp16"` gives 7 of the same |
| `country:SE "OCPP"` | 17 | The charging finds above mixed with cloud noise |
| `country:SE "Beckhoff"` | 26 | Beckhoff CX controllers answering Windows CE Remote Display (remote screen, no login); device IDs name property automation stations; treat like open VNC without a screenshot |
| `country:SE "Westermo"` | 38 | Westermo MRD-455 industrial 4G routers with a telnet login prompt, all on one mobile operator's M2M range |
| `country:SE "Tridium"` | 4 | Niagara 4 building automation |
| `country:SE "Mitsubishi Electric"` | 2 | Mitsubishi GOT heat-pump panels with open VNC |
| `country:SE "Sauter"` | 5 | SAUTER BACnet automation stations; 4 real hosts |
| `country:SE "Distech Controls"` | 4 | Distech BACnet building controllers |
| `country:SE "SAIA PCD"` | 127 | Nine of ten on page 1 are honeypots; one real Saia PCD web server |
| `country:SE "Ewon"` | 85 | Almost all honeypots; one real Ewon remote-access router on a mobile range |
| `country:SE port:30718 "Lantronix" "Password:" -"secured"` | 31 | Lantronix serial servers whose discovery answer shows the configured password in clear text instead of "Password secured"; some look like access-control gateways. Serious: report as a class. `-"Password secured"` gives 0, so negate the single word |
| `country:SE "AirLink"` | 3 | Sierra Wireless AirLink "AT Command Interpreter" on a mobile operator, one without a password prompt |
| `country:SE "ALEOS"` | 16 | Sierra Wireless RV50, ES450 and GX450 industrial 4G routers with a telnet login prompt, on mobile operators |
| `country:SE http.title:"ACEmanager" org:"Mobile Services"` | 4 | Sierra Wireless web admin on one mobile range; the bare title gives 159 |
| `country:SE "RUTX"` | 12 | Teltonika RUTX routers answering SNMP or telnet with model and kernel date |
| `country:SE http.title:"EBLWeb"` | 19 | Web interfaces of EBL fire-alarm panels |
| `country:SE http.title:"Web512II"` | 1 | Panasonic fire-alarm panel web on a mobile operator |
| `country:SE "SPC4300"` | 5 | Vanderbilt SPC intrusion-alarm panels with a telnet login prompt on broadband |
| `country:SE port:502 "Slave ID Data: Abelko 0.0.2" org:"Mobile Services"` | 5 | Abelko building and district-heating controllers answering Modbus with no login on a mobile range; all of `"Abelko"` is 77 |
| `country:SE port:502 "NIBE"` | 6 | NIBE heat pumps (some with Regin units) answering Modbus Device Identification |
| `country:SE "Boa/0.93.15" "NIBE"` | 6 | NIBE heat-pump web logins (401) |
| `country:SE "Server: Corrigo Webserver" port:80` | 15 | Regin Corrigo ventilation controllers, firmware dated 2012–2015; narrower than `"Regin"` |
| `country:SE "Server: C6"` | 11 | Komfovent C6 air-handling unit web |
| `country:SE "Server: C5"` | 43 | Komfovent C5 units and a Kockumation tank-gauging unit |
| `country:SE "Server: Anti-Web V3.0.7-hms2"` | 15 | Alliance AWU 600 units; `"Server: Anti-Web"` (39) adds Netbiter and AWU 500 |
| `country:SE http.title:"Netbiter"` | 7 | HMS and Ewon Netbiter remote-monitoring gateways, several on mobile static addresses |
| `country:SE port:47808 "Object Name: GOLD"` | 3 | Swegon GOLD air handlers on BACnet (`port:47808 "Swegon"` gives the same 3) |
| `country:SE "Systemair"` | 3 | Systemair controllers (Regin inside) on BACnet |
| `country:SE port:47808 "PXG3"` | 7 | Siemens Desigo PXG3 BACnet routers, with plant-room names in Location |
| `country:SE "IV Produkt"` | 1 | IV Produkt air handler (Climatix POL908) on BACnet |
| `country:SE port:47808 "Automated Logic"` | 1 | Automated Logic BACnet controller on a mobile range |
| `country:SE port:771 "Digi"` | 1 | Digi RealPort serial server |
| `country:SE "Server: Climatix" org:"Mobile Services"` | 3 | Siemens Climatix web logins on a mobile range; `port:8080 "Server: Climatix"` gives 31 |
| `country:SE "Elvaco" port:8080` | 12 | Elvaco CMe metering gateways (heat and water meters), several on mobile; `port:80 http.title:"Elvaco" org:"Ownit Broadband AB"` gives 11 |
| `country:SE "CR1000"` | 19 | Campbell CR1000 data loggers (weather, hydrology), most with the home page open |
| `country:SE http.title:"Sunny WebBox"` | 3 | SMA solar-plant loggers |
| `country:SE http.title:"Solar-Log"` | 48 | Solar-Log plant loggers (`Server: IPC@CHIP`), homes and businesses |
| `country:SE http.title:"Fronius Argeno"` | 2 | Fronius Argeno; `port:8080 http.title:"Fronius"` gives 2, the plain Fronius title 69 |
| `country:SE "KeContact"` | 3 | KEBA P30 wallboxes over mDNS with serial number; privacy, not infrastructure |

The queries from `"Lantronix"` down came from a council of three models on 2026-11-04 (215 tested, 66 fit on one page). What worked: banner strings copied exactly from real results (`Server: …`, BACnet `Object Name:`, Modbus `Slave ID Data:`), and splitting a big class with `org:"<operator>"`. What failed: plain brand words, solar and charging app brands, vendor names copied from BACnet PICS documents, and hostname words in free text (`"mobileonline"` matches nothing).

A second council round on 2026-11-04 (127 more tested, 43 fit a page) looked for critical infrastructure. These are the critical-infrastructure finds, most urgent first:

| Query | Hits | What came up |
|---|---|---|
| `country:SE port:502 "Slave ID Data:" "DPR_"` | 43 | District-heating substations answering Modbus with no login. The slave-ID string names each one: `UC VS/VV`, `E-VS1/VV1`, `VKA1/ UC`, `Undercentral` (UC = undercentral, VS = värmesystem, VV = varmvatten), with a date. On broadband and Telia mobile. `"Undercentral"` or `port:502 "Slave ID Data: ! Undercentral"` give 5 of the same |
| `country:SE "MRD-455"` | 31 | Westermo MRD-455 4G routers with a telnet login prompt (same class as `"Westermo"`, narrower); `"Westermo" port:23` gives 24 |
| `country:SE "SIMATIC NET"` | 5 | Siemens SCALANCE M876/MUM industrial 4G routers announcing model and firmware over SNMP, on mobile operators; `"SCALANCE"` gives the same 5 and `"SCALANCE M876"` gives 3. Narrower and cleaner than `"Siemens, SIMATIC"` (33) |
| `country:SE port:161 "ICR-" "(2023-"` | 34 | Advantech ICR 4G routers split by firmware year; `"(2021-"` and `"(2022-"` give 15 each — a way to surface the oldest firmware. The whole class (`port:161 "ICR-"`) is 160 |
| `country:SE port:30718 "Lantronix" "Type: X50" "Password:" -"secured"` | 20 | Lantronix X50 serial servers showing the password in the banner; `"Type: X90" "Password:" -"secured"` gives 4. `port:30718 "Lantronix" org:"Tele2 Sverige AB"` (59) maps the class, mostly `Password secured` |
| `country:SE port:502 "Slave ID Data: Abelko" org:"Telia Network Services"` | 18 | Abelko controllers (building and district heating) on Modbus, split to one page by operator; all of `"Abelko"` is 77 |
| `country:SE port:502 "Device Identification: AB Regin" org:"Ownit Broadband AB"` | 6 | Regin controllers on Modbus, sliced from 498 to one page with `org:` |
| `country:SE "SPC4300" "Login:"` | 5 | Vanderbilt SPC intrusion-alarm panels with a telnet login |
| `country:SE "CR1000" "401"` | 5 | Campbell CR1000 data loggers whose web asks for a password (hydrology, weather) |
| `country:SE "TBox" ` | 3 | Ovarro TBox RTUs (water and utility telemetry) |
| `country:SE port:47808 "PXG3" "Location:"` | 3 | Siemens Desigo PXG3 BACnet routers with plant-room names |
| `country:SE http.title:"Sulzer"` | 2 | Sulzer pump-monitoring portal (hosted, not a device) |
| `country:SE http.title:"SWARCO"` | 1 | SWARCO traffic-control portal (hosted) |

Lesson from this round: `org:"<operator>"` and `city:"<city>"` are the strongest way to cut a big class down to one page. Swedish words only match where the operator put them in a Modbus slave-ID (`"Undercentral"`, `"DPR_"`), not in HTTP titles. Empty in Sweden despite trying: electrical protection relays and grid RTUs (`"SIPROTEC"`, `"MiCOM"`, `"RTU500"`, `"Relion"`, `ssl:"SEL-3530"`, `"Easergy"`, `"Cepi"`), smart-meter head-ends (`"Aidon"`), Swedish words in titles or SNMP names (`http.title:"Pumpstation"`, `"Vattenverk"`, `"Reningsverk"`, `"Ställverk"`, `"Värmeverk"`, `"Kraftverk"`, `"Fjärravläsning"`), `"Sitraffic"`, `"TLS-450"`, `"viewLinc"`, `"testo Saveris"`, `"OnCell"`, `http.title:"FusionSolar"`, `"TopSit"`, `"Cargotec"`, `"Gallagher"`.

Too broad to read on one page (hundreds or thousands of hits, volume only): `port:10250`, `port:5985`, `port:6443 "kubernetes"`, `port:5938`, `port:1883 "MQTT Connection Code: 0"`, `http.title:"Home Assistant"`, `"Grafana"`, `"Portainer"`, `"Node-RED"`, `"phpMyAdmin"`, `port:631 "CUPS"`, `port:548 "Netatalk"`, `port:5060 "SIP/2.0"`, `http.title:"RabbitMQ Management"`, `http.title:"Proxmox"` (login pages), `"MiniServ"` (Webmin), `port:7547`, `"Climatix"` (667), `port:502 "Device Identification: AB Regin"` (498), `"GOLD authentication"` (466, Swegon web logins), `"Thermia"` (450, heat pumps over mDNS), `port:30718 "Lantronix"` (366), `"Elvaco"` (233), `"Swegon"` (123), `port:47808 "Vendor Name: AB Regin"` (115), `http.title:"Alliance - AWU"` (96), `port:47808 "Vendor Name: Siemens"` (94), `port:47808 "HvacFnct"` (71), `"Checkwatt"` (52, home-battery gateways over mDNS). Narrow them with a banner string before reading. Empty in Sweden: `http.title:"Apache Guacamole"`, `port:9200 "cluster_name"`, `port:2049 "nfs"`, `"Dashboard [Jenkins]"`, `"read_me"` on 27017 and 5432, `"iX T"`. Banner strings that match nothing on Shodan: `"Webmin"` (use `"MiniServ"`), `"TR-069"`, `"sysDescr"` (SNMP shows `Description:`).

Shodan has no `OR`: a query with it fails with "Invalid search query". Run each term on its own; ports take a comma list (`port:502,102`). `org:"<company>"` (Vattenfall, Fortum, Swedavia, Trafikverket) shows only the company's own edge (Citrix, Check Point, IIS logins), not its plants, which usually sit behind mobile operators. Also empty in Sweden: `"Nordex Control"`, `port:2404 "IEC"`, `port:102 "S7"`, `port:502 product:modbus`, `"Server: CarelDataServer"`, `"mikrotik" streetlight`, `"IEC 61850"`, `port:102 "MMS"`, `"OpenADR"`, `"Sparkplug"`, `port:1883 "spBv1.0"`, `"DLMS"`, `port:4059`, `"Building Management"`, `"ocpp1.6"`, `"B&R Automation"`, `"Danfoss"`, `"Trend Controls"`, `"HMS Networks"`, `"Siemens Desigo"`, `"Delta Controls"`, `"Hilscher"`, `"ProSoft"`, `"ICP DAS"`, `"Red Lion Controls"`, `"Yokogawa"`, `"Emerson"`, `"Endress+Hauser"`, `"Johnson Controls"`, `"Kieback&Peter"`, `"Belimo"`, `"Bosch Rexroth"`, `"GE Vernova"`, `"LOYTEC"`, `"IOLAN"`, `"INSYS"`, `"Smartpack"`, `"Power Xpert"`, `http.title:"PIKO"`, `"WEB'log"`, `http.title:"SmartLogger"`, `"Contemporary Controls"`, `"Reliable Controls"`, `"Robustel"`, `"InRouter"`, `"MultiConnect"`, `http.title:"Pro-face"`, `"ControlByWeb"`, `"CC612"`, `"Q.station"`, `"Web-IO"`, `"Quido"`, `"Z-GPRS3"`, `"Ferroamp"`, `"Zaptec"`, `"Growatt"`, `"GoodWe"`, `"SUN2000"`, `"Kostal"`, `"Carlo Gavazzi"`, `"Ngenic"`, `"EXOline"`, `"EXOcompact"`, `"Grundfos"`, `"AquaCom"`, `"Viola Systems"`, `"Conel"`, `"Anybus"`, `"2N" "Helios"`, `"TAC Vista"`, `port:47808 "Vendor Name: TAC"`, `"CTC EcoLogic"`, `"Produal Oy"`, `"OJ Electronics A/S"`, `"Priva"`, `"DEOS AG"`, `"Cylon Controls"`, `"Trend Control Systems"`, `"Novelan GmbH"`, `"Janitza"`, `"SOCOMEC"`, `http.title:"ECL Comfort"`, `http.title:"TROVIS"`, `http.title:"AK-SM"`, `http.title:"Weintek"`, `"Adcon Telemetry"`, `"HydroControl"`, `"Mitec"`, `"Consilium"`, `"Vigilon"`, `"SPC5"`, `"dormakaba"`, `"Integriti"`, `"Inner Range"`, `"Bewator"`, `"WebMaster Pro"`, `"UltraBase"`, `"Panasonic Fire"`, `"Server: C4"`, `"CX9020"`, `port:161 "ICR-2400"`; `"Advantech"` finds only an MQTT broker (the routers show up with `port:161 "public"`). Volume or noise: `"Schneider Electric"` (145, half cloud honeypots), `"Teltonika"` (113), `"WAGO"` (68, mostly honeypots), `"Loxone"` (294, cloud hosts all named "some name"), `"Honeywell"` (video recorders and printers), `"ABB"` (home automation and KNX logins), `"Carel"` (unrelated names), `"Easee"`, `"GARO"`, `"Victron"`, `"Flygt"`, `"NetModule"`, `"Esmi"`, `"IMSE"`, `"Securitas"`, `"Beijer"` (unrelated hosts), `"ioLogik"` (74, one real), `http.title:"OUMAN"` (one real EH-800, the rest the vendor's cloud), `"Boa/0.94"` (7,039).

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

Say plainly what is known and what is not. Order: open HMI with control and no password (VNC) > protocols with no authentication that take commands (IEC-104, Unitronics PCOM, S7, CODESYS v2) > serial servers with auth off or a password shown in the banner > login pages > building automation in bulk. Whether it is critical infrastructure is usually unknown: write "we do not know what it controls", list what it could be, and keep "urgent" out of the subject. One device of unknown purpose is not a crisis; phone the CERT if it must be seen the same day (CERT-SE listed 010-382 80 00 in late 2026; check cert.se for the current number, and cite the ticket).

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
- `scripts/cdp_eval.mjs`: runs a page script or expression in the shodan.io tab of a Chrome window started with `--remote-debugging-port` (node 22+ or bun).
- `scripts/shodan_cert.py`: `self`, `import`, `draft`. Keeps host checks in `hosts/`, screenshots in `shots/` and drafts in `drafts/` under the output folder; search batches go in `batch/` beside them.
- `tests/test_shodan_cert.py`: offline tests, including two that fail if a real IP or an unknown hostname lands in the repository.
- `.githooks/pre-commit`: runs the tests before every commit (`git config core.hooksPath .githooks` once per clone).
