# Shodan → CERT: report exposed control systems with your AI agent

An agent skill for reporting exposed control systems to your national CERT. Your agent searches Shodan in your own logged-in browser tab, weeds out honeypots, judges severity, and writes a draft email with Shodan's own screenshots inline. You read the draft and send it.

It is passive: it reads Shodan and nothing else, and never connects to a host it finds. It needs no Shodan API key and spends no query credits.

Built for Sweden and CERT-SE, but the country code and the recipient are the only Swedish parts.

## Check yourself first

```sh
python3 scripts/shodan_cert.py self
```

It looks up your current public IP in Shodan's free InternetDB (no account needed). Exit code 1 means Shodan lists open ports or known vulnerabilities on your connection, so it can drive an alert from cron or Home Assistant. `--allow 443` ignores ports you expect to be open, and `--json` prints one line for scripts. If you want mail when something changes, add your IP in [Shodan Monitor](https://monitor.shodan.io).

## Why

Heating panels with no password, PLCs that take commands from anyone, databases that have already been emptied: Shodan indexes all of it, and plenty of it sits on ordinary home and business connections. National CERTs get bulk feeds of open ports. What they get less of is someone who has looked at a host, ruled out a honeypot, and can say what it seems to control. That review is what this skill does, and a subscription that never reaches its limit can do it on a quiet evening.

## How it works

1. The agent runs a list of searches in your logged-in shodan.io tab (`scripts/shodan-batch.js`).
2. For every IP worth reporting it reads Shodan's host page (`scripts/shodan-hostcheck.js`): honeypot tag, ports, operator, hostnames, last seen, and the VNC screenshot.
3. `shodan_cert.py import` stores that and flags doubts: honeypot tags, many industrial protocols on one IP, cloud ranges.
4. `shodan_cert.py draft` writes an `.eml` with the screenshots inline. It refuses hosts tagged as honeypots or never checked.

[SKILL.md](SKILL.md) has the rules the agent follows, the queries that have found real things, how to sort out honeypots, and how to judge severity.

## Install

It works in any agent that reads `SKILL.md` and can run a shell. The browser part works four ways:

- **Claude Code** with the Claude in Chrome extension.
- **Codex, Gemini CLI or others on macOS** through `scripts/browser_js.sh`, which runs the page scripts in Safari's or Chrome's front tab via AppleScript. It needs "Allow JavaScript from Apple Events" switched on in the browser. Turn it off afterwards, because while it is on, any app allowed to automate the browser can run code in your logged-in tabs.
- **Any agent with a shell and Chrome** through `scripts/cdp_eval.mjs`, which runs the page scripts in a separate Chrome window started with its own profile and `--remote-debugging-port`. You log in to Shodan in that window once. Close it when you are done, because while it is open any program on your computer can control it through the port.
- **Agents with computer use** read the Shodan pages directly.

```sh
git clone https://github.com/joelhagvall/shodan-cert-report ~/.claude/skills/shodan-cert-report   # Claude Code
git clone https://github.com/joelhagvall/shodan-cert-report ~/.codex/skills/shodan-cert-report    # Codex
```

Then ask your agent something like "kolla shodan efter öppna VNC-paneler i Sverige och skriv ett utkast till CERT-SE".

Requirements: Python 3.9+ (standard library only) and a Shodan account logged in in your browser. The one-time Membership unlocks the filters the queries use.

```sh
python3 -m unittest discover -s tests     # offline
git config core.hooksPath .githooks       # once per clone: commits run the tests first
```

## Rules

- Never connect to, scan or log in to a host you found. In most countries that can be unauthorised access, and it adds nothing the CERT needs.
- A person reads and sends every report. Nothing is sent automatically.
- Findings stay on your machine (`~/.local/state/shodan-cert-report/`), never in a repository or a public post.
- Don't flood the CERT. Check whether a host has already been reported, and report what bulk feeds miss: systems that control something physical, systems already compromised, and owners you can name.

## License

MIT
