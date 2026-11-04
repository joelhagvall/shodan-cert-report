#!/bin/sh
# Run JavaScript in the front tab of Safari or Google Chrome on macOS and print the result.
# For agents without a browser tool of their own (Codex, Gemini CLI): the tab must be the user's logged-in
# https://www.shodan.io tab, and the browser must allow it once:
#   Safari: Settings > Advanced > "Show features for web developers", then Develop > "Allow JavaScript from Apple Events"
#   Chrome: View > Developer > "Allow JavaScript from Apple Events"
# Turn the setting off again afterwards: while it is on, any app allowed to automate the browser can run code in
# every logged-in tab.
#
#   scripts/browser_js.sh safari scripts/shodan-batch.js          # load a script file
#   scripts/browser_js.sh safari 'window.__run(["country:SE port:20256 unitronics"]); "started"'
#   scripts/browser_js.sh safari 'window.__done && JSON.stringify(window.__res)'
#
# The value of the last expression is printed; return strings (JSON.stringify), not objects or promises.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 safari|chrome FILE-or-CODE" >&2; exit 2; }
browser=$1
if [ -f "$2" ]; then code=$(cat "$2"); else code=$2; fi
case $browser in
  safari) osascript -e 'on run argv' \
            -e 'tell application "Safari" to do JavaScript (item 1 of argv) in current tab of front window' \
            -e 'end run' "$code" ;;
  chrome) osascript -e 'on run argv' \
            -e 'tell application "Google Chrome" to execute active tab of front window javascript (item 1 of argv)' \
            -e 'end run' "$code" ;;
  *) echo "browser must be safari or chrome" >&2; exit 2 ;;
esac
