// Run in the user's logged-in https://www.shodan.io tab (Claude in Chrome's JavaScript tool, or browser_js.sh).
// Uses the website, so it costs no API query credits. Starts in the background so the call returns at once;
// poll window.__res / window.__done in a later call with a wait under ~25 s, or the browser tool times out.
//
//   window.__run(['country:SE port:20256 unitronics', 'country:SE "3S-Smart"']);
//   // later:
//   window.__res.map(x => x.q + ' => ' + x.tot + ' | honeypot on page 1: '
//     + x.res.filter(s => /honeypot/.test(s)).length + '/' + x.res.length).join('\n')
//
// Only reads Shodan's own pages. Never fetch or open a found host.
window.__res = [];
window.__done = false;
window.__run = async (queries, delayMs = 1300) => {
  window.__res = [];
  window.__done = false;
  for (const q of queries) {
    try {
      const html = await (await fetch('/search?query=' + encodeURIComponent(q))).text();
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const main = doc.querySelector('main')?.innerText || '';
      const total = (main.match(/Total Results\s*([\d,]+)/) || [])[1]
        || (main.match(/Error:[\s\S]{0,150}/) || ['0'])[0];
      const res = [...doc.querySelectorAll('.result')]
        .map(r => r.innerText.replace(/\s+/g, ' ').trim().slice(0, 260));
      window.__res.push({ q, tot: total.replace(/\s+/g, ' '), res });
    } catch (e) {
      window.__res.push({ q, tot: 'ERR ' + e, res: [] });
    }
    await new Promise(r => setTimeout(r, delayMs));
  }
  window.__done = true;
};
'ready';
