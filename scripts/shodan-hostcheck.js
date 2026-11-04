// Run in the user's logged-in https://www.shodan.io tab (Claude in Chrome's JavaScript tool, or browser_js.sh).
// Reads Shodan's host page for each IP (never the host itself): the search list can lack the honeypot tag
// that the host page carries. With download=true it also saves each VNC screenshot Shodan shows as
// shodan-<ip>-<n>.jpg in the browser's download folder.
//
//   window.__check(['192.0.2.10', '192.0.2.11'], true);
//   // later, polling with a wait under ~25 s:
//   window.__hpdone && JSON.stringify(window.__hp)
//
// Save that JSON to a file and run: python3 scripts/shodan_cert.py import FILE
window.__hp = {};
window.__hpdone = false;
window.__check = async (ips, download = false, delayMs = 1200) => {
  window.__hp = {};
  window.__hpdone = false;
  for (const ip of ips) {
    try {
      const html = await (await fetch('/host/' + ip)).text();
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const text = doc.body.textContent.replace(/\s+/g, ' ');
      if (/No information available/i.test(text)) {
        window.__hp[ip] = { err: 'not in Shodan' };
        continue;
      }
      // General Information is <label>Name</label><div>value</div>: Hostnames, Domains, Country, City,
      // Organization, ISP, ASN. Several values (hostnames, domains) are one link each.
      const rows = {};
      for (const label of doc.querySelectorAll('label')) {
        const box = label.nextElementSibling;
        if (!box) continue;
        const links = [...box.querySelectorAll('a')].map(a => a.textContent.trim()).filter(Boolean);
        rows[label.textContent.trim()] = links.length > 1 ? links.join(' ') : box.textContent.replace(/\s+/g, ' ').trim();
      }
      const tagLinks = [...doc.querySelectorAll('a[href*="tag%3A"], a[href*="tag:"], .tag')]
        .map(a => a.textContent.trim()).filter(t => /^[a-z][a-z0-9-]*$/i.test(t));  // .tag also holds counts
      const tagLine = (text.match(/Tags:\s*(.{0,120})/) || [])[1] || '';
      const tags = [...new Set([...tagLinks, ...(tagLine.match(/\b[a-z][a-z-]{2,}\b/g) || [])
        .filter(t => /^(honeypot|compromised|ics|cloud|vpn|database|self-signed|eol-product|eol-os|starttls|medical|iot|scanner|tor|proxy|videogame|cdn|c2|malware|doublepulsar)$/.test(t))])];
      const ports = [...new Set([...text.matchAll(/\b(\d{1,5})\s*\/\s*(?:tcp|udp)\b/gi)].map(m => +m[1]))]
        .filter(p => p > 0 && p < 65536).sort((a, b) => a - b);
      const lastSeen = (text.match(/Last Seen:?\s*(\d{4}-\d{2}-\d{2})/i) || [])[1] || '';
      // Per-service collection timestamps on the host page (one per open port). The earliest is the closest
      // free proxy for how long the host has been exposed; true "first seen" needs the paywalled /history
      // timeline (Membership for historical data), so it is not available here and is reported as ''.
      const seen = [...new Set((html.match(/\b20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\b/g) || []).map(s => s.slice(0, 10)))].sort();
      const seenSince = seen[0] || lastSeen;
      // Screenshots only: skip the small site favicons that sit in .favicon next to HTTP titles.
      const shots = [...doc.querySelectorAll('img[src^="data:image"]')]
        .filter(i => !i.closest('.favicon') && !(+i.getAttribute('width') && +i.getAttribute('width') <= 64))
        .map(i => i.src);
      if (download) {
        shots.forEach((src, n) => {
          const a = document.createElement('a');
          a.href = src;
          a.download = `shodan-${ip}-${n + 1}.${src.startsWith('data:image/png') ? 'png' : 'jpg'}`;
          document.body.appendChild(a);
          a.click();
          a.remove();
        });
      }
      window.__hp[ip] = {
        ip, honeypot: /honeypot/i.test(tags.join(' ') + ' ' + tagLine), tags, ports, lastSeen,
        seenSince, seen, firstSeen: '',  // firstSeen needs the paywalled /history timeline; '' = unavailable
        org: rows['Organization'] || '', isp: rows['ISP'] || '', asn: rows['ASN'] || '',
        city: rows['City'] || '', country: rows['Country'] || '',
        hostnames: (rows['Hostnames'] || '').split(/\s+/).filter(Boolean),
        domains: (rows['Domains'] || '').split(/\s+/).filter(Boolean),
        screenshots: shots.length,
      };
    } catch (e) {
      window.__hp[ip] = { err: String(e) };
    }
    await new Promise(r => setTimeout(r, delayMs));
  }
  window.__hpdone = true;
};
'ready';
