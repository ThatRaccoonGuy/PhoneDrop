'use strict';

// Shown to a device that scanned the QR but hasn't been approved on the computer yet.
// Polls its own status; the server answers 404 once the request is denied or has expired.

const $ = (s) => document.querySelector(s);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function denied() {
  $('#pendingTitle').textContent = 'Request was denied';
  $('#pendingHint').textContent = 'Scan the QR again.';
}

async function poll() {
  for (;;) {
    try {
      const r = await fetch('/api/pair-status', { credentials: 'same-origin', cache: 'no-store' });
      if (r.status === 404 || r.status === 401) return denied();
      if (r.ok) {
        const d = await r.json();
        if (d.name) $('#pendingName').textContent = d.name;
        if (d.status === 'active') return location.replace('/');
      }
    } catch {} // network hiccup: keep trying
    await sleep(2000);
  }
}

poll();
