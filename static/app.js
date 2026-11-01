'use strict';

const $ = (s) => document.querySelector(s);
const CSRF = { 'X-PhoneDrop': '1' };
const CONCURRENCY = 2;
const RETRIES = 2;

let info = { maxBytes: Infinity, serverCopy: false, textCopy: false, local: false };
let files = [];
let notes = [];
let selecting = false;
const selected = new Set();
let version = '';
let viewerIndex = -1;

// ---------------------------------------------------------------- utils

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = (n) => encodeURIComponent(n);

function human(n) {
  for (const u of ['B', 'KB', 'MB', 'GB']) {
    if (n < 1024) return `${n < 10 && u !== 'B' ? n.toFixed(1) : Math.round(n)} ${u}`;
    n /= 1024;
  }
  return `${n.toFixed(1)} TB`;
}

function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

let toastTimer;
function toast(msg, bad = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = 'toast'), 2600);
}

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { ...CSRF, ...(opts.headers || {}) }, credentials: 'same-origin' });
  if (r.status === 401) {
    location.reload();
    throw new Error('Not paired');
  }
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(body.error || `${r.status} ${r.statusText}`);
  }
  return r;
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids) e.append(k);
  return e;
}

const isImage = (f) => f.kind === 'image';
const previewable = (f) => isImage(f) && !/heic|tiff/.test(f.type);
const hasThumb = (f) => ['image', 'video', 'pdf'].includes(f.kind);
const ext = (f) => f.name.split('.').pop().toUpperCase();

// ---------------------------------------------------------------- uploads

const pending = [];
let active = 0;

function enqueue(fileList) {
  const list = [...fileList].filter((f) => f.size > 0);
  if (!list.length) return;
  const q = $('#queue');
  q.hidden = false;
  for (const file of list) {
    const bar = el('div', { class: 'bar-fill' });
    const status = el('span', { class: 'muted' }, 'Waiting…');
    const row = el('div', { class: 'qrow' },
      el('div', { class: 'qtop' }, el('span', { class: 'ellipsis' }, file.name || 'image'), status),
      el('div', { class: 'progress' }, bar));
    q.prepend(row);
    if (file.size > info.maxBytes) {
      fail(row, status, `Too large (max ${human(info.maxBytes)})`);
      continue;
    }
    pending.push({ file, row, bar, status });
  }
  pump();
}

function pump() {
  while (active < CONCURRENCY && pending.length) {
    const job = pending.shift();
    active++;
    runJob(job).finally(() => {
      active--;
      pump();
      if (!active && !pending.length) setTimeout(cleanupQueue, 4000);
    });
  }
}

function fail(row, status, msg) {
  row.classList.add('failed');
  status.textContent = msg;
}

async function runJob({ file, row, bar, status }) {
  for (let attempt = 0; ; attempt++) {
    try {
      status.textContent = attempt ? `Retrying (${attempt})…` : '0%';
      const res = await uploadOne(file, (p) => {
        bar.style.width = `${p * 100}%`;
        status.textContent = `${Math.round(p * 100)}%`;
      });
      bar.style.width = '100%';
      status.textContent = `Saved as ${res.name}${res.meta === 'kept' ? ' (metadata kept)' : ''}`;
      row.classList.add('done');
      return;
    } catch (e) {
      if (e.fatal || attempt >= RETRIES) return fail(row, status, e.message);
      await sleep(1000 * (attempt + 1));
    }
  }
}

function uploadOne(file, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open('POST', '/api/upload');
    x.setRequestHeader('X-PhoneDrop', '1');
    x.setRequestHeader('X-Filename', enc(file.name || 'image'));
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    x.onload = () => {
      let body = {};
      try { body = JSON.parse(x.responseText); } catch {}
      if (x.status === 201) return resolve(body);
      if (x.status === 401) location.reload();
      const err = new Error(body.error || `Upload failed (${x.status})`);
      err.fatal = x.status >= 400 && x.status < 500;
      reject(err);
    };
    x.onerror = () => reject(new Error('Network error'));
    x.ontimeout = () => reject(new Error('Timed out'));
    x.send(file);
  });
}

function cleanupQueue() {
  if (active || pending.length) return;
  const q = $('#queue');
  q.querySelectorAll('.qrow.done').forEach((r) => r.remove());
  if (!q.children.length) q.hidden = true;
}

// ---------------------------------------------------------------- gallery

const cards = new Map();

function render(list) {
  files = list;
  const grid = $('#grid');
  const names = new Set(list.map((f) => f.name));
  for (const [name, card] of cards) {
    if (!names.has(name)) { card.remove(); cards.delete(name); }
  }
  list.forEach((f, i) => {
    let card = cards.get(f.name);
    if (!card || card.dataset.url !== f.url || card.dataset.kind !== f.kind) {
      const fresh = makeCard(f);
      card ? card.replaceWith(fresh) : null;
      card = fresh;
      cards.set(f.name, card);
    }
    card.querySelector('.meta-sub').textContent = `${human(f.size)} · ${ago(f.mtime)}`;
    card.classList.toggle('selected', selected.has(f.name));
    updateClip(card, f);
    if (grid.children[i] !== card) grid.insertBefore(card, grid.children[i] || null);
  });
  $('#empty').hidden = list.length > 0;
  $('#count').textContent = list.length ? `(${list.length})` : '';
  $('#zipAll').hidden = !list.length;
  $('#selectToggle').hidden = !list.length;
  for (const n of selected) if (!names.has(n)) selected.delete(n);
  if (selecting && !list.length) setSelecting(false);
  updateSelbar();
  if ($('#viewer').open) {
    const cur = $('#viewerName').textContent;
    const idx = files.findIndex((f) => f.name === cur);
    idx < 0 ? $('#viewer').close() : (viewerIndex = idx);
    if (idx >= 0) {
      applyCopyButton($('#viewerCopy'), files[idx]);
      applyHash(files[idx]);
    }
  }
}

// On this computer, Copy uses a PNG the server prepares in the background. Until it's ready the
// image shows a progress overlay and Copy is disabled, so the clipboard only ever gets the finished image.
function clipState(f) {
  if (!isImage(f)) return null;
  if (!info.serverCopy || !f.clip) return { label: 'Copy', disabled: false };
  switch (f.clip) {
    case 'ready': return { label: 'Copy', disabled: false };
    case 'converting': return { label: `${f.clipPct}%`, disabled: true, busy: true, pct: f.clipPct, text: `Converting ${f.clipPct}%` };
    case 'queued': return { label: 'Waiting…', disabled: true, busy: true, pct: 0, text: 'Waiting to convert…' };
    case 'error': return { label: 'Copy original', disabled: false };
    default: return { label: 'Prepare', disabled: false, title: 'Convert this image so it can be copied' };
  }
}

function applyCopyButton(btn, f) {
  const s = clipState(f);
  btn.hidden = !s;
  if (!s) return s;
  btn.textContent = s.label;
  btn.disabled = s.disabled;
  btn.title = s.title || '';
  return s;
}

function updateClip(card, f) {
  if (!isImage(f)) return;
  const s = applyCopyButton(card.querySelector('.copy-btn'), f);
  const overlay = card.querySelector('.convert');
  overlay.hidden = !s?.busy;
  if (s.busy) {
    overlay.querySelector('i').style.width = `${s.pct}%`;
    overlay.querySelector('.convert-label').textContent = s.text;
  }
}

function makeCard(f) {
  const tile = () => el('div', { class: `noprev ${f.kind}` }, ext(f));
  let thumb = tile();
  if (hasThumb(f)) {
    thumb = el('img', { src: f.thumb, alt: f.name, loading: 'lazy', decoding: 'async' });
    thumb.addEventListener('error', () => {
      if (previewable(f) && thumb.src.indexOf('/f/') < 0) thumb.src = f.url; // no thumbnailer: fall back to original
      else thumb.replaceWith(tile());
    });
  }
  const wrap = el('div', { class: 'thumb-wrap' },
      el('button', { class: 'thumb', 'aria-label': `Open ${f.name}`,
        onclick: () => (selecting ? toggleSelect(f.name) : openViewer(f.name)) }, thumb),
      el('span', { class: 'check' }));
  if (f.kind === 'video') wrap.append(el('span', { class: 'badge' }, '▶ video'));
  if (isImage(f)) {
    wrap.append(el('div', { class: 'convert', hidden: '' },
      el('div', { class: 'convert-bar' }, el('i')),
      el('span', { class: 'convert-label' })));
  }
  const primary = isImage(f)
    ? el('button', { class: 'copy-btn', onclick: () => copyImage(byName(f.name)) }, 'Copy')
    : f.kind === 'file'
      ? el('span', { class: 'copy-btn', hidden: '' })
      : el('a', { class: 'btn open-btn', href: f.url, target: '_blank', rel: 'noopener' }, 'Open');
  const share = el('button', { class: 'share-btn', onclick: () => shareFile(byName(f.name)) }, 'Share');
  const card = el('figure', { class: 'card' },
    wrap,
    el('figcaption', {},
      el('div', { class: 'meta' }, el('span', { class: 'ellipsis' }, f.name), el('span', { class: 'meta-sub muted' })),
      el('div', { class: `row${f.kind === 'file' ? ' two' : ''}` },
        primary, share,
        el('a', { class: 'btn', href: `/f/${enc(f.name)}?dl=1`, download: f.name }, 'Save'),
        el('button', { class: 'danger icon', 'aria-label': 'Delete', onclick: () => remove(byName(f.name)) }, '🗑'))));
  card.dataset.url = f.url;
  card.dataset.kind = f.kind;
  return card;
}

const byName = (n) => files.find((f) => f.name === n);

// ---------------------------------------------------------------- multi-select

function setSelecting(on) {
  selecting = on;
  if (!on) selected.clear();
  document.body.classList.toggle('selecting', on);
  $('#selectToggle').textContent = on ? 'Done' : 'Select';
  for (const [name, card] of cards) card.classList.toggle('selected', selected.has(name));
  updateSelbar();
}

function toggleSelect(name) {
  selected.has(name) ? selected.delete(name) : selected.add(name);
  cards.get(name)?.classList.toggle('selected', selected.has(name));
  updateSelbar();
}

function updateSelbar() {
  const bar = $('#selbar');
  bar.hidden = !selecting;
  if (!selecting) return;
  const n = selected.size;
  $('#selCount').textContent = `${n} selected`;
  $('#selAll').textContent = n === files.length ? 'Select none' : 'Select all';
  $('#selZip').classList.toggle('disabled', !n);
  $('#selDel').disabled = !n;
  $('#selZip').href = n ? '/api/zip?' + [...selected].map((x) => `n=${enc(x)}`).join('&') : '#';
}

async function deleteSelected() {
  const names = [...selected];
  if (!names.length || !confirm(`Delete ${names.length} file${names.length > 1 ? 's' : ''}?`)) return;
  try {
    const r = await (await api('/api/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ names }) })).json();
    toast(`Deleted ${r.deleted}`);
    setSelecting(false);
  } catch (e) { toast(e.message, true); }
}

async function remove(f) {
  if (!f || !confirm(`Delete ${f.name}?`)) return;
  try {
    await api(`/api/files/${enc(f.name)}`, { method: 'DELETE' });
    toast('Deleted');
  } catch (e) { toast(e.message, true); }
}

// ---------------------------------------------------------------- notes (text & links)

const URL_RE = /https?:\/\/[^\s<>"']+/g;
const noteEls = new Map();

// Turn URLs in the text into links. Only http(s) URLs match, so no javascript: links can sneak in.
function linkify(text) {
  const frag = document.createDocumentFragment();
  let last = 0;
  for (const m of text.matchAll(URL_RE)) {
    frag.append(text.slice(last, m.index));
    const url = m[0].replace(/[.,;:!?)]+$/, '');
    frag.append(el('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, url));
    frag.append(m[0].slice(url.length));
    last = m.index + m[0].length;
  }
  frag.append(text.slice(last));
  return frag;
}

const firstUrl = (text) => (text.match(URL_RE) || [null])[0];

function renderNotes(list) {
  notes = list;
  const box = $('#notes');
  const ids = new Set(list.map((n) => n.id));
  for (const [id, row] of noteEls) if (!ids.has(id)) { row.remove(); noteEls.delete(id); }
  list.forEach((n, i) => {
    let row = noteEls.get(n.id);
    if (!row) { row = makeNote(n); noteEls.set(n.id, row); }
    row.querySelector('.note-sub').textContent = ago(n.time);
    if (box.children[i] !== row) box.insertBefore(row, box.children[i] || null);
  });
  $('#notesSection').hidden = !list.length;
  $('#noteCount').textContent = list.length ? `(${list.length})` : '';
}

function makeNote(n) {
  const url = firstUrl(n.text);
  const actions = el('div', { class: 'row' },
    el('button', { onclick: () => copyNote(n) }, 'Copy'));
  if (url) actions.append(el('a', { class: 'btn', href: url, target: '_blank', rel: 'noopener noreferrer' }, 'Open'));
  actions.append(el('button', { class: 'danger icon', 'aria-label': 'Delete', onclick: () => removeNote(n) }, '🗑'));
  return el('div', { class: 'note' },
    el('div', { class: 'note-text' }, linkify(n.text)),
    actions,
    el('span', { class: 'note-sub muted' }));
}

async function sendNote(text) {
  text = (text || '').trim();
  if (!text) return;
  try {
    await api('/api/notes', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
    toast('Sent');
  } catch (e) { toast(e.message, true); }
}

async function copyNote(n) {
  try {
    if (info.textCopy) {
      await api(`/api/notes/${enc(n.id)}/copy`, { method: 'POST' });
    } else {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard not supported in this browser');
      await navigator.clipboard.writeText(n.text);
    }
    toast('Copied to clipboard');
  } catch (e) { toast(`Copy failed: ${e.message}`, true); }
}

async function removeNote(n) {
  try {
    await api(`/api/notes/${enc(n.id)}`, { method: 'DELETE' });
  } catch (e) { toast(e.message, true); }
}

// ---------------------------------------------------------------- share sheet (phones)

// navigator.share with files opens the phone's share sheet, where iOS offers "Save Image" /
// "Save Video" and Android offers the gallery, messaging apps, etc.
const SHARE_CACHE_MAX = 50 * 1024 * 1024;
const shareCache = new Map();

function canShareFiles() {
  return !info.local && typeof navigator.share === 'function' && typeof navigator.canShare === 'function';
}

async function fetchForShare(f) {
  let file = shareCache.get(f.name);
  if (file) return file;
  const blob = await (await fetch(f.url, { credentials: 'same-origin' })).blob();
  file = new File([blob], f.name, { type: f.type === 'application/octet-stream' ? '' : f.type });
  if (f.size <= SHARE_CACHE_MAX) {
    shareCache.set(f.name, file);
    if (shareCache.size > 6) shareCache.delete(shareCache.keys().next().value);
  }
  return file;
}

async function shareFile(f) {
  if (!f) return;
  const cached = shareCache.has(f.name);
  try {
    const file = await fetchForShare(f);
    if (!navigator.canShare({ files: [file] })) throw new Error("This file type can't be shared here");
    await navigator.share({ files: [file], title: f.name });
  } catch (e) {
    if (e.name === 'AbortError') return; // user closed the sheet
    // Safari only allows the share sheet right after a tap; a slow download can use that up.
    if (e.name === 'NotAllowedError' && !cached) return toast('Ready — tap Share again');
    toast(`Share failed: ${e.message}`, true);
  }
}

// ---------------------------------------------------------------- clipboard

async function toPng(blob) {
  if (blob.type === 'image/png') return blob;
  const bmp = await createImageBitmap(blob);
  const c = document.createElement('canvas');
  c.width = bmp.width; c.height = bmp.height;
  c.getContext('2d').drawImage(bmp, 0, 0);
  return new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error('Conversion failed'))), 'image/png'));
}

async function copyImage(f) {
  if (!f) return;
  if (info.serverCopy) {
    try {
      if (f.clip === 'none') {
        await api(`/api/prepare/${enc(f.name)}`, { method: 'POST' });
        return toast('Converting… Copy unlocks when it\'s done');
      }
      const r = await (await api(`/api/copy/${enc(f.name)}`, { method: 'POST' })).json();
      return toast(r.type === 'image/png' ? 'Copied to clipboard' : 'Copied the original (PNG conversion failed)');
    } catch (e) {
      return toast(e.message, true);
    }
  }
  try {
    if (!navigator.clipboard?.write || !window.ClipboardItem) throw new Error('Clipboard not supported in this browser');
    // Passing a promise keeps the user-gesture alive in Safari while the image loads.
    const png = fetch(f.url).then((r) => r.blob()).then(toPng);
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': png })]);
    toast('Copied to clipboard');
  } catch (e) {
    toast(`Copy failed: ${e.message}`, true);
  }
}

// ---------------------------------------------------------------- viewer

function openViewer(name) {
  viewerIndex = files.findIndex((f) => f.name === name);
  if (viewerIndex < 0) return;
  showViewer();
  const d = $('#viewer');
  if (!d.open) d.showModal();
}

function stopMedia() {
  for (const id of ['#viewerVideo', '#viewerAudio']) {
    const m = $(id);
    m.pause(); m.removeAttribute('src'); m.load(); m.hidden = true;
  }
}

function showViewer() {
  const f = files[viewerIndex];
  $('#viewerName').textContent = f.name;
  stopMedia();
  const img = $('#viewerImg'), file = $('#viewerFile');
  img.hidden = true; file.hidden = true;
  if (isImage(f)) {
    img.hidden = false;
    img.src = previewable(f) ? f.url : `${f.thumb}&size=1600`;
  } else if (f.kind === 'video' || f.kind === 'audio') {
    const m = $(f.kind === 'video' ? '#viewerVideo' : '#viewerAudio');
    m.src = f.url; m.hidden = false;
    m.play().catch(() => {});
  } else {
    file.hidden = false;
    file.querySelector('.viewer-ext').textContent = ext(f);
    file.querySelector('.viewer-size').textContent = human(f.size);
  }
  applyCopyButton($('#viewerCopy'), f);
  applyHash(f);
  if (canShareFiles() && f.size <= SHARE_CACHE_MAX) fetchForShare(f).catch(() => {}); // so Share is instant
  const open = $('#viewerOpen');
  open.hidden = isImage(f) || f.kind === 'file';
  open.href = f.url;
  $('#viewerDl').href = `/f/${enc(f.name)}?dl=1`;
  $('#viewerDl').setAttribute('download', f.name);
}

// The server hashes files in the background; until it's done the button says so.
function applyHash(f) {
  const b = $('#viewerHash');
  b.disabled = !f.sha256;
  b.textContent = f.sha256 ? `SHA-256 ${f.sha256.slice(0, 8)}…${f.sha256.slice(-4)}` : 'SHA-256 computing…';
  b.title = f.sha256 ? `${f.sha256}\nClick to copy` : '';
}

async function copyHash(f) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard not supported in this browser');
    await navigator.clipboard.writeText(f.sha256);
    toast('Hash copied');
  } catch (e) { toast(`Copy failed: ${e.message}`, true); }
}

function step(d) {
  if (!files.length) return;
  viewerIndex = (viewerIndex + d + files.length) % files.length;
  showViewer();
}

// ---------------------------------------------------------------- devices (this computer only)

// Like ago(), but keeps counting in days, for "paired 3 days ago".
function agoDays(ts) {
  const d = Math.floor(Math.max(0, Date.now() / 1000 - ts) / 86400);
  return d < 1 ? ago(ts) : `${d} day${d > 1 ? 's' : ''} ago`;
}

async function decide(id, action) {
  try {
    await api(`/api/devices/${enc(id)}/${action}`, { method: 'POST' });
    toast(action === 'approve' ? 'Device allowed' : 'Request denied');
  } catch (e) { toast(e.message, true); }
  if ($('#devices').open) loadDevices();
}

function decideButtons(d) {
  return [el('button', { class: 'primary', onclick: () => decide(d.id, 'approve') }, 'Allow'),
    el('button', { class: 'danger', onclick: () => decide(d.id, 'deny') }, 'Deny')];
}

// A device that scanned the QR shows up here until it is allowed or denied.
function renderPending(list) {
  const box = $('#pairBanner');
  box.replaceChildren(...list.map((d) => el('div', { class: 'pair-row' },
    el('span', { class: 'pair-text' }, `📱 ${d.name} (${d.ip}) wants to pair`),
    el('div', { class: 'pair-actions' }, ...decideButtons(d)))));
  box.hidden = !list.length;
}

async function loadDevices() {
  let list;
  try {
    list = (await (await api('/api/devices')).json()).devices;
  } catch (e) { return toast(e.message, true); }
  $('#deviceList').replaceChildren(...(list.length ? list.map(deviceRow) : [el('p', { class: 'muted' }, 'No devices.')]));
}

function deviceRow(d) {
  const tags = el('span', { class: 'tags' });
  if (d.current) tags.append(el('span', { class: 'tag' }, 'this computer'));
  if (d.status === 'pending') tags.append(el('span', { class: 'tag warn' }, 'waiting for approval'));
  if (d.role === 'guest') tags.append(el('span', { class: 'tag' }, 'guest'));
  const sub = d.status === 'pending' ? `asked ${ago(d.created)}`
    : d.role === 'guest' ? `arrived ${ago(d.created)} · can upload until ${clock(d.expires)}`
    : `paired ${agoDays(d.created)} · last seen ${agoDays(d.last_seen)}`;
  const actions = el('div', { class: 'pair-actions' });
  if (d.status === 'pending') actions.append(...decideButtons(d));
  else actions.append(el('button', { class: 'danger', onclick: () => revoke(d) }, 'Revoke'));
  return el('div', { class: 'device' },
    el('div', { class: 'device-info' },
      el('div', { class: 'device-name' }, el('span', { class: 'ellipsis' }, d.name), tags),
      el('span', { class: 'muted device-sub' }, `${d.ip} · ${sub}`)),
    actions);
}

async function revoke(d) {
  const what = d.current ? 'this computer (you will need to pair this browser again)' : d.name;
  if (!confirm(`Revoke ${what}?`)) return;
  try {
    await api(`/api/devices/${enc(d.id)}`, { method: 'DELETE' });
    if (d.current) return location.reload();
    toast('Revoked');
  } catch (e) { toast(e.message, true); }
  loadDevices();
}

function openDevices() {
  const d = $('#devices');
  if (!d.open) d.showModal();
  loadDevices();
}

// ---------------------------------------------------------------- guest link (this computer only)

const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

function showGuestLink(link) {
  $('#guestLink').hidden = !link;
  $('#guestCreate').textContent = link ? 'New link' : 'Create link';
  if (!link) return;
  const qr = $('#guestQr');
  qr.hidden = !link.qr;
  if (link.qr) qr.src = link.qr; else qr.removeAttribute('src');
  $('#guestUrl').value = link.url;
  $('#guestExpires').textContent = `Works once, until ${clock(link.expires)}.` + (link.qr ? '' : ' (Install qrencode to get a QR code here.)');
}

async function createGuestLink() {
  try {
    showGuestLink(await (await api('/api/guest', { method: 'POST' })).json());
  } catch (e) { toast(e.message, true); }
}

async function revokeGuestLink() {
  try {
    await api('/api/guest', { method: 'DELETE' });
    showGuestLink(null);
    toast('Guest link revoked');
  } catch (e) { toast(e.message, true); }
}

async function copyGuestLink() {
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard not supported in this browser');
    await navigator.clipboard.writeText($('#guestUrl').value);
    toast('Link copied');
  } catch (e) { toast(`Copy failed: ${e.message}`, true); }
}

function setupGuest() {
  const d = $('#guest');
  const btn = $('#guestBtn');
  btn.hidden = false;
  btn.onclick = () => { if (!d.open) d.showModal(); };
  const mins = info.guestMinutes;
  if (mins) {
    $('#guestExplain').textContent = 'Let someone who isn\'t paired send you files. The link is upload-only and works ' +
      `once, within 10 minutes; after they open it they can upload for ${mins} minute${mins > 1 ? 's' : ''}.`;
  }
  $('#guestClose').onclick = () => d.close();
  d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
  $('#guestCreate').onclick = createGuestLink;
  $('#guestCopy').onclick = copyGuestLink;
  $('#guestRevoke').onclick = revokeGuestLink;
  $('#guestUrl').addEventListener('focus', (e) => e.target.select());
}

// ---------------------------------------------------------------- live sync

function setOnline(ok) {
  const s = $('#status');
  s.classList.toggle('on', ok);
  s.title = ok ? 'Connected' : 'Reconnecting…';
}

async function sync() {
  for (;;) {
    try {
      const r = await api(`/api/files?wait=${enc(version)}`);
      const d = await r.json();
      setOnline(true);
      if (d.version !== version) { version = d.version; render(d.files); renderNotes(d.notes || []); }
      if (d.pending) renderPending(d.pending); // only sent to this computer
      if ($('#devices').open) loadDevices();
    } catch (e) {
      setOnline(false);
      await sleep(2500);
    }
  }
}

// ---------------------------------------------------------------- wiring

async function init() {
  sync(); // start loading the gallery right away, in parallel with /api/info
  try {
    info = await (await api('/api/info')).json();
  } catch {}
  if (files.length) render(files); // re-apply now that we know whether this is the computer
  document.body.classList.toggle('can-share', canShareFiles());
  if (info.keepDays) {
    const k = $('#keepNote');
    k.hidden = false;
    k.textContent = `Files and text are deleted automatically after ${info.keepDays} day${info.keepDays > 1 ? 's' : ''}.`;
  }
  if (info.local) {
    const devBtn = $('#devicesBtn');
    devBtn.hidden = false;
    devBtn.onclick = openDevices;
    $('#devicesClose').onclick = () => $('#devices').close();
    $('#devices').addEventListener('click', (e) => { if (e.target === $('#devices')) $('#devices').close(); });
    setupGuest();
    $('#hint').textContent = 'Drop files here, paste images or text with Ctrl+V, or send them from your phone.';
    if (info.folder) {
      const b = $('#openFolder');
      b.hidden = false;
      b.title = info.folder;
      b.onclick = () => api('/api/open-folder', { method: 'POST' }).catch((e) => toast(e.message, true));
    }
  }

  $('#selectToggle').onclick = () => setSelecting(!selecting);
  $('#selCancel').onclick = () => setSelecting(false);
  $('#selAll').onclick = () => {
    if (selected.size === files.length) selected.clear(); else files.forEach((f) => selected.add(f.name));
    for (const [name, card] of cards) card.classList.toggle('selected', selected.has(name));
    updateSelbar();
  };
  $('#selZip').onclick = (e) => { if (!selected.size) e.preventDefault(); };
  $('#selDel').onclick = deleteSelected;
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && selecting && !$('#viewer').open) setSelecting(false);
  });

  for (const [btn, input] of [['#pick', '#picker'], ['#pickAny', '#pickerAny']]) {
    const picker = $(input);
    $(btn).onclick = () => picker.click();
    picker.onchange = () => { enqueue(picker.files); picker.value = ''; };
  }

  const noteText = $('#noteText');
  const autosize = () => { noteText.style.height = 'auto'; noteText.style.height = `${Math.min(noteText.scrollHeight, 160)}px`; };
  noteText.addEventListener('input', autosize);
  const submitNote = async () => { await sendNote(noteText.value); noteText.value = ''; autosize(); };
  $('#noteSend').onclick = submitNote;
  noteText.addEventListener('keydown', (e) => {
    // Enter sends on a keyboard; Shift+Enter makes a new line. Phones use the Send button.
    if (e.key === 'Enter' && !e.shiftKey && info.local) { e.preventDefault(); submitNote(); }
  });

  document.addEventListener('paste', (e) => {
    const list = [...(e.clipboardData?.files || [])];
    if (list.length) { e.preventDefault(); return enqueue(list); }
    // Pasting text anywhere outside the text box sends it straight to the other device.
    const inField = /^(TEXTAREA|INPUT)$/.test(e.target?.tagName);
    const text = e.clipboardData?.getData('text/plain');
    if (!inField && text?.trim()) { e.preventDefault(); sendNote(text); }
  });

  let depth = 0;
  const overlay = $('#dropOverlay');
  const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes('Files');
  window.addEventListener('dragenter', (e) => { if (hasFiles(e)) { depth++; overlay.hidden = false; } });
  window.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; overlay.hidden = true; } });
  window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); depth = 0; overlay.hidden = true;
    enqueue(e.dataTransfer.files);
  });

  const viewer = $('#viewer');
  $('#viewerClose').onclick = () => viewer.close();
  viewer.addEventListener('close', stopMedia);
  $('#viewerPrev').onclick = () => step(-1);
  $('#viewerNext').onclick = () => step(1);
  $('#viewerCopy').onclick = () => copyImage(files[viewerIndex]);
  $('#viewerShare').onclick = () => shareFile(files[viewerIndex]);
  $('#viewerDel').onclick = () => remove(files[viewerIndex]);
  $('#viewerHash').onclick = () => files[viewerIndex]?.sha256 && copyHash(files[viewerIndex]);
  viewer.addEventListener('click', (e) => { if (e.target === viewer) viewer.close(); });
  document.addEventListener('keydown', (e) => {
    if (!viewer.open) return;
    if (e.key === 'ArrowLeft') step(-1);
    if (e.key === 'ArrowRight') step(1);
    if ((e.ctrlKey || e.metaKey) && e.key === 'c') { e.preventDefault(); copyImage(files[viewerIndex]); }
  });

  let sx = null;
  viewer.addEventListener('touchstart', (e) => (sx = e.touches[0].clientX), { passive: true });
  viewer.addEventListener('touchend', (e) => {
    if (sx === null) return;
    const dx = e.changedTouches[0].clientX - sx;
    if (Math.abs(dx) > 60) step(dx < 0 ? 1 : -1);
    sx = null;
  });

  setInterval(() => files.length && render(files), 60000); // refresh "x min ago"
}

init();
