'use strict';

const $ = (s) => document.querySelector(s);
const CSRF = { 'X-PhoneDrop': '1' };
const CONCURRENCY = 2;
const RETRIES = 2;

let info = { maxBytes: Infinity, serverCopy: false, local: false };
let files = [];
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

const previewable = (f) => !/heic|tiff/.test(f.type);

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
      status.textContent = `Saved as ${res.name}`;
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
    if (!card || card.dataset.url !== f.url) {
      const fresh = makeCard(f);
      card ? card.replaceWith(fresh) : null;
      card = fresh;
      cards.set(f.name, card);
    }
    card.querySelector('.meta-sub').textContent = `${human(f.size)} · ${ago(f.mtime)}`;
    updateClip(card, f);
    if (grid.children[i] !== card) grid.insertBefore(card, grid.children[i] || null);
  });
  $('#empty').hidden = list.length > 0;
  $('#count').textContent = list.length ? `(${list.length})` : '';
  $('#zipAll').hidden = !list.length;
  if ($('#viewer').open) {
    const cur = $('#viewerName').textContent;
    const idx = files.findIndex((f) => f.name === cur);
    idx < 0 ? $('#viewer').close() : (viewerIndex = idx);
    if (idx >= 0) applyCopyButton($('#viewerCopy'), files[idx]);
  }
}

// On this computer, Copy uses a PNG the server prepares in the background. Until it's ready the
// image shows a progress overlay and Copy is disabled, so the clipboard only ever gets the finished image.
function clipState(f) {
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
  btn.textContent = s.label;
  btn.disabled = s.disabled;
  btn.title = s.title || '';
  return s;
}

function updateClip(card, f) {
  const s = applyCopyButton(card.querySelector('.copy-btn'), f);
  const overlay = card.querySelector('.convert');
  overlay.hidden = !s.busy;
  if (s.busy) {
    overlay.querySelector('i').style.width = `${s.pct}%`;
    overlay.querySelector('.convert-label').textContent = s.text;
  }
}

function makeCard(f) {
  const thumb = el('img', { src: f.thumb, alt: f.name, loading: 'lazy', decoding: 'async' });
  thumb.addEventListener('error', () => {
    if (previewable(f) && thumb.src.indexOf('/f/') < 0) thumb.src = f.url; // no thumbnailer: fall back to original
    else thumb.replaceWith(el('div', { class: 'noprev' }, f.type.split('/')[1].toUpperCase()));
  });
  const card = el('figure', { class: 'card' },
    el('div', { class: 'thumb-wrap' },
      el('button', { class: 'thumb', 'aria-label': `Open ${f.name}`, onclick: () => openViewer(f.name) }, thumb),
      el('div', { class: 'convert', hidden: '' },
        el('div', { class: 'convert-bar' }, el('i')),
        el('span', { class: 'convert-label' }))),
    el('figcaption', {},
      el('div', { class: 'meta' }, el('span', { class: 'ellipsis' }, f.name), el('span', { class: 'meta-sub muted' })),
      el('div', { class: 'row' },
        el('button', { class: 'copy-btn', onclick: () => copyImage(byName(f.name)) }, 'Copy'),
        el('a', { class: 'btn', href: `/f/${enc(f.name)}?dl=1`, download: f.name }, 'Save'),
        el('button', { class: 'danger icon', 'aria-label': 'Delete', onclick: () => remove(byName(f.name)) }, '🗑'))));
  card.dataset.url = f.url;
  return card;
}

const byName = (n) => files.find((f) => f.name === n);

async function remove(f) {
  if (!f || !confirm(`Delete ${f.name}?`)) return;
  try {
    await api(`/api/files/${enc(f.name)}`, { method: 'DELETE' });
    toast('Deleted');
  } catch (e) { toast(e.message, true); }
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

function showViewer() {
  const f = files[viewerIndex];
  $('#viewerName').textContent = f.name;
  const img = $('#viewerImg');
  img.hidden = false;
  img.src = previewable(f) ? f.url : `${f.thumb}&size=1600`;
  applyCopyButton($('#viewerCopy'), f);
  $('#viewerDl').href = `/f/${enc(f.name)}?dl=1`;
  $('#viewerDl').setAttribute('download', f.name);
}

function step(d) {
  if (!files.length) return;
  viewerIndex = (viewerIndex + d + files.length) % files.length;
  showViewer();
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
      if (d.version !== version) { version = d.version; render(d.files); }
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
  if (info.local) {
    $('#hint').textContent = 'Drop images here, paste with Ctrl+V, or send them from your phone.';
    if (info.folder) {
      const b = $('#openFolder');
      b.hidden = false;
      b.title = info.folder;
      b.onclick = () => api('/api/open-folder', { method: 'POST' }).catch((e) => toast(e.message, true));
    }
  }

  const picker = $('#picker');
  $('#pick').onclick = () => picker.click();
  picker.onchange = () => { enqueue(picker.files); picker.value = ''; };

  document.addEventListener('paste', (e) => {
    const list = [...(e.clipboardData?.files || [])].filter((f) => f.type.startsWith('image/'));
    if (list.length) { e.preventDefault(); enqueue(list); }
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
  $('#viewerPrev').onclick = () => step(-1);
  $('#viewerNext').onclick = () => step(1);
  $('#viewerCopy').onclick = () => copyImage(files[viewerIndex]);
  $('#viewerDel').onclick = () => remove(files[viewerIndex]);
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
