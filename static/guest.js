'use strict';

// Page for a guest who opened a one-time drop link: upload only, nothing to browse.
// Self-contained on purpose (app.js isn't loaded here); the upload queue is the same as in app.js.

const $ = (s) => document.querySelector(s);
const CSRF = { 'X-PhoneDrop': '1' };
const CONCURRENCY = 2;
const RETRIES = 2;

let info = { maxBytes: Infinity };
let ended = false;
let sentCount = 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = (n) => encodeURIComponent(n);

function human(n) {
  for (const u of ['B', 'KB', 'MB', 'GB']) {
    if (n < 1024) return `${n < 10 && u !== 'B' ? n.toFixed(1) : Math.round(n)} ${u}`;
    n /= 1024;
  }
  return `${n.toFixed(1)} TB`;
}

let toastTimer;
function toast(msg, bad = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = 'toast'), 2600);
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else e.setAttribute(k, v);
  }
  for (const k of kids) e.append(k);
  return e;
}

// The session expired or was revoked on the computer: say so and stop offering uploads.
function endAccess() {
  if (ended) return;
  ended = true;
  $('#hint').textContent = 'Guest access has ended. Ask for a new link to send more.';
  $('#hint').classList.add('ended');
  for (const id of ['#pick', '#pickAny']) $(id).disabled = true;
  for (const job of pending.splice(0)) fail(job.row, job.status, 'Guest access has ended');
}

// ---------------------------------------------------------------- uploads

const pending = [];
let active = 0;

function enqueue(fileList) {
  if (ended) return;
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

function addSent(name) {
  sentCount++;
  $('#sent').prepend(el('li', { class: 'ellipsis' }, name));
  $('#sentSection').hidden = false;
  $('#sentCount').textContent = `(${sentCount})`;
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
      status.textContent = res.meta === 'kept' ? 'Sent (metadata kept)' : 'Sent';
      row.classList.add('done');
      addSent(res.name);
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
      if (x.status === 401) endAccess();
      const err = new Error(x.status === 401 ? 'Guest access has ended' : body.error || `Upload failed (${x.status})`);
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

// ---------------------------------------------------------------- wiring

async function init() {
  for (const [btn, input] of [['#pick', '#picker'], ['#pickAny', '#pickerAny']]) {
    const picker = $(input);
    $(btn).onclick = () => picker.click();
    picker.onchange = () => { enqueue(picker.files); picker.value = ''; };
  }
  try {
    const r = await fetch('/api/info', { headers: CSRF, credentials: 'same-origin', cache: 'no-store' });
    if (r.status === 401) return endAccess();
    if (r.ok) info = await r.json();
  } catch { return toast('Can\'t reach the computer', true); }
  if (info.expires) {
    const until = new Date(info.expires * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    $('#hint').textContent = `You can send files to this computer until ${until}.`;
    // Nothing else talks to the server while the page is idle, so end the page on time by itself.
    const left = info.expires * 1000 - Date.now();
    if (left < 2 ** 31) setTimeout(endAccess, Math.max(0, left)); // longer delays overflow setTimeout
  }
}

init();
