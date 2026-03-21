/* ADS Dashboard — Frontend JS */

async function api(url, opts = {}) {
  const resp = await fetch(url, opts);
  if (resp.status === 401) { location.href = '/login'; throw new Error('Unauthorized'); }
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || 'Request failed');
  }
  return resp.json();
}

function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

function timeAgo(ts) {
  const s = Math.floor(Date.now()/1000 - ts);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}

function shortModel(m) {
  if (!m) return '—';
  if (m.includes('qwen3')) return 'Qwen3 30B';
  if (m.includes('deepseek')) return 'DeepSeek 70B';
  return m.split('/').pop().substring(0, 20);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function copyApiKey() {
  const el = document.getElementById('api-key-preview');
  if (el) navigator.clipboard.writeText(el.textContent);
}
