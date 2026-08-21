const form = document.getElementById('scan-form');
const input = document.getElementById('url-input');
const statusEl = document.getElementById('status');
const reportEl = document.getElementById('report');
const gradeBadge = document.getElementById('grade-badge');
const reportUrl = document.getElementById('report-url');
const reportScore = document.getElementById('report-score');
const resultsByCategory = document.getElementById('results-by-category');

const STATUS_ICON = { pass: '✓', warn: '!', fail: '✕', na: '–' };
const CATEGORY_LABEL = {
  security: 'Sécurité',
  rgpd: 'RGPD',
  perf: 'Performance',
  seo: 'SEO',
};

let messages = {};

async function loadLocale() {
  try {
    const res = await fetch('/locales/fr.json');
    messages = await res.json();
  } catch {
    messages = {};
  }
}

function t(key) {
  return messages[key] ?? key;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  const button = form.querySelector('button');
  button.disabled = true;
  statusEl.hidden = false;
  statusEl.textContent = `Scan de ${url} en cours…`;
  reportEl.hidden = true;

  try {
    if (Object.keys(messages).length === 0) await loadLocale();

    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || `Erreur HTTP ${res.status}`);
    }

    const report = await res.json();
    renderReport(report);
    statusEl.hidden = true;
  } catch (err) {
    statusEl.textContent = `Erreur : ${err.message}`;
  } finally {
    button.disabled = false;
  }
});

function renderReport(report) {
  gradeBadge.textContent = report.grade;
  gradeBadge.dataset.grade = report.grade;
  reportUrl.textContent = report.url;
  reportScore.textContent = `Score : ${report.score}/100`;

  const byCategory = {};
  for (const r of report.results) {
    if (!byCategory[r.category]) byCategory[r.category] = [];
    byCategory[r.category].push(r);
  }

  resultsByCategory.innerHTML = '';
  for (const [category, rules] of Object.entries(byCategory)) {
    const block = document.createElement('div');
    block.className = 'category-block';

    const title = document.createElement('div');
    title.className = 'category-title';
    title.textContent = CATEGORY_LABEL[category] || category;
    block.appendChild(title);

    for (const rule of rules) {
      block.appendChild(renderRuleRow(rule));
    }

    resultsByCategory.appendChild(block);
  }

  reportEl.hidden = false;
}

function renderRuleRow(rule) {
  const row = document.createElement('div');
  row.className = 'rule-row';

  const status = document.createElement('div');
  status.className = 'rule-status';
  status.dataset.status = rule.status;
  status.textContent = STATUS_ICON[rule.status] || '?';
  row.appendChild(status);

  const body = document.createElement('div');
  body.className = 'rule-body';

  const message = document.createElement('div');
  message.className = 'rule-message';
  message.textContent = t(rule.messageKey);
  body.appendChild(message);

  if (rule.remediationKey && rule.status !== 'pass') {
    const remediation = document.createElement('div');
    remediation.className = 'rule-remediation';
    remediation.textContent = `→ ${t(rule.remediationKey)}`;
    body.appendChild(remediation);
  }

  const docs = document.createElement('div');
  docs.className = 'rule-docs';
  docs.innerHTML = `<a href="${rule.docs}" target="_blank" rel="noopener">Documentation</a>`;
  body.appendChild(docs);

  row.appendChild(body);
  return row;
}
