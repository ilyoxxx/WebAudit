(function () {
  const box = document.getElementById('keys-box');
  if (!box) return;

  const HEADERS = { 'Content-Type': 'application/json', 'x-requested-with': 'webaudit' };

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function fmtDate(iso) {
    try {
      return new Date(iso).toLocaleDateString('fr-FR');
    } catch {
      return '';
    }
  }

  async function api(method, url, body) {
    const res = await fetch(url, {
      method,
      headers: HEADERS,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  }

  function renderMessage(text) {
    box.replaceChildren(el('p', 'keys-muted', text));
  }

  function renderLoggedOut() {
    const btn = el('a', 'keys-btn', 'Se connecter avec GitHub');
    btn.href = '/auth/github';
    box.replaceChildren(
      el('p', 'keys-muted', 'Connecte-toi avec GitHub pour créer une clé API et scanner sans la limite de 3 scans par jour.'),
      btn,
    );
  }

  function renderLoggedIn(me, keys, max, newKey, errorMsg) {
    const frag = document.createDocumentFragment();

    const top = el('div', 'keys-top');
    top.appendChild(el('span', 'keys-muted', `Connecté en tant que ${me.login}`));
    const out = el('button', 'keys-link', 'Se déconnecter');
    out.type = 'button';
    out.addEventListener('click', async () => {
      await api('POST', '/auth/logout');
      load();
    });
    top.appendChild(out);
    frag.appendChild(top);

    if (errorMsg) frag.appendChild(el('p', 'keys-error', errorMsg));

    if (newKey) {
      const note = el('div', 'keys-new');
      note.appendChild(el('strong', null, 'Ta nouvelle clé (affichée une seule fois) :'));
      const code = el('code', 'keys-code', newKey);
      note.appendChild(code);
      const copy = el('button', 'keys-btn', 'Copier');
      copy.type = 'button';
      copy.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(newKey);
          copy.textContent = 'Copié ✓';
        } catch {
          copy.textContent = 'Copie impossible : sélectionne le texte';
        }
      });
      note.appendChild(copy);
      frag.appendChild(note);
    }

    const list = el('div', 'keys-list');
    if (keys.length === 0) list.appendChild(el('p', 'keys-muted', 'Aucune clé pour le moment.'));
    for (const k of keys) {
      const row = el('div', 'keys-row');
      const info = el('div', 'keys-info');
      info.appendChild(el('strong', null, k.name));
      info.appendChild(el('span', 'keys-muted', `${k.prefix}…  ·  créée le ${fmtDate(k.createdAt)}`));
      row.appendChild(info);
      const del = el('button', 'keys-link keys-danger', 'Supprimer');
      del.type = 'button';
      del.addEventListener('click', async () => {
        if (!confirm('Supprimer cette clé ? Les applications qui l\'utilisent cesseront de fonctionner.')) return;
        const r = await api('DELETE', '/api/keys/' + encodeURIComponent(k.id));
        if (!r.ok) return renderLoggedIn(me, keys, max, null, 'Suppression impossible.');
        renderLoggedIn(me, r.data.keys, r.data.max, null, null);
      });
      row.appendChild(del);
      list.appendChild(row);
    }
    frag.appendChild(list);

    const form = el('form', 'keys-form');
    const input = el('input');
    input.type = 'text';
    input.placeholder = 'Nom de la clé (ex : mon-script)';
    input.maxLength = 40;
    input.setAttribute('aria-label', 'Nom de la clé');
    const submit = el('button', 'keys-btn', 'Créer une clé');
    submit.type = 'submit';
    if (keys.length >= max) {
      submit.disabled = true;
      input.disabled = true;
    }
    form.appendChild(input);
    form.appendChild(submit);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      submit.disabled = true;
      const r = await api('POST', '/api/keys', { name: input.value.trim() });
      if (!r.ok) {
        return renderLoggedIn(me, keys, max, null, r.data.message || 'Création impossible.');
      }
      renderLoggedIn(me, r.data.keys, r.data.max, r.data.key, null);
    });
    frag.appendChild(form);
    frag.appendChild(el('p', 'keys-muted', `${keys.length} / ${max} clés utilisées.`));

    box.replaceChildren(frag);
  }

  async function load() {
    try {
      const me = (await api('GET', '/api/me')).data;
      if (!me.configured) return renderMessage('Les clés API ne sont pas encore activées sur ce serveur.');
      if (!me.loggedIn) return renderLoggedOut();
      const r = await api('GET', '/api/keys');
      if (!r.ok) return renderLoggedOut();
      renderLoggedIn(me, r.data.keys, r.data.max, null, null);
    } catch {
      renderMessage('Impossible de charger les clés API pour le moment.');
    }
  }

  load();
})();
