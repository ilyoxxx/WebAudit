// Génère public/mentions-legales.html, confidentialite.html et cgu.html
// à partir de legal/*.tpl.html et de legal/config.json.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dir = path.join(root, 'legal');
const out = path.join(root, 'public');

const cfg = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
cfg.updatedAt = new Date().toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const fill = (text) =>
  text.replace(/\{\{(\w+)\}\}/g, (_, k) => {
    if (!(k in cfg)) throw new Error('Variable inconnue dans legal/config.json : ' + k);
    return esc(cfg[k]);
  });

const layout = fs.readFileSync(path.join(dir, '_layout.html'), 'utf8');
const todo = Object.keys(cfg).filter((k) => String(cfg[k]).includes('À COMPLÉTER'));
const pages = fs.readdirSync(dir).filter((f) => f.endsWith('.tpl.html'));

if (pages.length === 0) throw new Error('Aucun modèle trouvé dans legal/');

for (const f of pages) {
  const raw = fs.readFileSync(path.join(dir, f), 'utf8');
  const m = raw.match(/^<!--\s*title:\s*(.+?)\s*-->/);
  if (!m) throw new Error(f + ' : la première ligne doit être <!-- title: Mon titre -->');
  const body = raw.replace(m[0], '');
  const page = layout.split('{{title}}').join(esc(m[1])).replace('{{content}}', () => body);
  const name = f.replace('.tpl.html', '.html');
  fs.writeFileSync(path.join(out, name), fill(page));
  console.log('Généré : public/' + name);
}

if (todo.length) {
  console.log('\nATTENTION : à compléter dans legal/config.json avant de publier : ' + todo.join(', '));
}
