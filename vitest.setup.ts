import { File } from 'node:buffer';

// Node 18 n'expose pas File en global par défaut (ajouté stable en Node 20),
// mais undici (dépendance transitive de cheerio) s'attend à le trouver.
// Polyfill minimal pour la compatibilité CI/Node 18.
if (typeof globalThis.File === 'undefined') {
  // @ts-expect-error -- polyfill global minimal
  globalThis.File = File;
}
