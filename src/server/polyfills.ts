import { File } from 'node:buffer';

// Node 18 n'expose pas File en global (stable depuis Node 20).
// cheerio -> undici en a besoin dès son chargement.
// Ce fichier doit être importé AVANT tout autre module dans server.ts.
const g = globalThis as unknown as { File?: typeof File };
if (typeof g.File === 'undefined') {
  g.File = File;
}
