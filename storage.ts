import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', '..', 'data');

export function dataPath(name: string): string {
  return path.join(DATA_DIR, name);
}

export function readJson<T>(file: string, fallback: T): T {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf-8')) as T;
  } catch {
    return fallback;
  }
}

/** Écriture atomique (fichier temporaire + rename), lisible uniquement par le propriétaire. */
export function writeJsonAtomic(file: string, data: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function mtime(file: string): number {
  try {
    return fs.statSync(file).mtimeMs;
  } catch {
    return 0;
  }
}
