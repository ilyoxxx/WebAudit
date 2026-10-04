import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const KEYS_FILE = path.join(__dirname, '..', '..', 'data', 'api-keys.json');

interface ApiKeyRecord {
  key: string;
  owner: string;
  createdAt: string;
  note?: string;
}

function loadKeys(): ApiKeyRecord[] {
  if (!fs.existsSync(KEYS_FILE)) return [];
  return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf-8'));
}

function saveKeys(keys: ApiKeyRecord[]): void {
  fs.mkdirSync(path.dirname(KEYS_FILE), { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

export function isValidKey(key: string): boolean {
  return loadKeys().some((k) => k.key === key);
}

export function generateKey(owner: string, note?: string): string {
  const key = `wa_${crypto.randomBytes(24).toString('hex')}`;
  const keys = loadKeys();
  keys.push({ key, owner, createdAt: new Date().toISOString(), note });
  saveKeys(keys);
  return key;
}

export function revokeKey(key: string): boolean {
  const keys = loadKeys();
  const filtered = keys.filter((k) => k.key !== key);
  saveKeys(filtered);
  return filtered.length !== keys.length;
}

export function listKeys(): ApiKeyRecord[] {
  return loadKeys();
}
