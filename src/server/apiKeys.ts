import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', '..', 'data');
const KEYS_FILE = path.join(DATA_DIR, 'api-keys.json');

export const MAX_KEYS_PER_OWNER = 3;

interface ApiKeyRecord {
  id?: string;
  key?: string; // anciennes clés en clair (compatibilité)
  hash?: string; // empreinte SHA-256 de la clé
  prefix?: string; // début de la clé, pour la reconnaître dans la liste
  owner: string;
  name?: string;
  createdAt: string;
  note?: string;
}

export interface PublicKeyInfo {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
}

function hashKey(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function loadKeys(): ApiKeyRecord[] {
  if (!fs.existsSync(KEYS_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf-8'));
  } catch {
    return [];
  }
}

function saveKeys(keys: ApiKeyRecord[]): void {
  fs.mkdirSync(path.dirname(KEYS_FILE), { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

export function isValidKey(key: string): boolean {
  const h = hashKey(key);
  return loadKeys().some((k) => (k.hash && k.hash === h) || (k.key && k.key === key));
}

function makeRecord(owner: string, name?: string, note?: string): { key: string; record: ApiKeyRecord } {
  const key = `wa_${crypto.randomBytes(24).toString('hex')}`;
  const record: ApiKeyRecord = {
    id: crypto.randomBytes(8).toString('hex'),
    hash: hashKey(key),
    prefix: key.slice(0, 7),
    owner,
    name: name || 'Ma clé',
    createdAt: new Date().toISOString(),
    note,
  };
  return { key, record };
}

// Création sans limite (usage administrateur / scripts)
export function generateKey(owner: string, note?: string): string {
  const { key, record } = makeRecord(owner, undefined, note);
  const keys = loadKeys();
  keys.push(record);
  saveKeys(keys);
  return key;
}

// Création pour un utilisateur connecté, avec limite par compte
export function createKeyForOwner(owner: string, name?: string): string {
  const keys = loadKeys();
  if (keys.filter((k) => k.owner === owner).length >= MAX_KEYS_PER_OWNER) {
    throw new Error('key_limit_reached');
  }
  const { key, record } = makeRecord(owner, (name || '').slice(0, 40));
  keys.push(record);
  saveKeys(keys);
  return key;
}

export function listKeysFor(owner: string): PublicKeyInfo[] {
  return loadKeys()
    .filter((k) => k.owner === owner)
    .map((k) => ({
      id: k.id || (k.hash ? k.hash.slice(0, 16) : crypto.createHash('sha256').update(k.key || '').digest('hex').slice(0, 16)),
      name: k.name || 'Ancienne clé',
      prefix: k.prefix || (k.key ? k.key.slice(0, 7) : 'wa_'),
      createdAt: k.createdAt,
    }));
}

export function revokeKeyById(owner: string, id: string): boolean {
  const keys = loadKeys();
  const infos = listKeysFor(owner);
  const target = infos.find((i) => i.id === id);
  if (!target) return false;
  const filtered = keys.filter((k) => {
    if (k.owner !== owner) return true;
    const kid = k.id || (k.hash ? k.hash.slice(0, 16) : crypto.createHash('sha256').update(k.key || '').digest('hex').slice(0, 16));
    return kid !== id;
  });
  saveKeys(filtered);
  return filtered.length !== keys.length;
}

// Révocation par clé complète (usage administrateur / scripts)
export function revokeKey(key: string): boolean {
  const keys = loadKeys();
  const h = hashKey(key);
  const filtered = keys.filter((k) => !((k.hash && k.hash === h) || (k.key && k.key === key)));
  saveKeys(filtered);
  return filtered.length !== keys.length;
}

export function listKeys(): ApiKeyRecord[] {
  return loadKeys();
}
