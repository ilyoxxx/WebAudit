import * as crypto from 'node:crypto';
import { dataPath, readJson, writeJsonAtomic, mtime } from './storage';

const KEYS_FILE = dataPath('api-keys.json');

export const MAX_KEYS_PER_OWNER = 3;
const KEY_RE = /^wa_[0-9a-f]{48}$/;

interface ApiKeyRecord {
  id?: string;
  key?: string; // anciennes clés en clair : migrées en empreinte au chargement
  hash?: string; // empreinte SHA-256 de la clé
  prefix?: string;
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

// Cache invalidé dès que le fichier change (le script generate-key.js l'écrit hors du serveur).
let cache: ApiKeyRecord[] = [];
let byHash = new Map<string, ApiKeyRecord>();
let cacheStamp = -1;

function recordId(k: ApiKeyRecord): string {
  return k.id || (k.hash ? k.hash.slice(0, 16) : '');
}

function loadKeys(): ApiKeyRecord[] {
  const stamp = mtime(KEYS_FILE);
  if (stamp === cacheStamp) return cache;

  const raw = readJson<unknown>(KEYS_FILE, []);
  const list: ApiKeyRecord[] = Array.isArray(raw) ? (raw as ApiKeyRecord[]) : [];

  // Migration : plus aucune clé en clair sur le disque.
  let migrated = false;
  for (const k of list) {
    if (k.key && !k.hash) {
      k.hash = hashKey(k.key);
      k.prefix = k.prefix || k.key.slice(0, 7);
      k.id = k.id || k.hash.slice(0, 16);
      delete k.key;
      migrated = true;
    }
  }
  if (migrated) writeJsonAtomic(KEYS_FILE, list);

  cache = list;
  byHash = new Map(list.filter((k) => k.hash).map((k) => [k.hash as string, k]));
  cacheStamp = mtime(KEYS_FILE);
  return cache;
}

function saveKeys(keys: ApiKeyRecord[]): void {
  writeJsonAtomic(KEYS_FILE, keys);
  cacheStamp = -1; // forcer le rechargement
  loadKeys();
}

/** Valide une clé et renvoie son identifiant interne (pour le plafond par clé), ou null. */
export function validateKey(key: string): string | null {
  if (typeof key !== 'string' || !KEY_RE.test(key)) return null;
  loadKeys();
  const rec = byHash.get(hashKey(key));
  return rec ? recordId(rec) || 'legacy' : null;
}

export function isValidKey(key: string): boolean {
  return validateKey(key) !== null;
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

function cleanName(name?: string): string {
  // eslint-disable-next-line no-control-regex
  return (name || '').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, 40);
}

// Création sans limite (usage administrateur / scripts)
export function generateKey(owner: string, note?: string): string {
  const { key, record } = makeRecord(owner, undefined, note);
  const keys = [...loadKeys(), record];
  saveKeys(keys);
  return key;
}

// Création pour un utilisateur connecté, avec limite par compte
export function createKeyForOwner(owner: string, name?: string): string {
  const keys = loadKeys();
  if (keys.filter((k) => k.owner === owner).length >= MAX_KEYS_PER_OWNER) {
    throw new Error('key_limit_reached');
  }
  const { key, record } = makeRecord(owner, cleanName(name));
  saveKeys([...keys, record]);
  return key;
}

export function listKeysFor(owner: string): PublicKeyInfo[] {
  return loadKeys()
    .filter((k) => k.owner === owner)
    .map((k) => ({
      id: recordId(k),
      name: k.name || 'Ancienne clé',
      prefix: k.prefix || 'wa_',
      createdAt: k.createdAt,
    }));
}

export function revokeKeyById(owner: string, id: string): boolean {
  const keys = loadKeys();
  const filtered = keys.filter((k) => !(k.owner === owner && recordId(k) === id));
  if (filtered.length === keys.length) return false;
  saveKeys(filtered);
  return true;
}

// Révocation par clé complète (usage administrateur / scripts)
export function revokeKey(key: string): boolean {
  const keys = loadKeys();
  const h = hashKey(key);
  const filtered = keys.filter((k) => k.hash !== h);
  if (filtered.length === keys.length) return false;
  saveKeys(filtered);
  return true;
}

export function listKeys(): ApiKeyRecord[] {
  return loadKeys();
}
