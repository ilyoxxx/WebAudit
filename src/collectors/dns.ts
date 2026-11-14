import { promises as dns } from 'node:dns';
import { URL } from 'node:url';

export interface DnsCollectResult {
  a: string[];
  aaaa: string[];
  mx: string[];
  txt: string[];
  dmarc?: string[];
}

async function safeResolve<T>(fn: () => Promise<T[]>): Promise<T[]> {
  try {
    return await fn();
  } catch {
    return [];
  }
}

/** DMARC : on cherche sur le domaine puis sur ses parents (domaine organisationnel). */
async function resolveDmarc(hostname: string): Promise<string[]> {
  const labels = hostname.split('.');
  for (let i = 0; i <= labels.length - 2; i++) {
    const domain = labels.slice(i).join('.');
    const txt = await safeResolve(() => dns.resolveTxt(`_dmarc.${domain}`));
    const found = txt.map((t) => t.join('')).filter((t) => /^v=DMARC1/i.test(t.trim()));
    if (found.length > 0) return found;
  }
  return [];
}

export async function collectDns(rawUrl: string): Promise<DnsCollectResult> {
  let hostname: string;
  try {
    hostname = new URL(rawUrl).hostname;
  } catch {
    return { a: [], aaaa: [], mx: [], txt: [], dmarc: [] };
  }

  const [a, aaaa, mxRecords, txtRecords, dmarc] = await Promise.all([
    safeResolve(() => dns.resolve4(hostname)),
    safeResolve(() => dns.resolve6(hostname)),
    safeResolve(() => dns.resolveMx(hostname)),
    safeResolve(() => dns.resolveTxt(hostname)),
    resolveDmarc(hostname),
  ]);

  return {
    a,
    aaaa,
    mx: mxRecords.map((r) => r.exchange),
    txt: txtRecords.map((t) => t.join('')),
    dmarc,
  };
}
