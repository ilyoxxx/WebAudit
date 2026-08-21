import { promises as dns } from 'node:dns';
import { URL } from 'node:url';

export interface DnsCollectResult {
  a: string[];
  aaaa: string[];
  mx: string[];
  txt: string[];
}

async function safeResolve<T>(fn: () => Promise<T[]>): Promise<T[]> {
  try {
    return await fn();
  } catch {
    return [];
  }
}

export async function collectDns(rawUrl: string): Promise<DnsCollectResult> {
  let hostname: string;
  try {
    hostname = new URL(rawUrl).hostname;
  } catch {
    return { a: [], aaaa: [], mx: [], txt: [] };
  }

  const [a, aaaa, mxRecords, txtRecords] = await Promise.all([
    safeResolve(() => dns.resolve4(hostname)),
    safeResolve(() => dns.resolve6(hostname)),
    safeResolve(() => dns.resolveMx(hostname)),
    safeResolve(() => dns.resolveTxt(hostname)),
  ]);

  return {
    a,
    aaaa,
    mx: mxRecords.map((r) => r.exchange),
    txt: txtRecords.map((t) => t.join('')),
  };
}
