const FREE_SCANS_PER_DAY = 3;
const hits = new Map<string, { count: number; resetAt: number }>();

export function checkFreeLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const entry = hits.get(ip);

  if (!entry || now > entry.resetAt) {
    hits.set(ip, { count: 1, resetAt: now + 24 * 60 * 60 * 1000 });
    return { allowed: true, remaining: FREE_SCANS_PER_DAY - 1 };
  }

  if (entry.count >= FREE_SCANS_PER_DAY) {
    return { allowed: false, remaining: 0 };
  }

  entry.count += 1;
  return { allowed: true, remaining: FREE_SCANS_PER_DAY - entry.count };
}
