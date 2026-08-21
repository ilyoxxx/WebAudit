export interface CollectedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

/**
 * undici renvoie parfois plusieurs Set-Cookie fusionnés dans une seule string
 * séparée par ", " — mais les dates (Expires=...) contiennent aussi des virgules,
 * donc on découpe sur le pattern "nom=valeur;" en début de segment plutôt que
 * naïvement sur toutes les virgules.
 */
export function collectCookies(setCookieHeader: string | undefined): CollectedCookie[] {
  if (!setCookieHeader) return [];

  const rawCookies = setCookieHeader.split(/,(?=\s*[^;=\s]+=)/);

  return rawCookies.map((raw) => {
    const parts = raw.split(';').map((p) => p.trim());
    const [name] = parts[0].split('=');

    const lower = parts.map((p) => p.toLowerCase());

    const sameSitePart = parts.find((p) => p.toLowerCase().startsWith('samesite='));

    return {
      name: name?.trim() ?? 'unknown',
      secure: lower.includes('secure'),
      httpOnly: lower.includes('httponly'),
      sameSite: sameSitePart ? sameSitePart.split('=')[1] : undefined,
    };
  });
}
