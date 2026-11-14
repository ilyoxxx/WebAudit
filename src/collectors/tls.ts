import * as tls from 'node:tls';
import { URL } from 'node:url';
import { guardedLookup, validateUrlObject, isBlockedError } from '../security/ssrf';

export interface TlsCollectResult {
  valid: boolean;
  protocol?: string;
  issuer?: string;
  daysUntilExpiry?: number;
  error?: string;
}

const TIMEOUT_MS = 6000;

export function collectTls(rawUrl: string): Promise<TlsCollectResult> {
  return new Promise((resolve) => {
    let hostname: string;
    try {
      const u = new URL(rawUrl);
      if (validateUrlObject(u)) {
        resolve({ valid: false, error: 'blocked_target' });
        return;
      }
      hostname = u.hostname;
    } catch {
      resolve({ valid: false, error: 'invalid_url' });
      return;
    }

    let done = false;
    const finish = (r: TlsCollectResult) => {
      if (done) return;
      done = true;
      clearTimeout(hardTimer);
      resolve(r);
    };

    // rejectUnauthorized:false est voulu : on INSPECTE le certificat, aucune donnée n'est envoyée.
    // Le lookup gardé empêche cette sonde de joindre une adresse interne.
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        timeout: TIMEOUT_MS,
        rejectUnauthorized: false,
        lookup: guardedLookup as never,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() ?? undefined;
        const authorized = socket.authorized;

        let daysUntilExpiry: number | undefined;
        if (cert && cert.valid_to) {
          const expiry = new Date(cert.valid_to).getTime();
          daysUntilExpiry = Math.floor((expiry - Date.now()) / (1000 * 60 * 60 * 24));
        }

        const issuerRaw = cert?.issuer?.O ?? cert?.issuer?.CN;
        const authError = socket.authorizationError as unknown;

        finish({
          valid: authorized,
          protocol,
          issuer: Array.isArray(issuerRaw) ? issuerRaw[0] : issuerRaw,
          daysUntilExpiry,
          error: authorized
            ? undefined
            : authError instanceof Error
              ? authError.message
              : String(authError ?? 'unknown_tls_error'),
        });
        socket.end();
      },
    );

    // Délai global : `timeout` ne couvre pas tous les blocages (ex. connexion qui n'aboutit jamais).
    const hardTimer = setTimeout(() => {
      socket.destroy();
      finish({ valid: false, error: 'timeout' });
    }, TIMEOUT_MS + 1000);

    socket.on('timeout', () => {
      socket.destroy();
      finish({ valid: false, error: 'timeout' });
    });

    socket.on('error', (err) => {
      finish({ valid: false, error: isBlockedError(err) ? 'blocked_target' : err.message });
    });
  });
}
