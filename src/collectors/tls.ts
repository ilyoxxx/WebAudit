import * as tls from 'node:tls';
import { URL } from 'node:url';

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
      hostname = new URL(rawUrl).hostname;
    } catch {
      resolve({ valid: false, error: 'invalid_url' });
      return;
    }

    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        timeout: TIMEOUT_MS,
        rejectUnauthorized: false, // on veut inspecter même les certifs invalides
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

        resolve({
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

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ valid: false, error: 'timeout' });
    });

    socket.on('error', (err) => {
      resolve({ valid: false, error: err.message });
    });
  });
}
