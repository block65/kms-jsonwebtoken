import * as jsonwebtoken from 'jsonwebtoken';
import * as crypto from 'crypto';

function toBase64Url(buff: Buffer): string {
  return Buffer.from(buff)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function fromBase64Url(encoded: string): Buffer {
  return Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

export async function sign(
  payload: string | Buffer | object,
  signatureFunction: (
    message: Buffer,
    options: Omit<jsonwebtoken.SignOptions, 'algorithm'>,
  ) => Buffer | Promise<Buffer>,
  options: Omit<jsonwebtoken.SignOptions, 'algorithm'>,
): Promise<string> {
  if (!options.keyid) {
    throw new Error('Must provide options.keyid');
  }

  // Use jsonwebtoken.sign to get the payload, as it has many useful features.
  const token = await new Promise<string>((resolve, reject) => {
    jsonwebtoken.sign(
      payload,
      Buffer.from([]), // jsonwebtoken hangs on falsy secret
      {
        ...options,
        algorithm: 'none',
        jwtid: options.jwtid || toBase64Url(crypto.randomBytes(12)),
      },
      (err, result) => {
        if (err) {
          return reject(err);
        }

        if (!result) {
          return reject(new Error('Empty token result'));
        }

        return resolve(result);
      },
    );
  });

  const [encodedAlgNoneHeader, encodedPayload] = token.split('.');
  const header = JSON.parse(fromBase64Url(encodedAlgNoneHeader).toString());
  const encodedRs256Header = toBase64Url(
    Buffer.from(JSON.stringify({ ...header, alg: 'RS256' })),
  );

  const signature = await signatureFunction(
    Buffer.from(`${encodedRs256Header}.${encodedPayload}`),
    options,
  );

  return [encodedRs256Header, encodedPayload, toBase64Url(signature)].join('.');
}
