import * as jsonwebtoken from 'jsonwebtoken';
import * as crypto from 'crypto';
import { KmsJsonWebTokenError } from './error';

export async function sign(
  payload: string | Buffer | object,
  signatureFunction: (
    message: Buffer,
    options: Omit<jsonwebtoken.SignOptions, 'algorithm'>,
  ) => Buffer | Promise<Buffer>,
  options: Omit<jsonwebtoken.SignOptions, 'algorithm'>,
): Promise<string> {
  if (!options.keyid) {
    throw new KmsJsonWebTokenError('Must provide options.keyid').debug({
      options,
    });
  }

  // Use jsonwebtoken.sign to get the payload, as it has many useful features.
  const token = await new Promise<string>((resolve, reject) => {
    jsonwebtoken.sign(
      payload,
      Buffer.from([]), // jsonwebtoken hangs on falsy secret
      {
        ...options,
        algorithm: 'none',
        jwtid: options.jwtid || crypto.randomBytes(12).toString('base64url'),
      },
      (err, result) => {
        if (err) {
          return reject(err);
        }

        if (!result) {
          return reject(
            new KmsJsonWebTokenError('Empty token result').debug({ result }),
          );
        }

        return resolve(result);
      },
    );
  });

  const [encodedAlgNoneHeader, encodedPayload] = token.split('.');
  const header = JSON.parse(
    Buffer.from(encodedAlgNoneHeader, 'base64url').toString(),
  );
  const encodedRs256Header = Buffer.from(
    JSON.stringify({ ...header, alg: 'RS256' }),
  ).toString('base64url');

  const signature = await signatureFunction(
    Buffer.from(`${encodedRs256Header}.${encodedPayload}`),
    options,
  );

  return [
    encodedRs256Header,
    encodedPayload,
    signature.toString('base64url'),
  ].join('.');
}
