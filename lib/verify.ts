import jsonwebtoken from 'jsonwebtoken';
import { KmsJsonWebTokenError } from './error.js';

export async function verify(
  token: string,
  getSecret: (
    header: jsonwebtoken.JwtHeader,
  ) => jsonwebtoken.Secret | Promise<jsonwebtoken.Secret>,
  options?: Omit<jsonwebtoken.VerifyOptions, 'algorithms' | 'complete'>,
): Promise<jsonwebtoken.Jwt> {
  const getPublicKeyOrSecret: jsonwebtoken.GetPublicKeyOrSecret = async (
    header,
    callback,
  ) => {
    Promise.resolve(getSecret(header))
      .then((secret) => callback(null, secret))
      .catch(callback);
  };

  const resolvedOptions: jsonwebtoken.VerifyOptions & { complete: true } = {
    ...options,
    algorithms: ['RS256'],
    complete: true,
  };

  return new Promise((resolve, reject) => {
    jsonwebtoken.verify(
      token,
      getPublicKeyOrSecret,
      resolvedOptions,
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
}
