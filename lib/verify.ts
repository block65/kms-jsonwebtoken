import * as jsonwebtoken from 'jsonwebtoken';
import { JwtHeader, Secret } from 'jsonwebtoken';

export async function verify(
  token: string,
  getSecret: (header: JwtHeader) => Secret | Promise<Secret>,
  options?: Omit<jsonwebtoken.VerifyOptions, 'algorithms'>,
): Promise<object> {
  return new Promise((resolve, reject) => {
    jsonwebtoken.verify(
      token,
      async (header, callback) => {
        Promise.resolve(getSecret(header))
          .then((secret) => callback(null, secret))
          .catch(callback);
      },
      { ...options, algorithms: ['RS256'] },
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
}
