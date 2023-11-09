import type { KMSClient } from '@aws-sdk/client-kms';
import jsonwebtoken from 'jsonwebtoken';
import { asymmetricSign, getPublicKey } from './aws-crypto.js';
import { KmsJsonWebTokenError } from './error.js';
import { sign } from './sign.js';
import { verify } from './verify.js';

export async function awsKmsSign(
  payload: string | Buffer | object,
  client: KMSClient,
  options: Omit<jsonwebtoken.SignOptions, 'algorithm'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  },
): Promise<string> {
  const { resolveKeyId, ...jwtOptions } = options;

  return sign(
    payload,
    async (message, { keyid }) => {
      if (!keyid) {
        throw new KmsJsonWebTokenError('Missing Key Id in Header').debug({
          message: message.toString('base64'),
          keyid,
        });
      }

      const keyId = await (resolveKeyId ? resolveKeyId(keyid) : keyid);

      return asymmetricSign(client, keyId, message);
    },
    jwtOptions,
  );
}

export async function awsKmsVerify(
  token: string,
  client: KMSClient,
  options: Omit<jsonwebtoken.VerifyOptions, 'algorithms' | 'complete'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  } = {},
): Promise<jsonwebtoken.Jwt> {
  const { resolveKeyId, ...jwtOptions } = options;

  return verify(
    token,
    async (header) => {
      if (header.alg !== 'RS256') {
        throw new KmsJsonWebTokenError('Header alg is not RS256').debug({
          header,
        });
      }

      if (!header.kid) {
        throw new KmsJsonWebTokenError('Missing Key Id in Header').debug({
          header,
        });
      }

      const keyId = await (resolveKeyId
        ? resolveKeyId(header.kid)
        : header.kid);

      return getPublicKey(client, keyId);
    },
    jwtOptions,
  );
}
