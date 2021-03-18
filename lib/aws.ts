import type { KMSClient } from '@aws-sdk/client-kms';
import * as jsonwebtoken from 'jsonwebtoken';
import { sign } from './sign';
import { verify } from './verify';
import { asymmetricSign, getPublicKey } from './aws-crypto';

export async function awsKmsSign(
  payload: string | Buffer | object,
  client: KMSClient,
  options: Omit<jsonwebtoken.SignOptions, 'algorithm'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  },
) {
  const { resolveKeyId, ...jwtOptions } = options;

  return sign(
    payload,
    async (message, { keyid }) => {
      if (!keyid) {
        throw new Error('Missing Key Id in Header');
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
  options: Omit<jsonwebtoken.VerifyOptions, 'algorithms'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  } = {},
): Promise<object> {
  const { resolveKeyId, ...jwtOptions } = options;

  return verify(
    token,
    async (header) => {
      if (header.alg !== 'RS256') {
        throw new Error('Header alg is not RS256');
      }

      if (!header.kid) {
        throw new Error('Missing Key Id in Header');
      }

      const keyId = await (resolveKeyId
        ? resolveKeyId(header.kid)
        : header.kid);

      return getPublicKey(client, keyId);
    },
    jwtOptions,
  );
}
