import * as jsonwebtoken from 'jsonwebtoken';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { sign } from './sign';
import { verify } from './verify';
import { asymmetricSign, getPublicKey } from './gcp-crypto';

export async function gcpKmsSign(
  payload: string | Buffer | object,
  client: KeyManagementServiceClient,
  options: Omit<jsonwebtoken.SignOptions, 'algorithm'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  } = {},
) {
  const { resolveKeyId, ...jwtOptions } = options;

  return sign(
    payload,
    async (message, { keyid }) => {
      if (!keyid) {
        throw new Error('Missing Key Id in Header');
      }

      const keyId = await (resolveKeyId ? resolveKeyId(keyid) : keyid);

      const signature = await asymmetricSign(client, keyId, message);

      return Buffer.from(signature);
    },
    jwtOptions,
  );
}

export async function gcpKmsVerify(
  token: string,
  client: KeyManagementServiceClient,
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
