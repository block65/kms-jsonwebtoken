import jsonwebtoken from 'jsonwebtoken';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { sign } from './sign.js';
import { verify } from './verify.js';
import { asymmetricSign, getPublicKey } from './gcp-crypto.js';
import { KmsJsonWebTokenError } from './error.js';

export async function gcpKmsSign(
  payload: string | Buffer | object,
  client: KeyManagementServiceClient,
  options: Omit<jsonwebtoken.SignOptions, 'algorithm'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  } = {},
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

      const signature = await asymmetricSign(client, keyId, message);

      return Buffer.from(signature);
    },
    jwtOptions,
  );
}

export async function gcpKmsVerify(
  token: string,
  client: KeyManagementServiceClient,
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
