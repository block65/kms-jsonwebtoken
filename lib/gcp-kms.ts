import * as jsonwebtoken from 'jsonwebtoken';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import * as crypto from 'crypto';
import { sign } from './sign';
import { verify } from './verify';

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

      const digest = crypto.createHash('sha256');
      digest.update(message);

      const keyId = await (resolveKeyId ? resolveKeyId(keyid) : keyid);

      const [signResponse] = await client.asymmetricSign({
        name: keyId,
        digest: {
          sha256: digest.digest(),
        },
      });

      if (!signResponse.signature) {
        throw new Error('Empty signature from GCP');
      }

      return Buffer.from(signResponse.signature);
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

      const [publicKey] = await client.getPublicKey({ name: keyId });

      if (!publicKey) {
        throw new Error('Missing Public Key');
      }

      if (
        publicKey.algorithm === 'EXTERNAL_SYMMETRIC_ENCRYPTION' ||
        publicKey.algorithm === 'GOOGLE_SYMMETRIC_ENCRYPTION' ||
        !publicKey.pem
      ) {
        throw new Error('Incompatible Public Key');
      }

      return publicKey.pem;
    },
    jwtOptions,
  );
}
