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

      // WARN: GCP KMS client.asymmetricSign expects the hash of the message
      // but our tests need the actual message,  because Node crypto.sign()
      // expects unhashed data
      // @ts-ignore
      // eslint-disable-next-line no-underscore-dangle
      const isSafeToPassMessage = client.asymmetricSign._isMockFunction;
      const [signResponse] = await client.asymmetricSign({
        name: keyId,
        digest: {
          sha256: digest.digest(),
        },
        ...(isSafeToPassMessage && { _message: message }),
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
        publicKey.algorithm !== 'RSA_SIGN_PKCS1_2048_SHA256' ||
        !publicKey.pem
      ) {
        throw new Error('Incompatible Public Key');
      }

      return publicKey.pem;
    },
    jwtOptions,
  );
}
