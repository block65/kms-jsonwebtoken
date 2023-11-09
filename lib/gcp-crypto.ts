import { createHash } from 'node:crypto';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import pMemoize from 'p-memoize';
import { KmsJsonWebTokenError } from './error.js';

export async function asymmetricSign(
  client: KeyManagementServiceClient,
  keyId: string,
  message: Buffer,
): Promise<Buffer> {
  const digest = createHash('sha256');
  digest.update(message);

  const [signResponse] = await client.asymmetricSign({
    name: keyId,
    digest: {
      sha256: digest.digest(),
    },
  });

  if (!signResponse.signature) {
    throw new KmsJsonWebTokenError('Empty signature from GCP').debug({
      signResponse,
    });
  }

  return Buffer.from(signResponse.signature);
}

export const getPublicKey = pMemoize(
  async (
    client: KeyManagementServiceClient,
    keyId: string,
  ): Promise<string> => {
    const [publicKey] = await client.getPublicKey({ name: keyId });

    if (!publicKey) {
      throw new KmsJsonWebTokenError('Missing Public Key').debug({ publicKey });
    }

    if (
      publicKey.algorithm !== 'RSA_SIGN_PKCS1_2048_SHA256' ||
      !publicKey.pem
    ) {
      throw new KmsJsonWebTokenError('Incompatible Public Key').debug({
        publicKey,
      });
    }

    return publicKey.pem;
  },
  {
    cacheKey: ([, keyId]) => keyId,
  },
);
