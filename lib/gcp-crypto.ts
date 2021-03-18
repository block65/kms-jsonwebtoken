import { KeyManagementServiceClient } from '@google-cloud/kms';
import * as crypto from 'crypto';
import * as pMemoize from 'p-memoize';

export async function asymmetricSign(
  client: KeyManagementServiceClient,
  keyId: string,
  message: Buffer,
): Promise<Buffer> {
  const digest = crypto.createHash('sha256');
  digest.update(message);

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
}

export const getPublicKey = pMemoize(
  async (
    client: KeyManagementServiceClient,
    keyId: string,
  ): Promise<string> => {
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
  {
    cacheKey: ([, keyId]) => keyId,
  },
);
