import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import * as pMemoize from 'p-memoize';
import { KmsJsonWebTokenError } from './error';

export async function asymmetricSign(
  client: KMSClient,
  keyId: string,
  message: Buffer,
): Promise<Buffer> {
  const signatureResult = await client.send(
    new SignCommand({
      KeyId: keyId,
      MessageType: 'RAW',
      Message: message,
      SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
    }),
  );

  if (!signatureResult.Signature) {
    throw new KmsJsonWebTokenError('Empty signature returned').debug({
      signatureResult,
    });
  }

  return Buffer.from(signatureResult.Signature);
}

export const getPublicKey = pMemoize(
  async function awsGetPublicKey(
    client: KMSClient,
    keyId: string,
  ): Promise<string> {
    const publicKey = await client.send(
      new GetPublicKeyCommand({ KeyId: keyId }),
    );

    if (!publicKey.PublicKey) {
      throw new KmsJsonWebTokenError('Missing Public Key').debug({ publicKey });
    }

    if (
      publicKey.KeyUsage !== 'SIGN_VERIFY' ||
      !publicKey.CustomerMasterKeySpec?.startsWith('RSA') ||
      !Buffer.isBuffer(publicKey.PublicKey)
    ) {
      throw new KmsJsonWebTokenError('Incompatible Public Key').debug({
        publicKey,
      });
    }

    const pubKeyStr = publicKey.PublicKey.toString('base64');

    return `-----BEGIN PUBLIC KEY-----\n${pubKeyStr}\n-----END PUBLIC KEY-----`;
  },
  {
    cacheKey: ([, keyId]) => keyId,
  },
);
