import { KeyManagementServiceClient } from '@google-cloud/kms';
import * as crypto from 'crypto';
import { gcpKmsSign, gcpKmsVerify } from '../lib';

jest.mock('../lib/gcp-crypto', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  return {
    getPublicKey: jest.fn(
      async (): /* request: protos.google.cloud.kms.v1.IGetPublicKeyRequest, */
      Promise<string> => {
        return publicKey.export({ format: 'pem', type: 'spki' }).toString();
      },
    ),

    asymmetricSign: async function mockSigner(
      client: KeyManagementServiceClient,
      keyId: string,
      message: Buffer,
    ): Promise<Buffer> {
      return crypto.sign('sha256', message, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      });
    },
  };
});

describe('GCP KMS', () => {
  test('Sign / Verify', async () => {
    const client = new KeyManagementServiceClient();

    const projectId = 'block65-corp';
    const locationId = 'global';
    const keyRingId = 'kms-jsonwebtoken-deleteme';
    // const keyId = 'kms-jsonwebtoken-deleteme';
    // const versionId = '1';

    async function resolveKeyId(kid: string) {
      const [keyId, versionId] = kid.split('/');

      return client.cryptoKeyVersionPath(
        projectId,
        locationId,
        keyRingId,
        keyId,
        versionId,
      );
    }

    const kid = `kms-jsonwebtoken-deleteme/1`;

    const initialPayload = {
      hello: 'test',
    };

    const token = await gcpKmsSign(initialPayload, client, {
      jwtid: 'static',
      keyid: kid,
      resolveKeyId,
    });

    const completePayload = await gcpKmsVerify(token, client, {
      complete: true,
      resolveKeyId,
    });

    expect(completePayload).toStrictEqual({
      header: {
        alg: 'RS256',
        kid,
        typ: 'JWT',
      },
      payload: {
        jti: 'static',
        iat: expect.any(Number),
        ...initialPayload,
      },
      signature: expect.any(String),
    });
  });
});
