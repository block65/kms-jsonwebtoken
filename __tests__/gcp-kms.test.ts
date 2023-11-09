import { constants, generateKeyPairSync, sign } from 'node:crypto';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { jest } from '@jest/globals';

jest.unstable_mockModule('../lib/gcp-crypto.js', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  return {
    getPublicKey: jest.fn(
      async (): Promise<string> =>
        publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    ),

    asymmetricSign: async function mockSigner(
      client: KeyManagementServiceClient,
      keyId: string,
      message: Buffer,
    ): Promise<Buffer> {
      return sign('sha256', message, {
        key: privateKey,
        padding: constants.RSA_PKCS1_PADDING,
      });
    },
  };
});

describe('GCP KMS', () => {
  test('Sign / Verify', async () => {
    const { gcpKmsSign, gcpKmsVerify } = await import('../lib/index.js');

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

    const kid = 'kms-jsonwebtoken-deleteme/1';

    const initialPayload = {
      hello: 'test',
    };

    const token = await gcpKmsSign(initialPayload, client, {
      jwtid: 'static',
      keyid: kid,
      resolveKeyId,
    });

    const payload = await gcpKmsVerify(token, client, {
      resolveKeyId,
    });

    expect(payload).toStrictEqual({
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
