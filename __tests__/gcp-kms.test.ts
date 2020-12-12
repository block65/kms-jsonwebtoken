import { KeyManagementServiceClient } from '@google-cloud/kms/build/src/v1';
import { gcpKmsSign, gcpKmsVerify } from '../lib/gcp-kms';

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
