import * as AWS from 'aws-sdk';
import { awsKmsSign, awsKmsVerify } from '../lib';

describe('Basic Tests', () => {
  test('AWS KMS Sign / Verify', async () => {
    const kms = new AWS.KMS();

    const kid = 'd08e7ebd-fa93-4cbb-81e3-a044d4df383f';

    async function resolveKeyId(id: string) {
      return `arn:aws:kms:ap-southeast-1:869591909565:key/${id}`;
    }

    const initialPayload = {
      hello: 'test',
    };

    const token = await awsKmsSign(initialPayload, kms, {
      jwtid: 'static',
      keyid: kid,
      resolveKeyId,
    });

    const completePayload = await awsKmsVerify(token, kms, { complete: true });

    expect(completePayload).toStrictEqual(
      expect.objectContaining({
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
      }),
    );
  });
});
