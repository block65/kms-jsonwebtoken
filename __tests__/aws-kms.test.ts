import {
  GetPublicKeyCommand,
  GetPublicKeyResponse,
  KMSClient,
  SignCommand,
  SignRequest,
  SignResponse,
} from '@aws-sdk/client-kms';
import awsSdkMock from 'aws-sdk-client-mock';
import { constants, generateKeyPairSync, sign } from 'node:crypto';
import { awsKmsSign, awsKmsVerify } from '../lib/index.js';

const mockKmsClient = awsSdkMock.mockClient(KMSClient);

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

mockKmsClient
  .on(SignCommand)
  .callsFake(async ({ Message }: SignRequest): Promise<SignResponse> => {
    if (!Message) {
      throw new Error('Empty Message');
    }

    return {
      Signature: sign('sha256', Message, {
        key: privateKey,
        padding: constants.RSA_PKCS1_PADDING,
      }),
      SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
    };
  });

mockKmsClient
  .on(GetPublicKeyCommand)
  .callsFake(async (): Promise<GetPublicKeyResponse> => {
    return {
      PublicKey: publicKey.export({ format: 'der', type: 'spki' }),
      KeyUsage: 'SIGN_VERIFY',
      KeySpec: 'RSA_2048',
    };
  });

describe.only('Basic Tests', () => {
  const kms = new KMSClient({});

  const kid = '46572b82-7181-494e-bd11-95152094cc27';

  async function resolveKeyId(id: string) {
    return `arn:aws:kms:us-east-1:123456789012:key/${id}`;
  }

  test('AWS KMS Sign / Verify', async () => {
    const initialPayload = {
      hello: 'test',
    };

    const signedToken = await awsKmsSign(initialPayload, kms, {
      jwtid: 'static',
      keyid: kid,
      resolveKeyId,
    });

    // const completePayload = await awsKmsVerify(token, kms, { complete: true });

    await expect(awsKmsVerify(signedToken, kms)).resolves.toStrictEqual(
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

    await expect(awsKmsVerify(signedToken, kms)).resolves.toStrictEqual({
      header: {
        typ: 'JWT',
        kid,
        alg: 'RS256',
      },
      payload: {
        jti: 'static',
        iat: expect.any(Number),
        ...initialPayload,
      },
      signature: expect.any(String),
    });
  });

  test('AWS KMS Sign / Verify', async () => {});
});
