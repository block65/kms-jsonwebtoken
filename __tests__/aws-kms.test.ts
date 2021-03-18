import {
  GetPublicKeyCommand,
  GetPublicKeyResponse,
  KMSClient,
  SignCommand,
  SignRequest,
  SignResponse,
} from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
import * as crypto from 'crypto';
import { awsKmsSign, awsKmsVerify } from '../lib';

const mockKmsClient = mockClient(KMSClient);

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

mockKmsClient.on(SignCommand).callsFake(
  async ({ Message }: SignRequest): Promise<SignResponse> => {
    if (!Message) {
      throw new Error('Empty Message');
    }

    return {
      Signature: crypto.sign('sha256', Message, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      }),
      SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
    };
  },
);

mockKmsClient.on(GetPublicKeyCommand).callsFake(
  async (): Promise<GetPublicKeyResponse> => {
    return {
      PublicKey: publicKey.export({ format: 'der', type: 'spki' }),
      KeyUsage: 'SIGN_VERIFY',
      CustomerMasterKeySpec: 'RSA_2048',
    };
  },
);

describe('Basic Tests', () => {
  test('AWS KMS Sign / Verify', async () => {
    const kms = new KMSClient({});

    const kid = '46572b82-7181-494e-bd11-95152094cc27';

    async function resolveKeyId(id: string) {
      return `arn:aws:kms:us-east-1:123456789012:key/${id}`;
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
  }, 30000);
});
