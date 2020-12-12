import * as AWS from 'aws-sdk';
import * as crypto from 'crypto';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const KMS = jest.fn().mockImplementation(() => ({
  sign: jest.fn(({ Message }: { Message: Buffer }) => {
    return {
      async promise(): Promise<AWS.KMS.Types.SignResponse> {
        return {
          Signature: crypto.sign('sha256', Message, {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING,
          }),
          SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
        };
      },
    };
  }),
  getPublicKey: jest.fn(() => {
    return {
      async promise(): Promise<AWS.KMS.Types.GetPublicKeyResponse> {
        return {
          PublicKey: publicKey.export({ format: 'der', type: 'spki' }),
          KeyUsage: 'SIGN_VERIFY',
          CustomerMasterKeySpec: 'RSA_2048',
        };
      },
    };
  }),
}));

export = { ...AWS, KMS };
