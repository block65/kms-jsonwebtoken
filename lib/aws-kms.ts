import * as jsonwebtoken from 'jsonwebtoken';
import { KMS } from 'aws-sdk';
import { sign } from './sign';
import { verify } from './verify';

export async function awsKmsSign(
  payload: string | Buffer | object,
  kms: KMS,
  options: Omit<jsonwebtoken.SignOptions, 'algorithm'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  },
) {
  const { resolveKeyId, ...jwtOptions } = options;

  return sign(
    payload,
    async (header, { keyid }) => {
      if (!keyid) {
        throw new Error('Missing Key Id in Header');
      }

      const keyId = await (resolveKeyId ? resolveKeyId(keyid) : keyid);

      const signatureResult = await kms
        .sign({
          KeyId: keyId,
          MessageType: 'RAW',
          Message: header,
          SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
        })
        .promise();

      if (!Buffer.isBuffer(signatureResult.Signature)) {
        throw new Error('Incompatible signature');
      }

      return signatureResult.Signature;
    },
    jwtOptions,
  );
}

export async function awsKmsVerify(
  token: string,
  kms: KMS,
  options: Omit<jsonwebtoken.VerifyOptions, 'algorithms'> & {
    resolveKeyId?: (kid: string) => string | Promise<string>;
  } = {},
): Promise<object> {
  const { resolveKeyId, ...jwtOptions } = options;

  return verify(
    token,
    async (header) => {
      if (header.alg !== 'RS256') {
        throw new Error('Header alg is not RS256');
      }

      if (!header.kid) {
        throw new Error('Missing Key Id in Header');
      }

      const keyId = await (resolveKeyId
        ? resolveKeyId(header.kid)
        : header.kid);

      const publicKey = await kms.getPublicKey({ KeyId: keyId }).promise();

      if (!publicKey.PublicKey) {
        throw new Error('Missing Public Key');
      }

      if (
        publicKey.KeyUsage !== 'SIGN_VERIFY' ||
        !publicKey.CustomerMasterKeySpec?.startsWith('RSA') ||
        !Buffer.isBuffer(publicKey.PublicKey)
      ) {
        throw new Error('Incompatible Public Key');
      }

      // console.log(publicKey.PublicKey.toString('base64'));

      const pubKeyStr = publicKey.PublicKey.toString('base64');
      return `-----BEGIN PUBLIC KEY-----\n${pubKeyStr}\n-----END PUBLIC KEY-----`;
    },
    jwtOptions,
  );
}
