export const KeyManagementServiceClient = jest.fn().mockImplementation(() => ({
  cryptoKeyVersionPath: jest
    .fn()
    .mockReturnValue((...args: string[]) => args.join('/')),
  // asymmetricSign: jest.fn(
  //   async (
  //     request: protos.google.cloud.kms.v1.IAsymmetricSignRequest & {
  //       _message: Buffer;
  //     },
  //   ): Promise<[protos.google.cloud.kms.v1.IAsymmetricSignResponse]> => {
  //     if (!request.digest?.sha256) {
  //       throw new Error('missing sha256 digest');
  //     }
  //
  //     if (typeof request.digest.sha256 === 'string') {
  //       throw new Error('sha256 digest is not a buffer');
  //     }
  //
  //     // WARN: Nodejs wants the whole message but GCP wants the hash
  //     // So we do a little dance here to allow us to test properly
  //
  //     // eslint-disable-next-line no-underscore-dangle
  //     const message = request._message;
  //
  //     if (!message) {
  //       throw new Error('Missing _message');
  //     }
  //
  //     const doubleCheckDigest = crypto.createHash('sha256');
  //     doubleCheckDigest.update(message);
  //
  //     if (
  //       Buffer.compare(doubleCheckDigest.digest(), request.digest.sha256) !== 0
  //     ) {
  //       throw new Error('_message digest differs');
  //     }
  //
  //     const signature = crypto.sign('sha256', message, {
  //       key: privateKey,
  //       padding: crypto.constants.RSA_PKCS1_PADDING,
  //     });
  //
  //     const verified = crypto.verify(
  //       'sha256',
  //       request.digest.sha256,
  //       publicKey,
  //       signature,
  //     );
  //
  //     return [
  //       {
  //         signature,
  //       },
  //     ];
  //   },
  // ),
  // getPublicKey: jest.fn(
  //   async (): /* request: protos.google.cloud.kms.v1.IGetPublicKeyRequest, */
  //   Promise<[protos.google.cloud.kms.v1.IPublicKey]> => {
  //     return [
  //       {
  //         pem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  //         algorithm: 'RSA_SIGN_PKCS1_2048_SHA256',
  //       },
  //     ];
  //   },
  // ),
}));
