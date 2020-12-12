function toBase64Url(buff: Buffer): string {
  return Buffer.from(buff)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function fromBase64Url(encoded: string): Buffer {
  return Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
