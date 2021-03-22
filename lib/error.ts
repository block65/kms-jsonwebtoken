import { CustomError } from '@block65/custom-error';

export class KmsJsonWebTokenError extends CustomError {
  constructor(msg: string, previous?: Error) {
    super(msg, previous);
    this.setName('KmsJsonWebTokenError');
  }
}
