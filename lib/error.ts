import { CustomError, Status } from '@block65/custom-error';

export class KmsJsonWebTokenError extends CustomError {
  public code = Status.INVALID_ARGUMENT;
}
