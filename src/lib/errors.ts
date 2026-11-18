export const ErrorCodes = {
    // Auth
    AUTH_INVALID_CREDENTIALS: 'AUTH_INVALID_CREDENTIALS',
    AUTH_UNAUTHORIZED: 'AUTH_UNAUTHORIZED',
    AUTH_INVALID_TOKEN_TYPE: 'AUTH_INVALID_TOKEN_TYPE',
    AUTH_EMAIL_NOT_VERIFIED: 'AUTH_EMAIL_NOT_VERIFIED',
    AUTH_ACCOUNT_NOT_ACTIVE: 'AUTH_ACCOUNT_NOT_ACTIVE',
    AUTH_EMAIL_TAKEN: 'AUTH_EMAIL_TAKEN',
    AUTH_INVALID_TOKEN: 'AUTH_INVALID_TOKEN',
    AUTH_VALIDATION_FAILED: 'AUTH_VALIDATION_FAILED',
    AUTH_ACCOUNT_LOCKED: 'AUTH_ACCOUNT_LOCKED',
    AUTH_ACCOUNT_DISABLED: 'AUTH_ACCOUNT_DISABLED',
  
    // Users / generic
    USER_NOT_FOUND: 'USER_NOT_FOUND',
    SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
    BAD_REQUEST: 'BAD_REQUEST',
    INTERNAL_ERROR: 'INTERNAL_ERROR',
  } as const;
  
  export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
  
  export class AppError extends Error {
    readonly code: ErrorCode;
    readonly statusCode: number;
  
    constructor(code: ErrorCode, message: string, statusCode: number) {
      super(message);
      this.name = 'AppError';
      this.code = code;
      this.statusCode = statusCode;
    }
  }