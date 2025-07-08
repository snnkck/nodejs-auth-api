export enum ErrorCodes {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR',
  NOT_FOUND = 'NOT_FOUND',
  DUPLICATE_ENTRY = 'DUPLICATE_ENTRY',
  DATABASE_ERROR = 'DATABASE_ERROR',
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  INVALID_TOKEN = 'INVALID_TOKEN'
}

export class APIError extends Error {
  public readonly statusCode: number;
  public readonly errorCode: ErrorCodes;
  public readonly isOperational: boolean;
  public readonly timestamp: Date;
  public readonly details?: any;

  constructor(
    message: string,
    statusCode: number = 400,
    errorCode: ErrorCodes = ErrorCodes.INTERNAL_SERVER_ERROR,
    details?: any
  ) {
    super(message);
    this.name = 'APIError';
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.isOperational = true;
    this.timestamp = new Date()

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, APIError);
    }
  }

  public toJSON() {
    return {
      name: this.name,
      message: this.message,
      statusCode: this.statusCode,
      errorCode: this.errorCode,
      timestamp: this.timestamp,
      details: this.details
    };
  }
}

// Specific error classes
export class ValidationError extends APIError {
  constructor(message: string, field?: string) {
    super(message, 400, ErrorCodes.VALIDATION_ERROR, { field });
  }
}

export class AuthenticationError extends APIError {
  constructor(message: string = "Kimlik doğrulama hatası") {
    super(message, 401, ErrorCodes.AUTHENTICATION_ERROR);
  }
}

export class AuthorizationError extends APIError {
  constructor(message: string = "Yetki hatası") {
    super(message, 403, ErrorCodes.AUTHORIZATION_ERROR);
  }
}

export class NotFoundError extends APIError {
  constructor(resource: string = "Kaynak") {
    super(`${resource} bulunamadı`, 404, ErrorCodes.NOT_FOUND);
  }
}

export class DuplicateEntryError extends APIError {
  constructor(message: string) {
    super(message, 409, ErrorCodes.DUPLICATE_ENTRY);
  }
}

export class DatabaseError extends APIError {
  constructor(message: string = "Veritabanı hatası") {
    super(message, 500, ErrorCodes.DATABASE_ERROR);
  }
}

export class TokenExpiredError extends APIError {
  constructor(message: string = "Token süresi dolmuş") {
    super(message, 401, ErrorCodes.TOKEN_EXPIRED);
  }
}

export class InvalidTokenError extends APIError {
  constructor(message: string = "Geçersiz token") {
    super(message, 401, ErrorCodes.INVALID_TOKEN);
  }
}

export class RateLimitError extends APIError {
  constructor(message: string = "Rate limit aşıldı") {
    super(message, 429, ErrorCodes.RATE_LIMIT_EXCEEDED);
  }
}

export default APIError;