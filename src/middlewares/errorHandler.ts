import { Request, Response, NextFunction } from 'express';
import { APIError } from '../utils/errors';
import AppResponse from '../utils/response';

const errorHandlerMiddleware = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  console.error('Error occurred:', {
    name: error.name,
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toLocaleString("tr-TR", {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false
        })
  });

  // APIError instance ise
  if (error instanceof APIError) {
    AppResponse.error(
      res,
      error.statusCode,
      error.message,
      error.errorCode,
      error.details
    );
    return;
  }

  // Prisma errors
  if (error.name === 'PrismaClientKnownRequestError') {
    const prismaError = error as any;
    
    // Unique constraint violation
    if (prismaError.code === 'P2002') {
      AppResponse.error(
        res,
        409,
        'Bu kayıt zaten mevcut',
        'DUPLICATE_ENTRY',
        { field: prismaError.meta?.target }
      );
      return;
    }
    
    // Kayıt bulunamadı
    if (prismaError.code === 'P2025') {
      AppResponse.error(
        res,
        404,
        'Kayıt bulunamadı',
        'NOT_FOUND'
      );
      return;
    }
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    AppResponse.error(
      res,
      401,
      'Geçersiz token',
      'INVALID_TOKEN'
    );
    return;
  }

  if (error.name === 'TokenExpiredError') {
    AppResponse.error(
      res,
      401,
      'Token süresi dolmuş',
      'TOKEN_EXPIRED'
    );
    return;
  }

  // Doğrulama errors
  if (error.name === 'ValidationError') {
    AppResponse.error(
      res,
      400,
      error.message,
      'VALIDATION_ERROR'
    );
    return;
  }

  // Default error
  AppResponse.error(
    res,
    500,
    process.env.NODE_ENV === 'development' ? error.message : 'İç sunucu hatası',
    'INTERNAL_SERVER_ERROR',
    process.env.NODE_ENV === 'development' ? error.stack : undefined
  );
};

export default errorHandlerMiddleware;