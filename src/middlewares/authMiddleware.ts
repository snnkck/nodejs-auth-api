import { Request, Response, NextFunction } from "express";
import APIError from "../utils/errors";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

// JWT payload interface'i - mevcut token yapınıza uygun
interface JWTPayload {
  userId: number;  // sub yerine userId kullanıyorsunuz
  iat?: number;
  exp?: number;
  [key: string]: any;
}

// User info interface'i (Prisma User modelinden)
interface UserInfo {
  id: number;
  name: string;
  email: string;
}

// Request interface'ini extend et
declare global {
  namespace Express {
    interface Request {
      user?: UserInfo;
    }
  }
}

const tokenCheck = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Authorization header kontrolü
    const headerToken = req.headers.authorization && req.headers.authorization.startsWith("Bearer ");
    if (!headerToken) {
      throw new APIError("Geçersiz Oturum Lütfen Oturum Açın", 401);
    }

    // Token'ı ayır
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new APIError("Authorization header bulunamadı", 401);
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      throw new APIError("Token bulunamadı", 401);
    }

    // JWT_SECRET kontrolü
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new APIError("JWT_SECRET yapılandırılmamış", 500);
    }

    // Token'ı doğrula
    const decoded = jwt.verify(token, jwtSecret) as JWTPayload;

    // JWT payload kontrolü - userId field'ini kontrol et
    if (!decoded || !decoded.userId) {
      throw new APIError("Geçersiz Token - Kullanıcı ID bulunamadı", 401);
    }

    // User ID'yi number olarak al (zaten number olmalı)
    const userId = decoded.userId;
    if (typeof userId !== 'number' || isNaN(userId)) {
      throw new APIError("Geçersiz Token - Kullanıcı ID formatı hatalı", 401);
    }

    // User bilgilerini Prisma ile al
    const userInfo = await prisma.user.findUnique({
      where: {
        id: userId
      },
      select: {
        id: true,
        name: true,
        email: true
      }
    });

    if (!userInfo) {
      throw new APIError("Geçersiz Token - Kullanıcı bulunamadı", 401);
    }

    // User bilgilerini request'e ekle
    req.user = {
      id: userInfo.id,
      name: userInfo.name,
      email: userInfo.email
    };

    next();
  } catch (error) {
    // JWT hataları
    if (error instanceof jwt.JsonWebTokenError) {
      return next(new APIError("Geçersiz Token - JWT hatası", 401));
    }
    if (error instanceof jwt.TokenExpiredError) {
      return next(new APIError("Token süresi dolmuş", 401));
    }
    if (error instanceof jwt.NotBeforeError) {
      return next(new APIError("Token henüz aktif değil", 401));
    }

    // Prisma hataları
    if (error instanceof Error) {
      if (error.name === 'PrismaClientValidationError') {
        return next(new APIError("Geçersiz Token - Veritabanı doğrulama hatası", 401));
      }
      if (error.name === 'PrismaClientKnownRequestError') {
        return next(new APIError("Veritabanı hatası", 500));
      }
    }

    // APIError'ları olduğu gibi geçir
    if (error instanceof APIError) {
      return next(error);
    }

    // Diğer hatalar
    console.error('Token middleware unexpected error:', error);
    next(new APIError("Beklenmedik hata", 500));
  }
};

export default tokenCheck;