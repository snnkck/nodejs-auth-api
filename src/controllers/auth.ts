import { NextFunction, Request, Response } from "express";
import { hashSync, compareSync } from "bcrypt";
import * as jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";
import * as crypto from "crypto";
import { sendEmail } from "../utils/email";
import {
  APIError,
  ValidationError,
  AuthenticationError,
  DuplicateEntryError,
  InvalidTokenError,
  DatabaseError
} from "../utils/errors";
import AppResponse from "../utils/response";
import { asyncHandler } from "../utils/async-handler";

export const signup = asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const { name, email, password } = req.body;
  
  // Tüm alanları doğrulama
  if (!name || !email || !password) {
    throw new ValidationError("Kayıt için lütfen tüm alanları doldurun!");
  }

  // Emailin formatı doğrumu?
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new ValidationError("Geçerli bir email adresi girin!", "email");
  }

  // Şifre validasyonu
  if (password.length < 6) {
    throw new ValidationError("Şifre en az 6 karakter olmalıdır!", "password");
  }

  try {
    // Kullanıcı kayıtlı mı kontrol et!
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      throw new DuplicateEntryError("Bu email adresi zaten kayıtlı!");
    }

    // Doğrulama token oluştur.
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Yeni kullanıcı oluştur
    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashSync(password, 10),
        emailVerified: false,
        emailVerificationToken: verificationToken,
        emailVerificationTokenExpiry: tokenExpiry
      }
    });

    // Doğrulama maili gönder
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    
    await sendEmail({
      to: email,
      subject: "Email Doğrulama",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #333;">Hoş geldiniz ${name}!</h2>
          <p>Email adresinizi doğrulamak için aşağıdaki linke tıklayın:</p>
          <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">
            Email Doğrula
          </a>
          <p><strong>Bu link 24 saat içinde geçerliliğini yitirecektir.</strong></p>
          <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
          <p style="color: #666; font-size: 14px;">
            Eğer buton çalışmıyorsa, bu linki tarayıcınıza kopyalayın:<br>
            <a href="${verificationUrl}">${verificationUrl}</a>
          </p>
        </div>
      `
    });

    // Hassas verileri kaldır!
    const { password: _, emailVerificationToken: __, ...userWithoutSensitiveData } = newUser;
    
    new AppResponse(
      userWithoutSensitiveData,
      "Kaydınızı onaylamak için lütfen mail adresinizi kontrol edin!"
    ).created(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Kullanıcı oluşturulurken bir hata oluştu");
  }
});

export const signin = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;
  
  // Validasyon
  if (!email || !password) {
    throw new ValidationError("Email ve şifre gereklidir");
  }

  try {
    // Kullanıcıyı bul
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      throw new AuthenticationError("Geçersiz email veya şifre!");
    }

    // Şifreyi kontrol et!
    if (!compareSync(password, user.password)) {
      throw new AuthenticationError("Geçersiz email veya şifre!");
    }

    // E-postanın doğrulanıp doğrulanmadığını kontrol et
    if (!user.emailVerified) {
      throw new AuthenticationError("Lütfen önce email adresinizi doğrulayın!");
    }

    // Token oluştur
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET!,
      { expiresIn: '24h' }
    );

    // Hassas bilgileri kaldır
    const { password: _, ...userWithoutPassword } = user;
    
    new AppResponse(
      { user: userWithoutPassword, token },
      "Giriş başarılı!"
    ).success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Giriş yapılırken bir hata oluştu");
  }
});

export const forgotPassword = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;
  
  if (!email) {
    throw new ValidationError("Email adresi gereklidir");
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email }
    });

    // Güvenlik: Her zaman aynı mesajı döndür

    const responseMessage = "Eğer email adresi sistemde kayıtlı ise, şifre sıfırlama linki gönderildi";

    if (!user) {
      new AppResponse(null, responseMessage).success(res);
      return;
    }

    // Reset token oluştur
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Reset token güncelle db de.
    await prisma.user.update({
      where: { email },
      data: {
        resetToken,
        resetTokenExpry: resetTokenExpiry,
      }
    });

    // Reset maili gönder.
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    
    await sendEmail({
      to: email,
      subject: "Şifre Sıfırlama",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #333;">Şifre Sıfırlama</h2>
          <p>Şifrenizi sıfırlamak için aşağıdaki linke tıklayın:</p>
          <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">
            Şifre Sıfırla
          </a>
          <p><strong>Bu link 10 dakika içinde geçerliliğini yitirecektir.</strong></p>
          <p>Eğer bu işlemi siz yapmadıysanız, bu emaili görmezden gelin.</p>
        </div>
      `
    });

    new AppResponse(null, responseMessage).success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Şifre sıfırlama işlemi sırasında bir hata oluştu");
  }
});

export const resetPassword = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { token, newPassword } = req.body;
  
  if (!token || !newPassword) {
    throw new ValidationError("Token ve yeni şifre gereklidir");
  }

  if (newPassword.length < 6) {
    throw new ValidationError("Şifre en az 6 karakter olmalıdır");
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpry: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      throw new InvalidTokenError("Geçersiz veya süresi dolmuş token");
    }

    // Şifreyi güncelle ve reset tokeni null yap.
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashSync(newPassword, 10),
        resetToken: null,
        resetTokenExpry: null
      }
    });

    new AppResponse(null, "Şifre başarıyla sıfırlandı").success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Şifre sıfırlama işlemi sırasında bir hata oluştu");
  }
});

export const verifyEmail = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { token } = req.body;

  if (!token) {
    throw new ValidationError("Doğrulama token'ı gereklidir");
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        emailVerificationToken: token,
        emailVerified: false,
        emailVerificationTokenExpiry: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      throw new InvalidTokenError("Geçersiz veya süresi dolmuş doğrulama token'ı");
    }

    // Doğrulama maili gönder onayla ve email onaylama tokenini null yap.
    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationToken: null,
        emailVerificationTokenExpiry: null
      }
    });

    // Otomatik oturum açma için token oluştur.
    const authToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    );

    const { password: _, ...userWithoutPassword } = user;
    
    new AppResponse(
      { 
        user: { ...userWithoutPassword, emailVerified: true },
        token: authToken 
      },
      "Email başarıyla doğrulandı!"
    ).success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Email doğrulama işlemi sırasında bir hata oluştu");
  }
});

export const protectedRoute = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  res.json({
    succes: true,
    message: "Korumalı route ok!",
    user: req.user
  })
});