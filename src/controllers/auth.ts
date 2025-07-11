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
import { OAuth2Client } from 'google-auth-library';

// Google OAuth client
const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  `${process.env.BACKEND_URL}/api/auth/google/callback`
);

// Token oluşturma yardımcı fonksiyonu
const generateTokens = (userId: number) => {
  const accessToken = jwt.sign(
    { userId, type: 'access' },
    process.env.JWT_SECRET!,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET!,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

// Google OAuth URL oluşturma
export const getGoogleAuthUrl = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const state = crypto.randomBytes(16).toString('hex');

  console.log('OAuth2Client redirect URI:', `${process.env.BACKEND_URL}/api/auth/google/callback`);

  const authUrl = googleClient.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email'],
    state: state,
    prompt: 'select_account'
  });

  new AppResponse(
    { authUrl, state },
    "Google OAuth URL oluşturuldu"
  ).success(res);
});

// Google OAuth callback
export const googleAuthCallback = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { code, state } = req.body;

  if (!code) {
    throw new ValidationError("Authorization code gereklidir");
  }

  try {
    // Token al
    const { tokens } = await googleClient.getToken(code);
    googleClient.setCredentials(tokens);

    // Kullanıcı bilgilerini al
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token!,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    
    if (!payload) {
      throw new AuthenticationError("Google token doğrulanamadı");
    }

    const { email, name, picture, sub: googleId } = payload;

    if (!email) {
      throw new ValidationError("Google hesabından email alınamadı");
    }

    // Kullanıcı var mı kontrol et
    let user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: email },
          { googleId: googleId }
        ]
      }
    });

    if (user) {
      // Kullanıcı var, Google ID'yi güncelle (yoksa)
      if (!user.googleId) {
        user = await prisma.user.update({
          where: { id: user.id },
          data: {
            googleId: googleId,
            avatar: picture || user.avatar,
            emailVerified: true // Google ile giriş yapanlar otomatik doğrulanır
          }
        });
      }
    } else {
      // Yeni kullanıcı oluştur
      user = await prisma.user.create({
        data: {
          name: name || 'Google User',
          email: email,
          googleId: googleId,
          avatar: picture,
          emailVerified: true,
          password: hashSync(crypto.randomBytes(32).toString('hex'), 10) // Rastgele şifre
        }
      });
    }

    // JWT tokenları oluştur
    const { accessToken, refreshToken } = generateTokens(user.id);

    // Refresh token'ı veritabanında sakla
    const refreshTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 gün

    await prisma.user.update({
      where: { id: user.id },
      data: {
        refreshToken,
        refreshTokenExpiry
      }
    });

    const { password: _, ...userWithoutPassword } = user;
    
    new AppResponse(
      { 
        user: userWithoutPassword, 
        accessToken,
        refreshToken 
      },
      "Google ile giriş başarılı!"
    ).success(res);

  } catch (error) {
    console.error('Google OAuth Error:', error);
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Google ile giriş yapılırken bir hata oluştu");
  }
});

export const googleAuthCallbackGET = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { code, state } = req.query;

  if (!code) {
    throw new ValidationError("Authorization code gereklidir");
  }

  try {
    const { tokens } = await googleClient.getToken(code as string);
    googleClient.setCredentials(tokens);

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token!,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    if (!payload) throw new AuthenticationError("Google token doğrulanamadı");

    const { email, name, picture, sub: googleId } = payload;

    if (!email) {
      throw new ValidationError("Google hesabından email alınamadı");
    }

    let user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: email },
          { googleId: googleId }
        ]
      }
    });

    if (user) {
      if (!user.googleId) {
        user = await prisma.user.update({
          where: { id: user.id },
          data: {
            googleId: googleId,
            avatar: picture || user.avatar,
            emailVerified: true
          }
        });
      }
    } else {
      user = await prisma.user.create({
        data: {
          name: name || 'Google User',
          email: email,
          googleId: googleId,
          avatar: picture,
          emailVerified: true,
          password: hashSync(crypto.randomBytes(32).toString('hex'), 10)
        }
      });
    }

    const { accessToken, refreshToken } = generateTokens(user.id);
    const refreshTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        refreshToken,
        refreshTokenExpiry
      }
    });

    // frontend'e token ile redirect et
    res.status(200).json({
      accessToken: accessToken,
      refreshToken: refreshToken
    });

  } catch (error) {
    console.error("Google Callback GET error:", error);
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Google ile giriş yapılırken bir hata oluştu");
  }
});


// Google hesabı bağlama (mevcut kullanıcı için)
export const linkGoogleAccount = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { code } = req.body;
  const userId = req.user?.id;

  if (!userId) {
    throw new AuthenticationError("Kullanıcı kimlik doğrulaması gerekli");
  }

  if (!code) {
    throw new ValidationError("Authorization code gereklidir");
  }

  try {
    // Token al
    const { tokens } = await googleClient.getToken(code);
    googleClient.setCredentials(tokens);

    // Kullanıcı bilgilerini al
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token!,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    
    if (!payload) {
      throw new AuthenticationError("Google token doğrulanamadı");
    }

    const { email, sub: googleId } = payload;

    // Bu Google hesabı başka bir kullanıcıda kayıtlı mı?
    const existingUser = await prisma.user.findFirst({
      where: {
        googleId: googleId,
        id: { not: userId }
      }
    });

    if (existingUser) {
      throw new DuplicateEntryError("Bu Google hesabı başka bir kullanıcıya bağlı");
    }

    // Mevcut kullanıcıya Google hesabını bağla
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        googleId: googleId,
        avatar: payload.picture || undefined
      }
    });

    const { password: _, ...userWithoutPassword } = updatedUser;
    
    new AppResponse(
      userWithoutPassword,
      "Google hesabı başarıyla bağlandı!"
    ).success(res);

  } catch (error) {
    console.error('Google Link Error:', error);
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Google hesabı bağlanırken bir hata oluştu");
  }
});

// Google hesabı bağlantısını kaldırma
export const unlinkGoogleAccount = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const userId = req.user?.id;

  if (!userId) {
    throw new AuthenticationError("Kullanıcı kimlik doğrulaması gerekli");
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      throw new AuthenticationError("Kullanıcı bulunamadı");
    }

    // Şifre yoksa Google hesabını kaldırmaya izin verme
    if (!user.password && user.googleId) {
      throw new ValidationError("Google hesabını kaldırmadan önce bir şifre belirleyin");
    }

    // Google bağlantısını kaldır
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        googleId: null
      }
    });

    const { password: _, ...userWithoutPassword } = updatedUser;
    
    new AppResponse(
      userWithoutPassword,
      "Google hesabı bağlantısı kaldırıldı!"
    ).success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Google hesabı bağlantısı kaldırılırken bir hata oluştu");
  }
});

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
  
  if (!email || !password) {
    throw new ValidationError("Email ve şifre gereklidir");
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      throw new AuthenticationError("Geçersiz email veya şifre!");
    }

    if (!compareSync(password, user.password)) {
      throw new AuthenticationError("Geçersiz email veya şifre!");
    }

    if (!user.emailVerified) {
      throw new AuthenticationError("Lütfen önce email adresinizi doğrulayın!");
    }

    console.log(user.id,"user.id::::::",typeof(user.id));
    

    // Access ve Refresh token oluştur
    const { accessToken, refreshToken } = generateTokens(user.id);

    console.log("accessToken::",accessToken);
    console.log("refreshToken:::", refreshToken);
    
    
    // Refresh token'ı veritabanında sakla
    const refreshTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 gün

    await prisma.user.update({
      where: { id: user.id },
      data: {
        refreshToken,
        refreshTokenExpiry
      }
    });

    const { password: _, ...userWithoutPassword } = user;
    
    new AppResponse(
      { 
        user: userWithoutPassword, 
        accessToken,
        refreshToken 
      },
      "Giriş başarılı!"
    ).success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Giriş yapılırken bir hata oluştu");
  }
});

// Yeni token alma endpoint'i
export const refreshToken = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new ValidationError("Refresh token gereklidir");
  }

  try {
    // Refresh token'ı doğrula
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as any;
    
    if (decoded.type !== 'refresh') {
      throw new InvalidTokenError("Geçersiz token tipi");
    }

    // Veritabanından kullanıcı ve token kontrol et
    const user = await prisma.user.findFirst({
      where: {
        id: decoded.userId,
        refreshToken: refreshToken,
        refreshTokenExpiry: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      throw new InvalidTokenError("Geçersiz veya süresi dolmuş refresh token");
    }

    // Yeni tokenlar oluştur
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user.id);

    // Yeni refresh token'ı veritabanında güncelle
    const newRefreshTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    await prisma.user.update({
      where: { id: user.id },
      data: {
        refreshToken: newRefreshToken,
        refreshTokenExpiry: newRefreshTokenExpiry
      }
    });

    new AppResponse(
      { 
        accessToken,
        refreshToken: newRefreshToken
      },
      "Token yenilendi"
    ).success(res);

  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new InvalidTokenError("Geçersiz refresh token");
    }
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Token yenileme sırasında bir hata oluştu");
  }
});

// Logout fonksiyonu
export const logout = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new ValidationError("Refresh token gereklidir");
  }

  try {
    // Refresh token'ı veritabanından sil
    await prisma.user.updateMany({
      where: { refreshToken },
      data: {
        refreshToken: null,
        refreshTokenExpiry: null
      }
    });

    new AppResponse(null, "Çıkış yapıldı").success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Çıkış yapılırken bir hata oluştu");
  }
});

// Tüm oturumları sonlandırma
export const logoutAllDevices = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const userId = req.user?.id;

  if (!userId) {
    throw new AuthenticationError("Kullanıcı kimlik doğrulaması gerekli");
  }

  try {
    await prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: null,
        refreshTokenExpiry: null
      }
    });

    new AppResponse(null, "Tüm cihazlardan çıkış yapıldı").success(res);

  } catch (error) {
    if (error instanceof APIError) {
      throw error;
    }
    throw new DatabaseError("Çıkış yapılırken bir hata oluştu");
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