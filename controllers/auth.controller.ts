import { Request, Response, NextFunction } from 'express';
import { generateUsername } from 'unique-username-generator';
import { PrismaClient, Prisma } from '@prisma/client';
import { signToken, generateAndEncryptToken, decryptToken } from '../utils/token';
import * as argon2 from "argon2";
import { user_status } from '@prisma/client';
import { sendEmail, sendSMS } from '../utils/sender';

const prisma = new PrismaClient();

export const userSelect = Prisma.validator<Prisma.usersDefaultArgs>()({
  select: {
    id: true,
    email: true,
    phone: true,
    username: true,
    email_verified_at: true,
    phone_verified_at: true,
    role: true,
    profiles: {
      select: {
        firstname: true,
        lastname: true,
        middlename: true,
        birthday: true,
        gender: true,
        country: true,
        city: true,
      }
    }
  },
})
const userSelectWithPassword = Prisma.validator<Prisma.usersDefaultArgs>()({
  select: {
    ...userSelect.select,
    password: true,
  },
})
export type User = Prisma.usersGetPayload<typeof userSelect>;
export type UserWithPassword = Prisma.usersGetPayload<typeof userSelectWithPassword>;

const generateJWTTokens = async (userId: number, refreshTokenParent: string | null = null) => {
  const accessToken = await signToken({ id: userId }, { exp: '15m' });
  const refreshToken = await prisma.refresh_tokens.create({
    data: { user_id: userId, parent: refreshTokenParent },
    select: { id: true },
  });
  return {
    accessToken,
    refreshToken: refreshToken.id,
  };
};

export const signup = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const email = req.body?.email || null;
    const phone = req.body?.phone || null;
    const password = req.body?.password;
    const clientIP = req.ip;
    const clientUA = req.headers['user-agent'];
    const type = email ? 'email' : 'phone';

    const user = await prisma.users.findFirst({
      where: { [type]: email || phone },
    });

    if (user) {
      return res.status(409).json({ message: 'User already exists.' });
    }

    const hashedPassword = await argon2.hash(password);
    const username = generateUsername('-', 3);
    const newUser: any = await prisma.users.create({
      data: {
        email,
        phone,
        password: hashedPassword,
        username,
        registration_ip: clientIP,
        registration_ua: clientUA,
        last_login_at: new Date(),
        last_login_ip: clientIP,
        last_login_ua: clientUA,
      },
      ...userSelectWithPassword,
    });
    delete newUser.password

    const { accessToken, refreshToken } = await generateJWTTokens(newUser.id);

    res.cookie('refresh-token', refreshToken, {
      path: '/',
      maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    });

    return res.status(200).json({ accessToken, user: newUser });
  } catch (error: any) {
    console.log('[AuthController](signup)', error.message);
    next(error);
  }
}

export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const email = req.body?.email || null;
    const phone = req.body?.phone || null;
    const password = req.body?.password;
    const clientIP = req.ip;
    const clientUA = req.get('User-Agent');
    const type = email ? 'email' : 'phone';

    const user: any = await prisma.users.findFirst({
      where: {
        [type]: email || phone,
        status: user_status.ACTIVE,
      },
      ...userSelectWithPassword
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordCorrect = await argon2.verify(user.password, password);

    if (!isPasswordCorrect) {
      return res.status(401).json({ message: 'Unauthorized' });
    } else {
      delete user.password;
    }

    const { accessToken, refreshToken } = await generateJWTTokens(user.id);

    await prisma.users.update({
      where: { id: user.id },
      data: {
        last_login_at: new Date(),
        last_login_ip: clientIP,
        last_login_ua: clientUA,
      },
    });

    res.cookie('refresh-token', refreshToken, {
      path: '/',
      maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    });

    return res.status(200).json({ accessToken, user });
  } catch (error: any) {
    console.log('[AuthController](login)', error.message);
    next(error);
  }
}

export const logout = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const refreshToken = req.cookies['refresh-token'];

    if (!refreshToken) {
      return res.status(400).json({ message: 'Bad Request' });
    }

    await prisma.refresh_tokens.update({
      where: { id: refreshToken },
      data: { revoked: true },
    });
    res.clearCookie('refresh-token');
    return res.status(200).json({ message: 'Logout successful' });
  } catch (error: any) {
    console.log('[AuthController](logout)', error.message);
    next(error);
  }
}

export const refreshTokens = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const tokenId = req.cookies['refresh-token'];

    if (!tokenId) {
      return res.status(401).json({ message: 'No refresh token' });
    }

    const session = await prisma.refresh_tokens.update({
      where: { id: tokenId, revoked: false },
      data: { revoked: true },
      select: { user_id: true },
    });

    if (!session || !session.user_id) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const { accessToken, refreshToken } = await generateJWTTokens(session.user_id, tokenId);

    res.cookie('refresh-token', refreshToken, {
      path: '/',
      maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    });

    return res.status(200).json({ accessToken });
  } catch (error: any) {
    console.log('[AuthController](refreshTokens)', error.message);
    next(error);
  }
}

export const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const email = req.body?.email || null;
    const phone = req.body?.phone || null;
    const type = email ? 'email' : 'phone';

    const user = await prisma.users.findFirst({
      where: { [type]: email || phone },
    });

    if (!user) return res.status(200).send('OK');

    let { recovery_token, recovery_token_expire } = user;
    let { token, encryptedToken } = generateAndEncryptToken(null);

    const tokenExpire = recovery_token_expire ? new Date(recovery_token_expire) : new Date();
    const isTokenExpire = tokenExpire.getTime() <= new Date().getTime();

    if (!isTokenExpire && recovery_token) {
      encryptedToken = recovery_token;
      token = decryptToken(recovery_token);
    }

    await prisma.users.update({
      where: { id: user.id },
      data: {
        recovery_token: encryptedToken,
        recovery_token_expire: new Date(Date.now() + 3600000),
      },
    });

    if (email) {
      const response = await sendEmail({
        to: email,
        subject: 'Відновлення паролю',
        template: 'confirm-mail',
        variables: {
          MAIN_TEXT: "Ваш запит на відновлення паролю отримано. Натисніть на посилання нижче або скористайтеся кодом підтвердження, щоб встановити новий пароль.",
          BUTTON_TEXT: "Змінити пароль",
          TOKEN: token,
          CONFIRM_URL: `https://${process.env.ALLOWED_ORIGIN}/auth/reset-password?hash=${encryptedToken}`
        }
      });
    } else {
      const response = await sendSMS({ to: phone, text: `Код підтвердження: ${token}` });
    }

    return res.status(200).send('OK');
  } catch (error: any) {
    console.log('[AuthController](forgotPassword)', error.message);
    next(error);
  }
}

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    let hash = req.body?.hash;
    const token = req.body?.token;
    const password = req.body?.password;
    const clientIP = req.ip;
    const clientUA = req.get('User-Agent');

    if (!hash) {
      const { encryptedToken } = generateAndEncryptToken(token);
      hash = encryptedToken;
    }

    const user = await prisma.users.findFirst({
      where: {
        recovery_token: hash as string,
        recovery_token_expire: { gt: new Date() },
      },
      ...userSelect
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid token' });
    }

    const hashedPassword = await argon2.hash(password);

    await prisma.users.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        recovery_token: null,
        recovery_token_expire: null,
        last_login_at: new Date(),
        last_login_ip: clientIP,
        last_login_ua: clientUA,
      },
    });

    const { accessToken, refreshToken } = await generateJWTTokens(user.id);

    res.cookie('refresh-token', refreshToken, {
      path: '/',
      maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    });

    return res.status(200).json({ accessToken, user });
  } catch (error: any) {
    console.log('[AuthController](resetPassword)', error.message);
    next(error);
  }
}
