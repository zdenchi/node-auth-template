import { Request, Response, NextFunction } from 'express';
import { generateUsername } from 'unique-username-generator';
import { PrismaClient, Prisma } from '@prisma/client';
import { signToken } from '../utils/token';
import { hash, verify } from 'argon2';
import { PRIVATE_KEY } from '../config';
import { getUserData } from '../utils/getUserData';
import { user_status } from '@prisma/client';

const prisma = new PrismaClient();

const profileSelect = Prisma.validator<Prisma.profilesDefaultArgs>()({})
const userSelect = Prisma.validator<Prisma.usersDefaultArgs>()({})
export type Profile = Prisma.profilesGetPayload<typeof profileSelect>;
export type User = Prisma.usersGetPayload<typeof userSelect>;

const generateJWTTokens = async (user: User) => {
  const accessToken = await signToken({ id: user.id }, PRIVATE_KEY, {
    exp: '30m',
  });
  const refreshToken = await prisma.refresh_tokens.create({
    data: { user_id: user.id },
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
    const confirmPassword = req.body?.confirmPassword;
    const clientIP = req.ip;
    const clientUA = req.headers['user-agent'];
    const type = email ? 'email' : 'phone';

    if (!(email && phone) || !(password || confirmPassword)) {
      return res.status(400).json({ message: 'Bad Request' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Password mismatch' });
    }

    const user = await prisma.users.findFirst({
      where: { [type]: email || phone },
    });

    if (user) {
      return res.status(409).json({ message: 'User already exists.' });
    }

    const hashedPassword = await hash(password);
    const username = generateUsername('-', 3);
    const newUser = await prisma.users.create({
      data: {
        email,
        phone,
        password: hashedPassword,
        username,
        registration_ip: clientIP,
        registration_ua: clientUA,
        last_login_at: new Date().toISOString(),
        last_login_ip: clientIP,
        last_login_ua: clientUA,
      },
    }) as User;

    const { accessToken, refreshToken } = await generateJWTTokens(newUser);

    res.cookie('refresh-token', refreshToken, {
      path: '/',
      maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    });

    const profile = await prisma.profiles.findUnique({
      where: { id: newUser.id },
      ...profileSelect,
    }) as Profile;
    const userData = getUserData(newUser, profile);

    return res.status(200).json({ accessToken, user: userData });
  } catch (error: any) {
    console.log('[UserController](signup)', error.message);
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

    if (!(email && phone) || !password) {
      return res
        .status(400)
        .json({ message: 'Email or phone and password must be provided' });
    }

    const user = await prisma.users.findFirst({
      where: { [type]: email || phone },
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordCorrect = await verify(user.password, password);
    const isUserActive = user.status === user_status.ACTIVE;

    if (!isPasswordCorrect || !isUserActive) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const { accessToken, refreshToken } = await generateJWTTokens(user);

    await prisma.users.update({
      where: { id: user.id },
      data: {
        last_login_at: new Date().toISOString(),
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

    const profile = await prisma.profiles.findUnique({
      where: { id: user.id },
      ...profileSelect,
    }) as Profile;
    const userData = getUserData(user, profile);

    return res.status(200).json({ accessToken, user: userData });
  } catch (error: any) {
    console.log('[UserController](login)', error.message);
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
    console.log('[UserController](logout)', error.message);
    next(error);
  }
}
