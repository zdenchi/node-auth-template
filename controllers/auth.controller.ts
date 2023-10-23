import { Request, Response, NextFunction } from 'express';
import { generateUsername } from 'unique-username-generator';
import { PrismaClient, Prisma } from '@prisma/client';
import { signToken } from '../utils/token';
import { hash } from 'argon2';
import { PRIVATE_KEY } from '../config';
import { getUserData } from '../utils/getUserData';

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
