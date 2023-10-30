import { Response, NextFunction } from 'express';
import { PrismaClient, Prisma } from '@prisma/client';
import { AuthRequest } from '../types';
import { userSelect } from './auth.controller';
import * as argon2 from "argon2";
import { generateAndEncryptToken, decryptToken } from '../utils/token';
import { sendEmail, sendSMS } from '../utils/sender';
import { VerificationType } from '../types';

const prisma = new PrismaClient();

export const getUser = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const id = req.userId;
    const user = await prisma.users.findUnique({
      where: { id },
      ...userSelect
    });

    if (!user) {
      return res.status(404).send('User not found');
    }

    res.status(200).json(user);
  } catch (error: any) {
    console.log('[UserController](getUser)', error.message);
    next(error);
  }
};

export const changePassword = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const id = req.userId;
    const oldPassword = req.body?.oldPassword;
    const newPassword = req.body?.newPassword;

    const user = await prisma.users.findUnique({
      where: { id },
      select: { password: true, provider: true }
    });

    if (!user) {
      return res.status(404).send('User not found');
    }

    if (!user.password) {
      return res.status(400).json({ message: 'You are registered with a social network' });
    }

    const isPasswordCorrect = await argon2.verify(user.password, oldPassword);

    if (!isPasswordCorrect) {
      return res.status(400).json({ message: 'Old password is incorrect' });
    }

    const hashedPassword = await argon2.hash(newPassword);

    await prisma.users.update({
      where: { id },
      data: { password: hashedPassword },
    });

    return res.status(200).json({ message: 'Password changed successfully' });
  } catch (error: any) {
    console.log('[UserController](changePassword)', error.message);
    next(error);
  }
};

export const updateUser = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const id = req.userId;
  const email = req.body?.email;
  const phone = req.body?.phone;

  try {
    const existingUser = await prisma.users.findUnique({ where: { id } });

    if (!existingUser) {
      return res.status(404).send('User not found');
    }

    const updatedData: { email?: string, phone?: string } = {};

    if (existingUser.phone_verified_at === null && phone) {
      updatedData.phone = phone;
    }

    if (existingUser.email_verified_at === null && email) {
      updatedData.email = email;
    }

    const updatedUser = await prisma.users.update({
      where: { id },
      data: updatedData,
      ...userSelect
    });

    return res.status(200).json(updatedUser);
  } catch (error: any) {
    console.log('[UserController](updateUser)', error.message);
    next(error);
  }
}

export const sendVerificationCode = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const id = req.userId;
  const type: VerificationType = req.body?.type;

  try {
    const user = await prisma.users.findUnique({ where: { id } });

    if (!user) {
      return res.status(404).send('User not found');
    }

    let verification_token = user[`${type}_verification_token`]
    let verification_token_expires = user[`${type}_verification_token_expire`]
    let { token, encryptedToken } = generateAndEncryptToken(null);
    const tokenExpire = verification_token_expires ? new Date(verification_token_expires) : new Date();
    const isTokenExpire = tokenExpire.getTime() <= new Date().getTime();

    if (!isTokenExpire && verification_token) {
      encryptedToken = verification_token;
      token = decryptToken(verification_token);
    }

    await prisma.users.update({
      where: { id: user.id },
      data: {
        [`${type}_verification_token`]: encryptedToken,
        [`${type}_verification_token_expire`]: new Date(Date.now() + 3600000),
      },
    });

    if (type === 'email' && user.email) {
      const response = await sendEmail({
        to: user.email,
        subject: 'Підтвердження єлектронної пошти',
        template: 'confirm-mail',
        variables: {
          MAIN_TEXT: "Для підтвердження вашої електронної пошти, перейдіть за посиланням або скористайтеся кодом підтвердження.",
          BUTTON_TEXT: "Підтвердити",
          TOKEN: token,
          CONFIRM_URL: `https://${process.env.ALLOWED_ORIGIN}/api/user/verify-email?hash=${encryptedToken}`
        }
      });
    } else if (type === 'phone' && user.phone){
      const response = await sendSMS({ to: user.phone, text: `Код підтвердження: ${token}` });
    }

    return res.status(200).send('OK');
  } catch (error: any) {
    console.log('[UserController](sendVerificationCode)', error.message);
    next(error);
  }
}

export const verifyEmail = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    let hash = req.body?.hash;
    const token = req.body?.token;

    if (!hash) {
      const { encryptedToken } = generateAndEncryptToken(token);
      hash = encryptedToken;
    }

    const user = await prisma.users.findFirst({
      where: {
        email_verification_token: hash as string,
        email_verification_token_expire: { gt: new Date() },
      },
      ...userSelect
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid token' });
    }

    await prisma.users.update({
      where: { id: user.id },
      data: {
        email_verification_token: null,
        email_verification_token_expire: null,
        email_verified_at: new Date(),
      },
    });

    return res.status(200).json(user);
  } catch (error: any) {
    console.log('[UserController](verifyEmail)', error.message);
    next(error);
  }
}

export const verifyPhone = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.body?.token;
    const { encryptedToken: verification_token } = generateAndEncryptToken(token);

    const user = await prisma.users.findFirst({
      where: {
        phone_verification_token: verification_token as string,
        phone_verification_token_expire: { gt: new Date() },
      },
      ...userSelect
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid token' });
    }

    await prisma.users.update({
      where: { id: user.id },
      data: {
        phone_verification_token: null,
        phone_verification_token_expire: null,
        phone_verified_at: new Date(),
      },
    });

    return res.status(200).json(user);
  } catch (error: any) {
    console.log('[UserController](verifyPhone)', error.message);
    next(error);
  }
}
