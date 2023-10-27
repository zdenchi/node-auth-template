import { Response, NextFunction } from 'express';
import { PrismaClient, Prisma } from '@prisma/client';
import { AuthRequest } from '../types';
import { userSelect } from './auth.controller';
import { hash, verify } from 'argon2';
import { generateAndEncryptToken, decryptToken } from '../utils/token';
import { sendEmail, sendSMS } from '../utils/sender';
import { VerificationType } from '../types';

const prisma = new PrismaClient();

type UpdatedUserData = {
  email?: string;
  phone?: string;
  email_confirmed_at?: Date;
  phone_confirmed_at?: Date;
}

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
    const confirmPassword = req.body?.confirmPassword;

    if (!oldPassword || !newPassword || !confirmPassword) {
      return res
        .status(401)
        .json({ message: 'Old password, new password and password confirm must be provided' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'New password and password confirm must match' });
    }

    const user = await prisma.users.findUnique({
      where: { id },
      select: { password: true }
    });

    if (!user) {
      return res.status(404).send('User not found');
    }

    const isPasswordCorrect = await verify(user.password, oldPassword);

    if (!isPasswordCorrect) {
      return res.status(400).json({ message: 'Old password is incorrect' });
    }

    const hashedPassword = await hash(newPassword);

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

  if (!type) {
    return res.status(400).json({ message: 'Verification type must be provided' });
  }

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
    let verification_token = req.query?.hash;
    const token = req.body?.token;

    if (!verification_token) {
      const { encryptedToken } = generateAndEncryptToken(token);
      verification_token = encryptedToken;
    }

    const user = await prisma.users.findFirst({
      where: {
        email_verification_token: verification_token as string,
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
