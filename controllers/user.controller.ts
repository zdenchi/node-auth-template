import { Response, NextFunction } from 'express';
import { PrismaClient, Prisma } from '@prisma/client';
import { AuthRequest } from '../types';
import { userSelect } from './auth.controller';
import { hash, verify } from 'argon2';

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