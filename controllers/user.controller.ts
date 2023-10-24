import { Response, NextFunction } from 'express';
import { PrismaClient, Prisma } from '@prisma/client';
import { AuthRequest } from '../types';
import { userSelect } from './auth.controller';

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
  } catch (error) {
    next(error);
  }
};
