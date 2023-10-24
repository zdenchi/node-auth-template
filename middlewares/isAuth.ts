import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/token';
import { PUBLIC_KEY } from '../config';

export interface AuthRequest extends Request {
  userId?: number;
}

export const isAuth = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const refreshToken: string | undefined = req.cookies['refresh-token'];
  const accessToken: string | undefined = req.headers.authorization?.split(' ')[1];

  if (!accessToken || !refreshToken) {
    return res.status(403).send('Missing token');
  }

  try {
    const decodedToken = await verifyToken(accessToken, PUBLIC_KEY) as any;
    req.userId = parseInt(decodedToken.id);
    next();
  } catch (error: any) {
    console.log('[middlewares](isAuth):', error.message);
    return res.status(401).send('Authentication failed: Invalid token');
  }
};
