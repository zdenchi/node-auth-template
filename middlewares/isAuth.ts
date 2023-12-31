import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/token';

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
    const decodedToken = await verifyToken(accessToken) as any;
    req.userId = parseInt(decodedToken.sub);
    next();
  } catch (error: any) {
    console.log('[middlewares](isAuth):', error.message);
    return res.status(401).send('Authentication failed: Invalid token');
  }
};
