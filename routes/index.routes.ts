import { Router } from 'express';
import { isAuth } from '../middlewares';
import authRoutes from './auth.routes';
import userRoutes from './user.routes';

const router = Router();

router
  .use('/auth', authRoutes)
  .use('/user', isAuth, userRoutes);

export default router;
