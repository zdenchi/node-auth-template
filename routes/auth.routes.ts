import { Router } from 'express';

import {
  signup,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
} from '../controllers/auth.controller';

const router = Router();

router
  .post('/signup', signup)
  .post('/login', login)
  .get('/logout', logout)
  .get('/refresh-tokens', refreshTokens)
  .post('/forgot-password', forgotPassword)
  .patch('/reset-password', resetPassword);

export default router;
