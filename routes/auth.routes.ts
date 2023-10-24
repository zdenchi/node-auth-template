import { Router } from 'express';

import {
  signup,
  login,
  logout,
  refreshTokens,
} from '../controllers/auth.controller';

const router = Router();

router
  .post('/signup', signup)
  .post('/login', login)
  .get('/logout', logout)
  .get('/refresh-tokens', refreshTokens);

export default router;
