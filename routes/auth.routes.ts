import { Router } from 'express';

import {
  signup,
  login,
  logout,
} from '../controllers/auth.controller';

const router = Router();

router
  .post('/signup', signup)
  .post('/login', login)
  .get('/logout', logout);

export default router;
