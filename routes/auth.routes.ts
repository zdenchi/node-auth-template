import { Router } from 'express';
import schemaValidator from "../middlewares/schemaValidator";
import {
  signup,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  googleOauthHandler
} from '../controllers/auth.controller';

const router = Router();

router
  .post('/signup', schemaValidator("auth"), signup)
  .post('/login', schemaValidator("auth"), login)
  .get('/logout', logout)
  .get('/refresh-tokens', refreshTokens)
  .post('/forgot-password', schemaValidator("emailOrPhone"), forgotPassword)
  .patch('/reset-password', schemaValidator("resetPassword"), resetPassword)
  .get('/social/google', googleOauthHandler);

export default router;
