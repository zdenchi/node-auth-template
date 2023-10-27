import { Router } from 'express';

import {
  getUser,
  changePassword,
  updateUser,
  sendVerificationCode,
  verifyEmail,
  verifyPhone,
} from '../controllers/user.controller';

const router = Router();

router
  .get('/', getUser)
  .patch('/change-password', changePassword)
  .patch('/update', updateUser)
  .post('/verify', sendVerificationCode)
  .patch('/verify-email', verifyEmail)
  .patch('/verify-phone', verifyPhone);

export default router;
