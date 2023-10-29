import { Router } from 'express';
import schemaValidator from "../middlewares/schemaValidator";
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
  .patch('/change-password', schemaValidator("changePassword"), changePassword)
  .patch('/update', schemaValidator('emailOrPhone'), updateUser)
  .post('/verify', schemaValidator("sendVerificationCode"), sendVerificationCode)
  .patch('/verify-email', schemaValidator("verifyEmail"), verifyEmail)
  .patch('/verify-phone', schemaValidator("verifyPhone"), verifyPhone);

export default router;
