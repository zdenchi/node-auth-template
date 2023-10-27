import { Router } from 'express';

import {
  getUser,
  changePassword,
  updateUser,
} from '../controllers/user.controller';

const router = Router();

router
  .get('/', getUser)
  .patch('/change-password', changePassword)
  .patch('/update', updateUser);

export default router;
