import { Router } from 'express';

import {
  getUser,
  changePassword,
} from '../controllers/user.controller';

const router = Router();

router
  .get('/', getUser)
  .patch('/change-password', changePassword);

export default router;
