import { Router } from 'express';
import authRoutes from './auth.routes.js';

const router = Router();

router
  .get('/', (req, res) => res.send('Hello World!'))
  .use('/auth', authRoutes);

export default router;
