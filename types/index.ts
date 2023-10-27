export { User } from '../controllers/auth.controller'

export { AuthRequest } from '../middlewares/isAuth'

export enum VerificationType {
  email = 'email',
  phone = 'phone'
}
