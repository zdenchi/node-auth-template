import Joi, { ObjectSchema, CustomHelpers } from "joi";
import parsePhoneNumber from 'libphonenumber-js/mobile';

const isPhoneValid = (value: string, helpers: CustomHelpers) => {
  if (parsePhoneNumber(value)?.isValid()) return value;
  return helpers.error('any.invalid', { message: 'Phone number is invalid' });
}

const emailOrPhone = Joi.object().keys({
  email: Joi
    .string()
    .trim()
    .lowercase()
    .email()
    .optional(),
  phone: Joi
    .string()
    .trim()
    .custom(isPhoneValid)
    .optional(),
}).or('email', 'phone');

const auth = Joi.object().keys({
  email: Joi
    .string()
    .trim()
    .lowercase()
    .email()
    .optional(),
  phone: Joi
    .string()
    .trim()
    .custom(isPhoneValid)
    .optional(),
  password: Joi
    .string()
    .min(8)
    .required(),
}).or('email', 'phone');

const resetPassword = Joi.object().keys({
  hash: Joi.string().optional(),
  token: Joi.string().length(6).optional(),
  password: Joi
    .string()
    .min(8)
    .required(),
  confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
}).or('hash', 'token');

const changePassword = Joi.object().keys({
  oldPassword: Joi
    .string()
    .min(8)
    .required(),
  newPassword: Joi
    .string()
    .min(8)
    .required(),
  confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required(),
});

const sendVerificationCode = Joi.object().keys({
  type: Joi.string().valid('email', 'phone').required()
});

const verifyEmail = Joi.object().keys({
  hash: Joi.string().optional(),
  token: Joi.string().optional(),
}).or('hash', 'token');

const verifyPhone = Joi.object().keys({
  token: Joi.string().required(),
});

export default {
  "emailOrPhone": emailOrPhone,
  "auth": auth,
  "resetPassword": resetPassword,
  "changePassword": changePassword,
  "sendVerificationCode": sendVerificationCode,
  "verifyEmail": verifyEmail,
  "verifyPhone": verifyPhone,
} as { [key: string]: ObjectSchema };
