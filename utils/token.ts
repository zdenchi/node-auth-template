import * as jose from 'jose';
import { randomInt, createCipheriv, createDecipheriv } from 'node:crypto';
import { PRIVATE_KEY, PUBLIC_KEY, SECRET_KEY, SECRET_IV } from '../config';

const secretKey = Buffer.from(SECRET_KEY as string, 'utf-8');
const iv = Buffer.from(SECRET_IV as string, 'utf-8');

export const signToken = async (
  payload: jose.JWTPayload,
  options: { exp: string }
): Promise<string> => {
  try {
    const privateKey = await jose.importPKCS8(PRIVATE_KEY, 'EdDSA');
    const jwt = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime(options.exp)
      .sign(privateKey);
    return jwt;
  } catch (error: any) {
    console.error('Error signing token:', error.message);
    throw error;
  }
};

export const verifyToken = async (token: string) => {
  try {
    const publicKey = await jose.importSPKI(PUBLIC_KEY, 'EdDSA');
    const jwt = await jose.jwtVerify(token, publicKey);
    return jwt.payload;
  } catch (error: any) {
    console.error('Error verifying token:', error.message);
    throw error;
  }
};

export function generateAndEncryptToken(token: string | null) {
  if (!token) token = randomInt(100000, 999999).toString();
  const cipher = createCipheriv('aes-256-cbc', secretKey, iv);
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return {
    token,
    encryptedToken: encrypted.toString('hex'),
  };
}

export function decryptToken(token: string) {
  const decipher = createDecipheriv('aes-256-cbc', secretKey, iv);
  const decrpyted = Buffer.concat([decipher.update(Buffer.from(token, 'hex')), decipher.final()]);
  return decrpyted.toString('utf8');
}
