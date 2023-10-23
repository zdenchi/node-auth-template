import * as jose from 'jose';
import { randomInt, createHmac } from 'node:crypto';

export const signToken = async (
  payload: jose.JWTPayload,
  secret: string,
  options: { exp: string }
): Promise<string> => {
  try {
    const privateKey = await jose.importPKCS8(secret, 'EdDSA');
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

export const verifyToken = async (token: string, secret: string) => {
  try {
    const publicKey = await jose.importSPKI(secret, 'EdDSA');
    const jwt = await jose.jwtVerify(token, publicKey);
    return jwt.payload;
  } catch (error: any) {
    console.error('Error verifying token:', error.message);
    throw error;
  }
};

export const generateTokenAndHash = (secret: string) => {
  const token = randomInt(100000, 999999).toString();
  const hmac = createHmac('sha256', secret);
  const hashedToken = hmac.update(token).digest('hex');
  return { token, hashedToken }
}
