import { readFileSync } from 'fs';

export const { CONFORMATION_SECRET_KEY, CONFORMATION_SECRET_IV } = process.env;
export const PRIVATE_KEY = readFileSync('./config/private_key.pem', 'utf8');
export const PUBLIC_KEY = readFileSync('./config/public_key.pem', 'utf8');
