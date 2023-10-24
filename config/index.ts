import { readFileSync } from 'fs';

export const PRIVATE_KEY = readFileSync('./config/private_key.pem', 'utf8');
export const PUBLIC_KEY = readFileSync('./config/public_key.pem', 'utf8');
