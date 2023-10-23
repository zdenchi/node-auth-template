import { readFileSync } from 'fs';

export const PRIVATE_KEY = readFileSync('./config/private_key.pem', 'utf8');
