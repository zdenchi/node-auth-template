import { writeFileSync, mkdirSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';

function generateKeyPair() {
  const dirPath = './config';

  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  mkdirSync(dirPath, { recursive: true });
  writeFileSync(`${dirPath}/public_key.pem`, publicKey);
  writeFileSync(`${dirPath}/private_key.pem`, privateKey);
}

generateKeyPair();
