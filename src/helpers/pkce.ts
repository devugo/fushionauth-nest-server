import * as crypto from 'crypto';

function base64URLEncode(str) {
  return str
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

export const generateVerifier = () => {
  return base64URLEncode(crypto.randomBytes(32));
};

export const generateChallenge = (verifier) => {
  return base64URLEncode(sha256(verifier));
};
