import { promisify } from 'util';
import * as Axios from 'axios';
import * as jsonwebtoken from 'jsonwebtoken';
const jwkToPem = require('jwk-to-pem');

export interface ClaimVerifyRequest {
  readonly token?: string;
}

export interface ClaimVerifyResult {
  readonly userName: string;
  readonly clientId: string;
  readonly isValid: boolean;
  readonly error?: any;
}

interface TokenHeader {
  kid: string;
  alg: string;
}
interface PublicKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}
interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

interface PublicKeys {
  keys: PublicKey[];
}

interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}

interface Claim {
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  username: string;
  client_id: string;
}

const cognitoPoolId = process.env.COGNITO_POOL_ID || 'us-east-1_HC0P4th3o';
if (!cognitoPoolId) {
  throw new Error('env var required for cognito pool');
}
const cognitoIssuer = `https://cognito-idp.us-east-1.amazonaws.com/${cognitoPoolId}`;

let cacheKeys: MapOfKidToPublicKey | undefined;
const getPublicKeys = async (): Promise<MapOfKidToPublicKey> => {
  if (!cacheKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const publicKeys = await Axios.default.get<PublicKeys>(url);
    cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
      const pem = jwkToPem(current);
      agg[current.kid] = { instance: current, pem };
      return agg;
    }, {} as MapOfKidToPublicKey);'/'
    return cacheKeys;
  } else {
    return cacheKeys;
  }
};

const verifyPromised = promisify(jsonwebtoken.verify.bind(jsonwebtoken));

const handler = async (request: ClaimVerifyRequest): Promise<any> => {
  let result: ClaimVerifyResult;
  try {
    console.log(`user claim verify invoked for ${JSON.stringify(request)}`);
    const token = request.token;
    const tokenSections = (token || '').split('.');
    if (tokenSections.length < 2) {
      throw new Error('requested token is invalid');
    }
    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON) as TokenHeader;
    console.log("🚀 ~ file: decode-verify-jwt.ts ~ line 86 ~ handler ~ header", header)
    const keys = await getPublicKeys();
    const key = keys[header.kid];
    if (key === undefined) {
      throw new Error('claim made for unknown kid');
    }
    // const claim = await verifyPromised(token, key.pem) as unknown as Claim;
    if (token) {
      const claim = jsonwebtoken.verify(token, key.pem) as Claim
      console.log("🚀 ~ file: decode-verify-jwt.ts ~ line 95 ~ handler ~ claim", claim)

      const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
      if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
        throw new Error('claim is expired or invalid');
      }
      if (claim.iss !== cognitoIssuer) {
        throw new Error('claim issuer is invalid');
      }
      if (claim.token_use !== 'access') {
        throw new Error('claim use is not access');
      }
      console.log(`claim confirmed for ${claim.username}`);
      result = { userName: claim.username, clientId: claim.client_id, isValid: true };
    } else {
      result = { userName: 'NA', clientId: 'NA', isValid: false };
    }

  } catch (error) {
    console.log("🚀 ~ file: decode-verify-jwt.ts ~ line 107 ~ handler ~ error", error)
    result = { userName: '', clientId: '', error, isValid: false };
  }
  return result;
};

export { handler };
