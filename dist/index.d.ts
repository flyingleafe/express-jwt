import * as jose from 'jose';
import * as express from 'express';
import expressUnless from 'express-unless';
export declare type IsRevoked = (req: express.Request, token: string) => Promise<boolean>;
declare type TokenGetter = (req: express.Request) => string | undefined;
declare type Params = {
    secret: Uint8Array | jose.KeyLike | jose.JWTVerifyGetKey;
    getToken?: TokenGetter;
    isRevoked?: IsRevoked;
    credentialsRequired?: boolean;
} & jose.JWTVerifyOptions;
export { UnauthorizedError } from './errors/UnauthorizedError';
export declare type ExpressJwtRequest<T = jose.JWTPayload> = express.Request & {
    auth: T;
};
export declare const expressjwt: (options: Params) => {
    (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void>;
    unless: typeof expressUnless;
};
