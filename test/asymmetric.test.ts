/* eslint-disable @typescript-eslint/ban-ts-comment */
import * as jose from 'jose';
import * as express from 'express';
import { expressjwt, UnauthorizedError, ExpressJwtRequest } from '../src';
import assert from 'assert';

var PUBLIC_KEY, PRIVATE_KEY: jose.KeyLike;

const getIncludedKey: jose.JWTVerifyGetKey = async (protectedHeader) => {
  const { alg, jwk } = protectedHeader;

  if (typeof jwk === 'undefined') {
    throw new Error('No JWK key included in the token header, even though it is expected');
  }

  return jose.importJWK(jwk, alg)
}

before(async function () {
  const { publicKey, privateKey } = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519'});
  PUBLIC_KEY = publicKey;
  PRIVATE_KEY = privateKey;
})

describe('test asymmetric keys', function () { 
  it('can verify Ed25519 signed JWT against a public key', async function () {
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .sign(PRIVATE_KEY)

    const req = {} as ExpressJwtRequest;
    const res = {} as express.Response;
    req.headers = { authorization: 'Bearer ' + token };
   
    expressjwt({ secret: PUBLIC_KEY, algorithms: ['EdDSA'] })(req, res, function () {
      assert.equal(req.auth.foo, 'bar');
    });
  });

  it('can verify using private key as well', async function () {
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .sign(PRIVATE_KEY)

    const req = {} as ExpressJwtRequest;
    const res = {} as express.Response;
    req.headers = { authorization: 'Bearer ' + token };
   
    expressjwt({ secret: PRIVATE_KEY, algorithms: ['EdDSA'] })(req, res, function () {
      assert.equal(req.auth.foo, 'bar');
    });
  });

  it('can verify token only using the embedded public key', async function () {
    const publicJwk = await jose.exportJWK(PUBLIC_KEY);
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'EdDSA', jwk: publicJwk })
      .sign(PRIVATE_KEY)

    const req = {} as ExpressJwtRequest;
    const res = {} as express.Response;
    req.headers = { authorization: 'Bearer ' + token };
   
    expressjwt({ secret: getIncludedKey, algorithms: ['EdDSA'] })(req, res, function () {
      assert.equal(req.auth.foo, 'bar');
    });
  });
})
