/* eslint-disable @typescript-eslint/ban-ts-comment */
import * as jose from 'jose';
import * as express from 'express';
import { expressjwt, UnauthorizedError, ExpressJwtRequest } from '../src';
import assert from 'assert';


describe('failure tests', function () {
  const req = {} as express.Request;
  const res = {} as express.Response;

  it('should throw if options not sent', function () {
    try {
      // @ts-ignore
      expressjwt();
    } catch (e) {
      assert.ok(e);
      assert.equal(e.message, "express-jwt: `secret` is a required option");
    }
  });

  it('should throw if algorithms is not sent', function () {
    try {
      // @ts-ignore
      expressjwt({ secret: Buffer.from('shhhh') });
    } catch (e) {
      assert.ok(e);
      assert.equal(e.message, 'express-jwt: `algorithms` is a required option');
    }
  });

  it('should throw if algorithms is not an array', function () {
    try {
      // @ts-ignore
      expressjwt({ secret: Buffer.from('shhhh'), algorithms: 'foo' });
    } catch (e) {
      assert.ok(e);
      assert.equal(e.message, 'express-jwt: `algorithms` must be an array');
    }
  });

  it('should throw if no authorization header and credentials are required', function (done) {
    expressjwt({ secret: Buffer.from('shhhh'), credentialsRequired: true, algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_required');
      done();
    });
  });

  it('support unless skip', function (done) {
    req.originalUrl = '/index.html';
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'] }).unless({ path: '/index.html' })(req, res, function (err) {
      assert.ok(!err);
      done();
    });
  });

  it('should skip on CORS preflight', function (done) {
    const corsReq = {} as express.Request;
    corsReq.method = 'OPTIONS';
    corsReq.headers = {
      'access-control-request-headers': 'sasa, sras,  authorization'
    };
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'] })(corsReq, res, function (err) {
      assert.ok(!err);
      done();
    });
  });

  it('should throw if authorization header is malformed', function (done) {
    req.headers = {};
    req.headers.authorization = 'wrong';
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_bad_format');
      done();
    });
  });

  it('should throw if authorization header is not Bearer', function () {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_bad_scheme');
    });
  });

  it('should next if authorization header is not Bearer and credentialsRequired is false', function (done) {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'], credentialsRequired: false })(req, res, function (err) {
      assert.ok(typeof err === 'undefined');
      done();
    });
  });

  it('should throw if authorization header is not well-formatted jwt', function (done) {
    req.headers = {};
    req.headers.authorization = 'Bearer wrongjwt';
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      done();
    });
  });

  it('should throw if jwt is an invalid json', function (done) {
    req.headers = {};
    req.headers.authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.yJ1c2VybmFtZSI6InNhZ3VpYXIiLCJpYXQiOjE0NzEwMTg2MzUsImV4cCI6MTQ3MzYxMDYzNX0.foo';
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      done();
    });
  });

  it('should throw if authorization header is not valid jwt', async function () {
    const secret = Buffer.from('shhhhhh');
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: Buffer.from('different-shhhh'), algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, 'signature verification failed');
    });
  });

  it('should throw if audience is not expected', async function () {
    const secret = Buffer.from('shhhhhh');
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setExpirationTime("1s")
      .setAudience('expected-audience')
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret)  

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: secret, algorithms: ['HS256'], audience: 'not-expected-audience' })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, 'unexpected "aud" claim value');
    });
  });

  it('should throw if token is expired', async function () {
    const secret = Buffer.from('shhhhhh');
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setExpirationTime(1382412921)
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: secret, algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.inner.name, 'JWTExpired');
      assert.equal(err.message, '"exp" claim timestamp check failed');
    });
  });

  it('should throw if token issuer is wrong', async function () {
    const secret = Buffer.from('shhhhhh');
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setIssuer('http://foo')
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: secret, algorithms: ['HS256'], issuer: 'http://wrong' })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, 'unexpected "iss" claim value');
    });
  });

  it('should use errors thrown from custom getToken function', function (done) {
    expressjwt({
      secret: Buffer.from('shhhhhh'), algorithms: ['HS256'],
      getToken: () => { throw new UnauthorizedError('invalid_token', { message: 'Invalid token!' }); }
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, 'Invalid token!');
      done();
    });
  });

  it('should throw error when signature is wrong', async function () {
    const secret = Buffer.from("shhh");
    const token = await new jose.SignJWT({ foo: 'bar'})
      .setIssuer('http://www')
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    // manipulate the token
    const newContent = Buffer.from("{foo: 'bar', edg: 'ar'}").toString('base64');
    const splitetToken = token.split(".");
    splitetToken[1] = newContent;
    const newToken = splitetToken.join(".");
    // build request
    // @ts-ignore
    req.headers = [];
    req.headers.authorization = 'Bearer ' + newToken;
    expressjwt({ secret: secret, algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, 'signature verification failed');
    });
  });

  it('should throw error if token is expired even with when credentials are not required', async function () {
    const secret = Buffer.from('shhhhhh');
    const token = await new jose.SignJWT({ foo: 'bar'})
      .setExpirationTime(1382412921)
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: secret, credentialsRequired: false, algorithms: ['HS256'] })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, '"exp" claim timestamp check failed');
    });
  });

  it('should throw error if token is invalid even with when credentials are not required', async function () {
    const secret = Buffer.from('shhhhhh');
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setExpirationTime(1382412921)
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: Buffer.from("not the secret"), algorithms: ['HS256'], credentialsRequired: false })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
      assert.equal(err.message, 'signature verification failed');
    });
  });

});

describe('work tests', function () {
  // var req = {} as express.Request;
  // var res = {} as express.Response;

  it('should work if authorization header is valid jwt', async function () {
    const secret = Buffer.from('shhhhhh');
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    const req = {} as ExpressJwtRequest;
    const res = {} as express.Response;
    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: secret, algorithms: ['HS256'] })(req, res, function () {
      assert.equal(req.auth.foo, 'bar');
    });
  });

  it('should work if authorization header is valid with a buffer secret', async function () {
    const secret = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64');
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    const req = {} as ExpressJwtRequest;
    const res = {} as express.Response;

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: secret, algorithms: ['HS256'] })(req, res, function () {
      assert.equal(req.auth.foo, 'bar');
    });
  });

  it('should work if no authorization header and credentials are not required', function (done) {
    const req = {} as express.Request;
    const res = {} as express.Response;
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'], credentialsRequired: false })(req, res, function (err) {
      assert(typeof err === 'undefined');
      done();
    });
  });

  it('should not work if no authorization header', function (done) {
    const req = {} as express.Request;
    const res = {} as express.Response;
    expressjwt({ secret: Buffer.from('shhhh'), algorithms: ['HS256'] })(req, res, function (err) {
      assert(typeof err !== 'undefined');
      done();
    });
  });

  it('should produce a stack trace that includes the failure reason', async function () {
    const req = {} as express.Request;
    const res = {} as express.Response;
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(Buffer.from('secretA'));
    
      req.headers = {};
    req.headers.authorization = 'Bearer ' + token;

    expressjwt({ secret: Buffer.from('secretB'), algorithms: ['HS256'] })(req, res, function (err) {
      const index = err.stack.indexOf('UnauthorizedError: signature verification failed')
      assert.equal(index, 0, "Stack trace didn't include 'invalid signature' message.")
    });

  });

  it('should work with a custom getToken function', async function () {
    const req = {} as ExpressJwtRequest;
    const res = {} as express.Response;
    const secret = Buffer.from('shhhhhh');
    
    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'HS256' })    
      .sign(secret);

    req.headers = {};
    req.query = {};
    req.query.token = token;

    function getTokenFromQuery(req) {
      return req.query.token;
    }

    expressjwt({
      secret: secret,
      algorithms: ['HS256'],
      getToken: getTokenFromQuery,
    })(req, res, function () {
      assert.equal(req.auth.foo, 'bar');
    });
  });

  it('should work with a secretCallback function that accepts header argument', async function () {
    const req = {} as ExpressJwtRequest;
    const res = {} as express.Response;
    const secret = Buffer.from('shhhhhh');
    const getSecret: jose.JWTVerifyGetKey = async (protectedHeader) => {
      assert.equal(protectedHeader.alg, 'HS256');
      // @ts-ignore
      // assert.equal(token.payload.foo, 'bar');
      return secret;
    };

    const token = await new jose.SignJWT({ foo: 'bar' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({ secret: getSecret, algorithms: ['HS256'] })(req, res, function () {
      assert.equal(req.auth.foo, 'bar');
    });
  });
});
