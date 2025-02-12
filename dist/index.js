"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.expressjwt = exports.UnauthorizedError = void 0;
var jose = __importStar(require("jose"));
var express_unless_1 = __importDefault(require("express-unless"));
var UnauthorizedError_1 = require("./errors/UnauthorizedError");
var UnauthorizedError_2 = require("./errors/UnauthorizedError");
Object.defineProperty(exports, "UnauthorizedError", { enumerable: true, get: function () { return UnauthorizedError_2.UnauthorizedError; } });
var expressjwt = function (options) {
    if (!(options === null || options === void 0 ? void 0 : options.secret))
        throw new RangeError('express-jwt: `secret` is a required option');
    if (!options.algorithms)
        throw new RangeError('express-jwt: `algorithms` is a required option');
    if (!Array.isArray(options.algorithms))
        throw new RangeError('express-jwt: `algorithms` must be an array');
    var getVerificationKey = typeof options.secret === 'function' ?
        options.secret :
        function () { return __awaiter(void 0, void 0, void 0, function () { return __generator(this, function (_a) {
            return [2 /*return*/, options.secret];
        }); }); };
    var credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;
    var middleware = function (req, res, next) {
        return __awaiter(this, void 0, void 0, function () {
            var token, hasAuthInAccessControl, parts, scheme, credentials, tokenPayload, payload, err_1, isRevoked, _a, request, err_2;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        _b.trys.push([0, 7, , 8]);
                        if (req.method === 'OPTIONS' && 'access-control-request-headers' in req.headers) {
                            hasAuthInAccessControl = req.headers['access-control-request-headers']
                                .split(',')
                                .map(function (header) { return header.trim(); })
                                .includes('authorization');
                            if (hasAuthInAccessControl) {
                                return [2 /*return*/, next()];
                            }
                        }
                        if (options.getToken && typeof options.getToken === 'function') {
                            token = options.getToken(req);
                        }
                        else if (req.headers && req.headers.authorization) {
                            parts = req.headers.authorization.split(' ');
                            if (parts.length == 2) {
                                scheme = parts[0];
                                credentials = parts[1];
                                if (/^Bearer$/i.test(scheme)) {
                                    token = credentials;
                                }
                                else {
                                    if (credentialsRequired) {
                                        throw new UnauthorizedError_1.UnauthorizedError('credentials_bad_scheme', { message: 'Format is Authorization: Bearer [token]' });
                                    }
                                    else {
                                        return [2 /*return*/, next()];
                                    }
                                }
                            }
                            else {
                                throw new UnauthorizedError_1.UnauthorizedError('credentials_bad_format', { message: 'Format is Authorization: Bearer [token]' });
                            }
                        }
                        if (!token) {
                            if (credentialsRequired) {
                                throw new UnauthorizedError_1.UnauthorizedError('credentials_required', { message: 'No authorization token was found' });
                            }
                            else {
                                return [2 /*return*/, next()];
                            }
                        }
                        tokenPayload = void 0;
                        _b.label = 1;
                    case 1:
                        _b.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, jose.jwtVerify(token, getVerificationKey, options)];
                    case 2:
                        payload = (_b.sent()).payload;
                        tokenPayload = payload;
                        return [3 /*break*/, 4];
                    case 3:
                        err_1 = _b.sent();
                        throw new UnauthorizedError_1.UnauthorizedError('invalid_token', err_1);
                    case 4:
                        _a = options.isRevoked;
                        if (!_a) return [3 /*break*/, 6];
                        return [4 /*yield*/, options.isRevoked(req, token)];
                    case 5:
                        _a = (_b.sent());
                        _b.label = 6;
                    case 6:
                        isRevoked = _a || false;
                        if (isRevoked) {
                            throw new UnauthorizedError_1.UnauthorizedError('revoked_token', { message: 'The token has been revoked.' });
                        }
                        request = req;
                        request.auth = tokenPayload;
                        next();
                        return [3 /*break*/, 8];
                    case 7:
                        err_2 = _b.sent();
                        return [2 /*return*/, next(err_2)];
                    case 8: return [2 /*return*/];
                }
            });
        });
    };
    middleware.unless = express_unless_1.default;
    return middleware;
};
exports.expressjwt = expressjwt;
