"use strict";
/**
 * Erick Ponce Leão <erickponceleao@gmail.com>
 */
var _ = require("underscore");
var querystring = require("querystring");
var crypto = require("crypto");
var Token = (function () {
    function Token(key, secret) {
        this.key = key;
        this.secret = secret;
    }
    Token.prototype.sign = function (request) {
        request.sign(this);
    };
    return Token;
}());
exports.Token = Token;
var Request = (function () {
    function Request(method, path, query) {
        var _this = this;
        this.queryDict = {};
        this.authDict = {};
        this.signed = false;
        if (typeof path != 'string')
            throw new Error('Expected string');
        if (typeof query != 'object')
            throw new Error('Expected object');
        _.forEach(query, function (value, key) {
            var keyLower = key.toLowerCase();
            if (keyLower.search('auth_') >= 0) {
                _this.authDict[keyLower] = value.trim();
            }
            else {
                if (_.isArray(value)) {
                    _.forEach(value, function (v, idx) {
                        value[idx] = v.trim();
                    });
                    _this.queryDict[keyLower + '[]'] = value;
                } else if (_.isObject(value)) {
                    _this.queryDict[keyLower] = value;
                } else {
                    _this.queryDict[keyLower] = value.trim();
                }

            }
        });
        this.method = method.toUpperCase();
        this.path = path;
    }
    Request.prototype.getAuthField = function (field) {
        var authFieldKey = 'auth_' + field;
        if (authFieldKey in this.authDict) {
            return this.authDict[authFieldKey];
        }
        else {
            throw new Error('Missing parameter: ' + field);
        }
    };
    Request.prototype.sign = function (token) {
        this.authDict = {
            auth_version: Request.AUTH_VERSION,
            auth_key: token.key,
            auth_timestamp: Math.floor(new Date().getTime() / 1000)
        };
        this.authDict['auth_signature'] = this.signature(token);
        this.signed = true;
        return this.authDict;
    };
    Request.prototype.authenticate = function (token, raiseException, timeMsGrace) {
        if (raiseException === void 0) { raiseException = true; }
        if (timeMsGrace === void 0) { timeMsGrace = 600; }
        if (!token.secret)
            throw new Error('Provided token is missing secret');
        try {
            this.validateVersion();
            this.validateTimestamp(timeMsGrace);
            this.validateSignature(token);
        }
        catch (e) {
            if (raiseException)
                throw new Error(e.message);
            else
                return false;
        }
        return true;
    };
    Request.prototype.getAuthDict = function () {
        if (!this.signed)
            throw new Error('Request not signed');
        return this.authDict;
    };
    Request.prototype.signedParams = function () {
        return _.extend(this.queryDict, this.authDict);
    };
    Request.prototype.sortObj = function (obj) {
        var ordered = {};
        Object.keys(obj).sort().forEach(function (key) {
            ordered[key] = obj[key];
        });
        return ordered;
    };
    Request.prototype.parameterString = function () {
        var paramDict = this.signedParams() || {};
        var paramDictLower = {};
        _.forEach(paramDict, function (value, key) {
            paramDictLower[key.toLowerCase()] = value;
        });
        delete paramDictLower['auth_signature'];
        var stringifyed = querystring.stringify(this.sortObj(paramDictLower));
        return querystring.unescape(stringifyed);
    };
    Request.prototype.stringToSign = function () {
        return [this.method, this.path, this.parameterString()].join('\n');
    };
    Request.prototype.signature = function (token) {
        return crypto.createHmac('sha256', token.secret).update(this.stringToSign()).digest('hex');
    };
    Request.prototype.validateVersion = function () {
        if (this.getAuthField('version') != Request.AUTH_VERSION)
            throw new Error('Version not supported');
    };
    Request.prototype.validateTimestamp = function (timeMsGrace) {
        if (!timeMsGrace)
            return true;
        var timeMs = this.getAuthField('timestamp');
        var now = Math.floor(new Date().getTime() / 1000);
        var error = (now - timeMs);
        if (error >= timeMsGrace) {
            var errorMsg = 'Timestamp expired: Given timestamp '
                + '(' + timeMs + ') not within ' + timeMsGrace
                + ' of server time (' + now + ')';
            throw new Error(errorMsg);
        }
        return true;
    };
    Request.prototype.validateSignature = function (token) {
        var authSignature = this.getAuthField('signature');
        var sig = this.signature(token);
        if (authSignature != sig) {
            var errorMsg = 'Invalid signature: you should have '
                + 'sent HmacSHA256Hex(' + this.stringToSign() + ', your_secret_key)'
                + ', but you sent ' + authSignature;
            throw new Error(errorMsg);
        }
        return true;
    };
    Request.ISO8601 = new Date().toISOString();
    Request.AUTH_VERSION = '1.0';
    return Request;
}());
exports.Request = Request;
//# sourceMappingURL=signature.js.map
