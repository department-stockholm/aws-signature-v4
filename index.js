/* eslint-env node */
/* eslint no-use-before-define: [0, "nofunc"] */
'use strict';

// sources of inspiration:
// https://web-identity-federation-playground.s3.amazonaws.com/js/sigv4.js
// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
var crypto = require('crypto');
var querystring = require('querystring');

exports.createCanonicalRequest = function(method, pathname, query, headers, payload) {
  return [
    method.toUpperCase(),
    pathname,
    exports.createCanonicalQueryString(query),
    exports.createCanonicalHeaders(headers),
    exports.createSignedHeaders(headers),
    payload
  ].join('\n');
};

exports.createCanonicalQueryString = function(params) {
  return Object.keys(params).sort().map(function(key) {
    return encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
  }).join('&');
};

exports.createCanonicalHeaders = function(headers) {
  return Object.keys(headers).sort().map(function(name) {
    return name.toLowerCase().trim() + ':' + headers[name].toString().trim() + '\n';
  }).join('');
};

exports.createSignedHeaders = function(headers) {
  return Object.keys(headers).sort().map(function(name) {
    return name.toLowerCase().trim();
  }).join(';');
};

exports.createCredentialScope = function(time, region, service) {
  return [toDate(time), region, service, 'aws4_request'].join('/');
};

exports.createStringToSign = function(time, region, service, request) {
  return [
    'AWS4-HMAC-SHA256',
    toTime(time),
    exports.createCredentialScope(time, region, service),
    hash(request, 'hex')
  ].join('\n');
};

exports.createSignature = function(secret, time, region, service, stringToSign) {
  var h1 = hmac('AWS4' + secret, toDate(time)); // date-key
  var h2 = hmac(h1, region); // region-key
  var h3 = hmac(h2, service); // service-key
  var h4 = hmac(h3, 'aws4_request'); // signing-key
  return hmac(h4, stringToSign, 'hex');
};

exports.createPresignedS3URL = function(bucket, name, options) {
  options = options || {};
  options.method = options.method || 'GET';
  options.bucket = options.bucket || process.env.AWS_S3_BUCKET;
  return exports.createPresignedURL(
    options.method,
    bucket + '.s3.amazonaws.com',
    '/' + name,
    's3',
    'UNSIGNED-PAYLOAD',
    options
  );
};

exports.createPresignedURL = function(method, host, path, service, payload, options) {
  options = options || {};
  options.key = options.key || process.env.AWS_ACCESS_KEY_ID;
  options.secret = options.secret || process.env.AWS_SECRET_ACCESS_KEY;
  options.protocol = options.protocol || 'https';
  options.headers = options.headers || {};
  options.timestamp = options.timestamp || Date.now();
  options.region = options.region || 'us-east-1';
  options.expires = options.expires || 86400; // 24 hours
  options.headers = options.headers || {};

  // host is required
  options.headers.Host = host;

  var query = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': options.key + '/' + exports.createCredentialScope(options.timestamp, options.region, service),
    'X-Amz-Date': toTime(options.timestamp),
    'X-Amz-Expires': options.expires,
    'X-Amz-SignedHeaders': exports.createSignedHeaders(options.headers)
  };
  var canonicalRequest = exports.createCanonicalRequest(method, path, query, options.headers, payload);
  var stringToSign = exports.createStringToSign(options.timestamp, options.region, service, canonicalRequest);
  var signature = exports.createSignature(options.secret, options.timestamp, options.region, service, stringToSign);
  query['X-Amz-Signature'] = signature;
  return options.protocol + '://' + host + path + '?' + querystring.stringify(query);
};

function toTime(time) {
  return new Date(time).toISOString().replace(/[:\-]|\.\d{3}/g, '');
}

function toDate(time) {
  return toTime(time).substring(0, 8);
}

function hmac(key, string, encoding) {
  return crypto.createHmac('sha256', key)
    .update(string, 'utf8')
    .digest(encoding);
}

function hash(string, encoding) {
  return crypto.createHash('sha256')
    .update(string, 'utf8')
    .digest(encoding);
}
