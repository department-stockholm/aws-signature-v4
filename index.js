/* eslint-env node */
/* eslint no-use-before-define: [0, "nofunc"] */
"use strict";

// sources of inspiration:
// https://web-identity-federation-playground.s3.amazonaws.com/js/sigv4.js
// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
var crypto = require("crypto");
var querystring = require("querystring");
var path = require("path");

exports.createCanonicalRequest = function(
  method,
  pathname,
  query,
  headers,
  payload,
  doubleEscape
) {
  return [
    method.toUpperCase(),
    createCanonicalURI(
      doubleEscape
        ? pathname
            .split(/\//g)
            .map(v => encodeURIComponent(v))
            .join("/")
        : pathname
    ),
    exports.createCanonicalQueryString(query),
    exports.createCanonicalHeaders(headers),
    exports.createSignedHeaders(headers),
    createCanonicalPayload(payload)
  ].join("\n");
};

function createCanonicalURI(uri) {
  var url = path.resolve(uri);
  if (uri[uri.length - 1] == "/" && url[url.length - 1] != "/") {
    url += "/";
  }
  return url;
}

function createCanonicalPayload(payload) {
  if (payload == "UNSIGNED-PAYLOAD") {
    return payload;
  }
  return hash(payload || "", "hex");
}

exports.createCanonicalQueryString = function(params) {
  if (!params) {
    return "";
  }
  if (typeof params == "string") {
    params = querystring.parse(params);
  }
  return Object.keys(params)
    .sort()
    .map(function(key) {
      var values = Array.isArray(params[key]) ? params[key] : [params[key]];
      return values
        .sort()
        .map(function(val) {
          return encodeURIComponent(key) + "=" + encodeURIComponent(val);
        })
        .join("&");
    })
    .join("&");
};

exports.createCanonicalHeaders = function(headers) {
  return Object.keys(headers)
    .sort()
    .map(function(name) {
      var values = Array.isArray(headers[name])
        ? headers[name]
        : [headers[name]];
      return (
        name.toLowerCase().trim() +
        ":" +
        values
          .map(function(v) {
            return v.replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "");
          })
          .join(",") +
        "\n"
      );
    })
    .join("");
};

exports.createSignedHeaders = function(headers) {
  return Object.keys(headers)
    .sort()
    .map(function(name) {
      return name.toLowerCase().trim();
    })
    .join(";");
};

exports.createCredentialScope = function(time, region, service) {
  return [toDate(time), region, service, "aws4_request"].join("/");
};

exports.createStringToSign = function(time, region, service, request) {
  return [
    "AWS4-HMAC-SHA256",
    toTime(time),
    exports.createCredentialScope(time, region, service),
    hash(request, "hex")
  ].join("\n");
};

exports.createAuthorizationHeader = function(
  key,
  scope,
  signedHeaders,
  signature
) {
  return [
    "AWS4-HMAC-SHA256 Credential=" + key + "/" + scope,
    "SignedHeaders=" + signedHeaders,
    "Signature=" + signature
  ].join(", ");
};

exports.createSignature = function(
  secret,
  time,
  region,
  service,
  stringToSign
) {
  var h1 = hmac("AWS4" + secret, toDate(time)); // date-key
  var h2 = hmac(h1, region); // region-key
  var h3 = hmac(h2, service); // service-key
  var h4 = hmac(h3, "aws4_request"); // signing-key
  return hmac(h4, stringToSign, "hex");
};

exports.createPresignedS3URL = function(name, options) {
  options = options || {};
  options.method = options.method || "GET";
  options.bucket = options.bucket || process.env.AWS_S3_BUCKET;
  options.signSessionToken = true;
  options.doubleEscape = false;
  return exports.createPresignedURL(
    options.method,
    options.bucket + ".s3.amazonaws.com",
    "/" + name,
    "s3",
    "UNSIGNED-PAYLOAD",
    options
  );
};

exports.createPresignedURL = function(
  method,
  host,
  path,
  service,
  payload,
  options
) {
  options = options || {};
  options.key = options.key || process.env.AWS_ACCESS_KEY_ID;
  options.secret = options.secret || process.env.AWS_SECRET_ACCESS_KEY;
  options.sessionToken = options.sessionToken || process.env.AWS_SESSION_TOKEN;
  options.protocol = options.protocol || "https";
  options.timestamp = options.timestamp || Date.now();
  options.region = options.region || process.env.AWS_REGION || "us-east-1";
  options.expires = options.expires || 86400; // 24 hours
  options.headers = options.headers || {};
  options.signSessionToken = options.signSessionToken || false;
  options.doubleEscape =
    options.doubleEscape !== undefined ? options.doubleEscape : true;

  // host is required
  options.headers.Host = host;

  var query = options.query ? querystring.parse(options.query) : {};
  query["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256";
  query["X-Amz-Credential"] =
    options.key +
    "/" +
    exports.createCredentialScope(options.timestamp, options.region, service);
  query["X-Amz-Date"] = toTime(options.timestamp);
  query["X-Amz-Expires"] = options.expires;
  query["X-Amz-SignedHeaders"] = exports.createSignedHeaders(options.headers);

  // when a session token must be "signed" into the canonical request
  // (needed for some services, such as s3)
  if (options.sessionToken && options.signSessionToken) {
    query["X-Amz-Security-Token"] = options.sessionToken;
  }

  var canonicalRequest = exports.createCanonicalRequest(
    method,
    path,
    query,
    options.headers,
    payload,
    options.doubleEscape
  );
  var stringToSign = exports.createStringToSign(
    options.timestamp,
    options.region,
    service,
    canonicalRequest
  );
  var signature = exports.createSignature(
    options.secret,
    options.timestamp,
    options.region,
    service,
    stringToSign
  );
  query["X-Amz-Signature"] = signature;

  // when a session token must NOT be "signed" into the canonical request
  // (needed for some services, such as IoT)
  if (options.sessionToken && !options.signSessionToken) {
    query["X-Amz-Security-Token"] = options.sessionToken;
  } else {
    delete query["X-Amz-Security-Token"];
  }

  return (
    options.protocol + "://" + host + path + "?" + querystring.stringify(query)
  );
};

function toTime(time) {
  return new Date(time).toISOString().replace(/[:\-]|\.\d{3}/g, "");
}

function toDate(time) {
  return toTime(time).substring(0, 8);
}

function hmac(key, string, encoding) {
  return crypto
    .createHmac("sha256", key)
    .update(string, "utf8")
    .digest(encoding);
}

function hash(string, encoding) {
  return crypto
    .createHash("sha256")
    .update(string, "utf8")
    .digest(encoding);
}
