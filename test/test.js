/* eslint-env node, mocha */
"use strict";

var assert = require("assert");
var aws = require("../");

describe("aws-signature-v4", function() {
  // taken from the AWS documentation example code
  var accessKey = "AKIAIOSFODNN7EXAMPLE";
  var secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  var sessionToken = "EXAMPLESESSION";
  var exampleTime = Date.parse("Fri, 24 May 2013 00:00:00 GMT");
  var canonicalRequest = aws.createCanonicalRequest(
    "GET",
    "/test.txt",
    {
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential":
        "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
      "X-Amz-Date": "20130524T000000Z",
      "X-Amz-Expires": 86400,
      "X-Amz-SignedHeaders": "host"
    },
    {
      Host: "examplebucket.s3.amazonaws.com"
    },
    "UNSIGNED-PAYLOAD"
  );
  var stringToSign = aws.createStringToSign(
    exampleTime,
    "us-east-1",
    "s3",
    canonicalRequest
  );
  var signature = aws.createSignature(
    secretKey,
    exampleTime,
    "us-east-1",
    "s3",
    stringToSign
  );
  var presignedURL = aws.createPresignedS3URL("test.txt", {
    key: accessKey,
    secret: secretKey,
    bucket: "examplebucket",
    timestamp: exampleTime
  });

  it("should generate a canonical request", function() {
    assert.equal(
      canonicalRequest,
      [
        "GET",
        "/test.txt",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host",
        "host:examplebucket.s3.amazonaws.com",
        "",
        "host",
        "UNSIGNED-PAYLOAD"
      ].join("\n")
    );
  });

  it("should generate a string to sign", function() {
    // time, region, service, request
    assert.equal(
      stringToSign,
      [
        "AWS4-HMAC-SHA256",
        "20130524T000000Z",
        "20130524/us-east-1/s3/aws4_request",
        "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04"
      ].join("\n")
    );
  });

  it("should generate a signature", function() {
    // secret, time, region, service, stringToSign
    assert.equal(
      signature,
      "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
  });

  it("should generate a presigned url", function() {
    assert.equal(
      presignedURL,
      "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
  });

  it("should generate a presigned url with query params", function() {
    var presignedUrlWithQuery = aws.createPresignedS3URL("test.txt", {
      key: accessKey,
      secret: secretKey,
      bucket: "examplebucket",
      timestamp: exampleTime,
      query: "key=value&key2=value2"
    });
    assert.equal(
      presignedUrlWithQuery,
      "https://examplebucket.s3.amazonaws.com/test.txt?key=value&key2=value2&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=9441992768076e59f7162b6a5dd3782cddf270398d8508408386af62eed5570c"
    );
  });

  it("should generate a presigned s3 url with security token, and security token should not be the last parameter", function() {
    var presignedUrlWithSecurityToken = aws.createPresignedS3URL("test.txt", {
      key: accessKey,
      secret: secretKey,
      bucket: "examplebucket",
      timestamp: exampleTime,
      sessionToken: sessionToken
    });
    assert.equal(
      presignedUrlWithSecurityToken,
      "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=12abb65becb4cfbac48bfdd9eb3178408ff6fd7f470505f4baf3dcad7088253f"
    );
  });

  it("should generate a presigned mqtt url with security token, and security token should be the last parameter", function() {
    var presignedUrlWithSecurityToken = aws.createPresignedURL(
      "GET",
      "example.iot.us-east-1.amazonaws.com",
      "/mqtt",
      "iotdevicegateway",
      "",
      {
        protocol: "wss",
        key: accessKey,
        secret: secretKey,
        timestamp: exampleTime,
        sessionToken: sessionToken
      }
    );
    assert.equal(
      presignedUrlWithSecurityToken,
      "wss://example.iot.us-east-1.amazonaws.com/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fiotdevicegateway%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=3ec863617e7e6afa53fc5669c7db4983300818ddc18e72db53c6408d00f60d94&X-Amz-Security-Token=EXAMPLESESSION"
    );
  });
});
