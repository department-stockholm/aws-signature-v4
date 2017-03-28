AWS Signature V4
================

Generating the "new" AWS V4 signatures can be a bit of a pain.

For instance if you need to generate a signed URL for S3 where you have a key, secret and bucket. The steps to actually sign it is an order of magnitude more complicated than what the AWS V2 signatures were.

Just have a look at [their own docs][sign-query-docs].

This module exists to provide some help. It does those steps in their example for you and provides you with a simple way to sign an S3 URL mainly, but also a more simplified way to sign any AWS URL.

# Example

This is the easiest example how you may sign an S3 GET URL (assuming you have set your [AWS ENV vars](#aws-env-vars) set up):

```
var v4 = require('aws-signature-v4');
var url = v4.createPresignedS3URL('logs/my-file.txt');
// url => "https://examplebucket.s3.amazonaws.com/logs/my-file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
```

Say you want to upload using HTTP, for instance with [this neat component][s3-component] you can also do this in a `/sign` route :

```
var v4 = require('aws-signature-v4');
var url = v4.createPresignedS3URL(req.query.name, {
  region: 'eu-central-1', // using frankfurt which requires V4 at the moment
  expires: 3600, // need to upload within 1 hour
  method: 'PUT',
  headers: {
    'x-amz-acl': 'public-read' // set the uploaded file ACL to public-read
  }
});
```

# Install

It's available on [npm](https://npmjs.org) so you can simply install it with:

```
npm install --save aws-signature-v4
```


# API

## AWS ENV vars

I've tried to use the "official" ENV vars by default in this module. The ones they use in their own SDK:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`
- `AWS_S3_BUCKET` (not really official, but useful)


## Public API

### createPresignedS3URL(name[, options])

Returns a [query-signed AWS URL][sign-query-docs] with some S3 service specifics.

Options may be any of [createPresignedURL](#createpresignedurlmethod-host-path-service-payload-options)s options plus:

- `method` (defaults to `"GET"`)
- `bucket` (defaults to `process.env.AWS_S3_BUCKET`)

### createPresignedURL(method, host, path, service, payload[, options])

Returns a [query-signed AWS URL][sign-query-docs].

- `key` (defaults to `process.env.AWS_ACCESS_KEY_ID`)
- `secret` (defaults to `process.env.AWS_SECRET_ACCESS_KEY`)
- `protocol` (defaults to `"https"`)
- `headers` (defaults to `{}`)
- `timestamp` (defaults to `Date.now()`)
- `region` (defaults to `process.env.AWS_REGION || "us-east-1"`)
- `expires` (defaults to `86400`, or 24 hours)
- `headers` (defaults to `{}`)
- `query` Optional query parameters attached to the AWS API call (defaults to none)

## Internal API (but still available)

### createCanonicalRequest(method, pathname, query, headers, payload)

Returns a `CanonicalRequest` as defined by [query-signed AWS URL docs][sign-query-docs].

### createCanonicalQueryString(params)

Returns a `CanonicalQueryString` as defined by [query-signed AWS URL docs][sign-query-docs].

### createCanonicalHeaders(headers)

Returns a `CanonicalHeaders` as defined by [query-signed AWS URL docs][sign-query-docs].

### createSignedHeaders(headers)

Returns the `Signed Headers` as defined by [query-signed AWS URL docs][sign-query-docs].

### createCredentialScope(time, region, service)

Returns the `Credential Scope` as defined by [query-signed AWS URL docs][sign-query-docs].

### createStringToSign(time, region, service, request)

Returns the `StringToSign` as defined by [query-signed AWS URL docs][sign-query-docs].

### createSignature(secret, time, region, service, stringToSign)

Returns the `Signature` as defined by [query-signed AWS URL docs][sign-query-docs].


[sign-query-docs]: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
[s3-component]: https://github.com/component/s3/tree/0.3.x
