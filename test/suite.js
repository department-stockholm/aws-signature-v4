/* eslint-env node, mocha */
"use strict";

var assert = require("assert");
var aws = require("../");
var fs = require("fs");
var path = require("path");
var url = require("url");

describe("aws-sig-v4-test-suite (as of 2018-10-20)", function() {
  var tests = fs.readdirSync(path.join(__dirname, "aws-sig-v4-test-suite"));
  var creds = "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request";
  var secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
  var securityToken =
    "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
  var exampleKey = "AKIDEXAMPLE";
  var exampleTime = Date.parse("2015-08-30T12:36:00Z");
  var exampleRegion = "us-east-1";
  var exampleService = "service";

  it("should generate same credential scope", function() {
    var cscope =
      "AKIDEXAMPLE/" +
      aws.createCredentialScope(exampleTime, exampleRegion, exampleService);
    assert.equal(cscope, creds);
  });

  // special cases for "post-sts-token" and "normalize-path"
  // which uses a nested dir structure
  var special = ["post-sts-token", "normalize-path"];
  special.forEach(function(dir) {
    var extra = fs.readdirSync(
      path.join(__dirname, "aws-sig-v4-test-suite", dir)
    );
    extra
      .filter(function(subdir) {
        return subdir.indexOf(".") == -1; // remove files
      })
      .forEach(function(subdir) {
        tests.push(path.join(dir, subdir));
      });
  });

  tests.forEach(function(dir) {
    if (special.includes(dir)) {
      // skip special cases
      return;
    }
    it(dir, async function() {
      var prefix = path.join(
        __dirname,
        "aws-sig-v4-test-suite",
        dir,
        path.basename(dir)
      );

      var fixtures = {
        // original request
        oreq: fs.readFileSync(prefix + ".req"),
        // canonical request
        creq: fs.readFileSync(prefix + ".creq").toString(),
        // the string-to-sign
        sts: fs.readFileSync(prefix + ".sts").toString(),
        // auth signature
        authz: fs.readFileSync(prefix + ".authz").toString(),
        // signed request
        sreq: fs.readFileSync(prefix + ".sreq").toString()
      };

      var req = await parseRequest(fixtures.oreq);

      var creq = aws.createCanonicalRequest(
        req.method,
        req.url.pathname,
        req.url.query,
        req.headers,
        req.body
      );
      assert.equal(creq, fixtures.creq);

      var sts = aws.createStringToSign(
        exampleTime,
        exampleRegion,
        "service",
        creq
      );
      assert.equal(sts, fixtures.sts);

      var authz = aws.createAuthorizationHeader(
        exampleKey,
        aws.createCredentialScope(exampleTime, exampleRegion, exampleService),
        aws.createSignedHeaders(req.headers),
        aws.createSignature(
          secretKey,
          exampleTime,
          exampleRegion,
          exampleService,
          sts
        )
      );
      assert.equal(authz, fixtures.authz);
    });
  });
});

function parseRequest(str) {
  return new Promise((resolve, reject) => {
    var http = require("http");
    var net = require("net");
    var server = http.createServer();
    server.on("request", function(req, res) {
      var body = [];
      req.on("error", function(err) {
        console.log("request error", err);
        reject(err);
      });
      req.on("data", function(buf) {
        body.push(buf);
      });
      req.on("end", function() {
        server.close();

        // node parses headers in a way not supported by
        // aws (joins multiple lines) so we do some manual parsing here
        var headers = {};
        for (var i = 0; i < req.rawHeaders.length; i += 2) {
          var k = req.rawHeaders[i];
          var v = parseHeader(req.rawHeaders[i + 1]);
          headers[k] = [].concat(headers[k] || [], v);
        }

        // remove any content-length headers that was
        // injected to create a valid http request
        // in prepareRequest()
        if (
          headers["Content-Length"] &&
          str.toString().indexOf("Content-Length") === -1
        ) {
          delete headers["Content-Length"];
        }

        // special case for "content-type" from
        // post-x-www-form-urlencoded-parameters
        if (headers["Content-Type"] && headers["Content-Type"].length == 2) {
          headers["Content-Type"] = [headers["Content-Type"].join(" ")];
        }

        // nodejs < v11 does not support utf-8 properly in urls
        // so we parse the url manually from the input request
        // https://github.com/nodejs/node/pull/20270
        // (fixes the get-utf8 test)
        var path = str.toString().match(/(GET|POST) (.+?) HTTP\/1.1/)[2];
        var uri = encodeURI("http://" + headers.Host + path);

        resolve({
          url: url.parse(uri),
          method: req.method,
          headers: headers,
          body: Buffer.concat(body)
        });

        res.end();
      });
    });
    server.on("error", function(err) {
      console.log("server error", err);
      reject(err);
    });
    server.on("clientError", function(err) {
      console.log("server client error", err);
      reject(err);
    });
    server.listen("0", function() {
      var socket = net.createConnection(server.address(), function() {
        // since the aws test request isn't actually
        // valid HTTP we need to fix it first...
        // (fixes normalize-path/get-space)
        var req = prepareRequest(str);
        socket.end(req);
      });
      socket.on("error", function(err) {
        console.log("socket error", err);
        reject(err);
      });
    });
  });
}

function parseHeader(value) {
  return value.match(/"[^"]+"|\S+/g);
}

function prepareRequest(req) {
  var isBody = false;
  var bodyLength = 0;
  return (
    req
      .toString()
      .split("\n")
      .map(function(line, index) {
        if (index === 0) {
          // fixes normalize-path/get-space
          // because the header line is not valid http
          // (the url has a space in it...)
          var head = line.match(/(GET|POST) (.+?) (HTTP\/1.1)/);
          return [head[1], encodeURI(head[2]), head[3]].join(" ");
        }
        if (isBody) {
          // fixes post-x-www-form-urlencoded
          // misses content-length?
          bodyLength = line.length;
        } else if (line == "") {
          isBody = true;
        }
        return line;
      })
      .map(function(line, index) {
        if (index === 0 && bodyLength > 0) {
          line += "\nContent-Length: " + bodyLength;
        }
        return line;
      })
      .join("\r\n") + "\r\n\r\n"
  );
}
