var Message = require('../lib/models/Message');
var Certificate = require('../lib/models/Certificate');
var Box = require('../lib/app/ctx');
var gost89 = require('gost89');
var fs = require('fs');
var http = require('http');
var url = require('url');


function _getResponse(resp) {
    var rmsg;
    try {
        rmsg = new Message(resp.body);
    }
    catch (e) {
        return null
    }

    if (!rmsg.info) {
        return null;
    }
    var result = rmsg.info.readInt32LE(4);
    if (result !== 1) {
        return null;
    }

    var raw_cert = rmsg.info.slice(8);
    rmsg = new Message(raw_cert);
    var certificates = rmsg.info.certificate.map(function (certData) {
        return new Certificate(certData);
    });

    var response_data = []
    certificates.map(function (cert, index) {
        if (cert.extension.ipn != undefined){
            // var certificate_name = create_certificate_name(
            //     cert.as_dict().usage.sign, 
            //     cert.as_dict().usage.encrypt
            // )

            // save certificates
            // fs.writeFileSync(certificate_name, cert.as_asn1());
            response_data.push(cert.as_dict())
        }
    });

    var msg = {status: 200, payload: response_data}
    // console.log('jk_response:' + JSON.stringify(msg))
    return msg
}

function post(queryUrL, data, response) {
    var parsed = url.parse(queryUrL);

    var req = http.request({
        host:  parsed.host,
        path: parsed.path,
        method: 'POST',
        headers: {
            'Content-Length': data.length,
        },

    }, function (res) {
        var chunks = [];
        // console.log('res', res.statusCode);
        res.on('data', function (chunk) {
            chunks.push(chunk);
        });
        res.on('end', function () {
            var complete_response_data = Buffer.concat(chunks);
            response({body: complete_response_data, code: res.status});
        });
    });
    req.on('error', function(e) {
        response({code: 599});
    });
    req.write(data);
    req.end();
}

function _getQuery(box) {
    var keyids = box.keys.map(function (info) {
        return info.priv.pub().keyid(box.algo);
    });

    /* black magic here. blame eeeeeet */
    var ct = Buffer.alloc(120);
    ct.fill(0);
    keyids[0].copy(ct, 0xC);
    (keyids[1] || keyids[0]).copy(ct, 0x2C);
    ct[0x6C] = 0x1;
    ct[0x70] = 0x1;
    ct[0x08] = 2;
    ct[0] = 0x0D;

    var msg = new Message({type: 'data', data: ct});

    return msg.as_asn1();
}

function fetch(signKeyPath, password){
    try{
        var box = new Box({
            keys: [{
                privPath: signKeyPath,
                password: password,
            }],
            algo: gost89.compat.algos()
        });
    } catch(error){
        return error
    }

    var payload = _getQuery(box);
    var servers = [
        'http://acskidd.gov.ua',
        'http://masterkey.ua',
    ];

    var idx;
    for (idx=0; idx < servers.length; idx++) {
        post(servers[idx] + '/services/cmp/', payload, _getResponse);
    }
}

module.exports.fetch_certificates = fetch;