var Message = require('../models/Message');
var Certificate = require('../models/Certificate');
var Box = require('../app/ctx');
var gost89 = require('gost89');
var fs = require('fs');
var http = require('http');
var url = require('url');


function getUserInfo(signKeyFilePath, password){
    return fetch(signKeyFilePath, password).then(response => {
        const preprocessedData = response.filter(item => item != null)
            .map(serverResponse => {
                return serverResponse.length > 0 
                    ? serverResponse.map(certificate => _preprocessCertificate(certificate))
                    : []
            })

        return new Promise((resolve, reject) => {
            resolve(preprocessedData);
        })
    })
}

function fetch(signKeyFilePath, password){
    const buff = fs.readFileSync(signKeyFilePath);

    var box = new Box({
        keys: [{
            file: buff,
            password: password,
        }],
        algo: gost89.compat.algos()
    });

    if (box.isWithCerts()){
        // likely Privatbank's jks
        const r = []

        box.keys.forEach(k => {
            if (k.cert.extension.ipn != undefined){
                r.push(k.cert)
            }
        })

        return Promise.all([r])
    }
    
    // look up certs on cmp servers
    var payload = _getQuery(box);
    var servers = [
        'http://acskidd.gov.ua',
        'http://masterkey.ua',
        'http://uakey.com.ua',
        'http://ca.diia.gov.ua',
    ];

    return Promise.all(
        servers.map(hostname => { 
            return _httpRequest('post', hostname + '/services/cmp/', payload)
                .catch(error => {
                    // omit
                })
        })
    )
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
    ct[0]    = 0x0D;

    var msg = new Message({type: 'data', data: ct});

    return msg.as_asn1();
}

function _httpRequest(method, url, body = null) {
    if (!['get', 'post', 'head'].includes(method)) {
        throw new Error(`Invalid method: ${method}`);
    }

    let urlObject;

    try {
        urlObject = new URL(url);
    } catch (error) {
        throw new Error(`Invalid url ${url}`);
    }

    if (body && method !== 'post') {
        throw new Error(`Invalid use of the body parameter while using the ${method.toUpperCase()} method.`);
    }

    let options = {
        method: method.toUpperCase(),
        hostname: urlObject.hostname,
        port: urlObject.port,
        path: urlObject.pathname
    };

    if (body) {
        options.headers = {'Content-Length':Buffer.byteLength(body)};
    }

    return new Promise((resolve, reject) => {

        const clientRequest = http.request(options, incomingMessage => {

            // Response object.
            let response = {
                statusCode: incomingMessage.statusCode,
                headers: incomingMessage.headers,
                body: []
            };

            // Collect response body data.
            incomingMessage.on('data', chunk => {
                response.body.push(chunk);
            });

            // Resolve on end.
            incomingMessage.on('end', () => {
                if (response.body.length) {
                    response.body = Buffer.concat(response.body);
                }

                if (response.statusCode >= 300){
                    reject(response)
                } else {
                    resolve(_getResponse(response));
                }
            });
        });
        
        // Reject on request error.
        clientRequest.on('error', error => {
            reject(error);
        });

        // Write request body if present.
        if (body) {
            clientRequest.write(body);
        }

        // Close HTTP connection.
        clientRequest.end();
    });
}

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
    certificates.map(function (cert) {
        if (cert.extension.ipn != undefined){
            const commonName = cert.subject.commonName
            if (!commonName.toLowerCase().includes("ocsp") && !commonName.toLowerCase().includes("cmp")) {
                response_data.push(cert)
            }
        }
    });

    return response_data
}

function _is_stamp(key_ext_usage_id){
    const stamp_ext_usage_id = [1, 2, 804, 2, 1, 1, 1, 3, 9]

    function _check_if_stamp(key_ext_usage_id){
        return key_ext_usage_id.every((value, index) => value === stamp_ext_usage_id[index]);
    }

    return key_ext_usage_id.some((a_ext_usage, index) => _check_if_stamp(a_ext_usage));
}

function _preprocessCertificate(cert){
    var certificate = cert.as_dict()

    var subjectInfo = certificate.subject
    var extension   = certificate.extension
    var usage       = certificate.usage
    var valid       = certificate.valid

    const organization_name      = subjectInfo.organizationName
    const subject_key_identifier = extension.subjectKeyIdentifier
    const business_form          = extension.ipn.EDRPOU ? 'ТОВ' : 'ФОП'
    const full_name              = subjectInfo.commonName
    const key_type               = extension.extendedKeyUsage ? _is_stamp(extension.extendedKeyUsage) ? 'stamp': 'regular' : 'regular'
    const town                   = subjectInfo.localityName
    var serial_number            = cert.rdnSerial().toUpperCase()
    serial_number                = serial_number.substring(0, serial_number.indexOf('@'));
    const region                 = subjectInfo.stateOrProvinceName
    const edrpou                 = extension.ipn.EDRPOU
    const ipn                    = extension.ipn.DRFO
    const cert_usage             = usage.sign ? 'sign' : 'encrypt'
    const valid_from             = valid.from
    const valid_to               = valid.to

    const cert_dict = {
        subject_key_identifier: subject_key_identifier,
        key_type              : key_type,
        business_form         : business_form,
        organization_name     : organization_name,
        full_name             : full_name,
        town                  : town,
        serial_number         : serial_number,
        region                : region,
        edrpou                : edrpou,
        ipn                   : ipn,
        usage                 : cert_usage,
        valid_from            : valid_from,
        valid_to              : valid_to,
    }

    return {
        'raw': cert.as_asn1(),
        'dict': cert_dict
    }
}


module.exports.fetch       = fetch;
module.exports.getUserInfo = getUserInfo;
