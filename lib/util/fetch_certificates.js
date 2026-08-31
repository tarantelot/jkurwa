var Message = require('../models/Message');
var Certificate = require('../models/Certificate');
var Box = require('../app/ctx');
var gost89 = require('gost89');
var dstu7564 = require('dstu7564');
var dstucryptAlgos = require('dstucrypt-algos');
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
        // dstucrypt-algos wraps gost89 and additionally dispatches the
        // Dstu7564mac-256/Dstu7624cbc-256 (Kupyna/Kalyna) key containers
        // some newer CAs issue; it's a superset of gost89.compat.algos().
        algo: dstucryptAlgos.algos()
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
    // Endpoints below were derived from the official IIT CACertificates.p7b
    // bundle (every accredited Ukrainian ACSK's authorityInfoAccess OCSP URL,
    // with "ocsp" swapped for "cmp" - the same convention jkurwa's own
    // findCertsCmp() uses upstream) and verified live to actually speak the
    // CMP protocol, covering every accredited provider, not just a handful.
    var payload = _getQuery(box);
    var servers = [
        'http://acskidd.gov.ua/services/cmp/',
        'http://masterkey.ua/services/cmp/',
        'http://cmp.masterkey.ua/services/cmp/',
        'http://uakey.com.ua/services/cmp/',
        'http://ca.diia.gov.ua/services/cmp/',
        'http://ca.depositsign.com/services/cmp/',
        'http://ca.vchasno.ua/services/cmp/',
        'http://canbu.bank.gov.ua/services/cmp/',
        'http://canbu.bank.gov.ua/openbanking/services/cmp/',
        'http://csk.uss.gov.ua/services/cmp/',
        'http://acsk.dpsu.gov.ua/services/cmp/',
        'http://acsk.oree.com.ua/services/cmp/',
        'http://acsk.privatbank.ua/services/cmp/',
        'http://amokey.com.ua/services/cmp/',
        'http://ca.alfabank.kiev.ua/services/cmp/',
        'http://ca.bankalliance.ua/cmp',
        'http://ca.bankalliance.ua/cmp-kupyna',
        'http://ca.credit-agricole.ua/services/cmp/',
        'http://ca.edin.ua/services/cmp/',
        'http://ca.gp.gov.ua/cmp',
        'http://ca.gp.gov.ua/cmp-kupyna',
        'http://ca.mil.gov.ua/services/cmp/',
        'http://ca.monobank.ua/services/cmp/dstu/',
        'http://ca.mvs.gov.ua/services/cmp/',
        'http://ca.ngu.gov.ua/services/cmp/',
        'http://ca.oschadbank.ua/cmp-kupyna',
        'http://ca.oschadbank.ua/public/cmp',
        'http://ca.pravex.com.ua/services/cmp/',
        'http://ca.sensebank.com.ua/services/cmp/',
        'http://ca.szru.gov.ua/services/cmp/',
        'http://ca.tascombank.ua/services/cmp/',
        'http://ca.tax.gov.ua/services/cmp/',
        'http://csk.ukrsibbank.com/services/cmp/',
        'http://csk.uz.gov.ua/services/cmp/',
        'http://pki.pumb.ua/services/cmp/',
        'http://qca.ukrgasbank.com/cmp',
        'http://qca.ukrgasbank.com/cmp-kupyna',
        'http://va1-knedp.ssu.gov.ua/services/cmp/',
        'http://va2-knedp.ssu.gov.ua/services/cmp/'
    ];

    return Promise.all(
        servers.map(url => {
            return _httpRequest('post', url, payload)
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

    // The second lookup slot exists for 2-key containers (sign+encrypt
    // pair), where it's the second key's own id. For single-key files it
    // used to just repeat keyids[0]. Some newer CAs (e.g. uakey.com.ua)
    // compute the CA-side key identifier with Dstu7564 (Kupyna) instead of
    // the legacy Gost34311 hash box.algo.hash always uses, so a Kupyna-based
    // key id would never match and every CMP server reports "not found"
    // even though the certificate exists. Use the free second slot to also
    // try the Kupyna variant instead of wasting it on a duplicate.
    var altKeyid = keyids.length === 1
        ? dstu7564.computeHash(32, box.keys[0].priv.pub().serialize())
        : null;

    /* black magic here. blame eeeeeet */
    var ct = Buffer.alloc(120);
    ct.fill(0);
    keyids[0].copy(ct, 0xC);
    (keyids[1] || altKeyid || keyids[0]).copy(ct, 0x2C);
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

        // With dozens of CMP servers now queried in parallel per lookup, one
        // slow/unresponsive host must not stall the whole getUserInfo() call.
        clientRequest.setTimeout(8000, () => {
            clientRequest.destroy(new Error(`Timed out contacting ${url}`));
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
