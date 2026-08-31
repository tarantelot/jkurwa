'use strict';

var asn1 = require('asn1.js'),
    dstszi2010 = require('./dstszi2010.js'),
    rfc3280 = require('./rfc3280'),
    CipherParams = dstszi2010.ContentEncryptionAlgorithmIdentifier,
    ContentInfo = dstszi2010.ContentInfo;


var OID = {
    '1 2 840 113549 1 5 13': "PBES2",
    "1 2 840 113549 1 5 12": "PBKDF2",
};

var PBES2 = asn1.define("StorePBES2", function () {
    this.seq().obj(
        this.key("head").seq().obj(
            this.key("id").objid(OID),
            this.key("pbes2").seq().obj(
                this.key("keyDerivationFunc").seq().obj(
                    this.key("id").objid(OID),
                    this.key('params').seq().obj(
                        this.key("salt").octstr(),
                        this.key("cycles").int(),
                        this.key("keyLength").optional().int(),
                        this.key("hash").use(CipherParams)
                    )
                ),
                this.key("encryptionScheme").use(CipherParams)
            )
        ),
        this.key("cryptData").octstr()
    );
});


var pbes2_parse = function (data) {
    const obj = PBES2.decode(data, 'der');
    return [pbes2_parse_asn1(obj)];
}

// Recognized PBKDF2 hash algorithms, keyed by the resolved algorithm name
// (see rfc3280.ALGORITHMS_IDS). Value is the "kdf" name dstucrypt-algos'
// storeload() dispatches on.
var KDF_BY_HASH = {
    'Gost34311-hmac': 'Gost34311-hmac',
    'Dstu7564mac-256': 'Dstu7564mac-256',
};

// Recognized content ciphers, keyed by the resolved algorithm name. ivLen/
// sboxLen describe the expected GOST28147Parameters shape for that cipher;
// sboxLen 0 means the cipher carries no separate S-box (dke absent).
var CIPHER_SPECS = {
    'Gost28147-cfb': { ivLen: 8, sboxLen: 64 },
    'Dstu7624cbc-256': { ivLen: 32, sboxLen: 0 },
};

var pbes2_parse_asn1 = function (asn1) {
    var kdf, enc, params, iv, sbox, salt, iter, kdfName, encName, spec;

    if (asn1.head.id !== 'PBES2') {
        throw new Error(asn1.head.id);
    }
    kdf = asn1.head.pbes2.keyDerivationFunc;
    if (kdf.id !== 'PBKDF2') {
        throw new Error(asn1.head.p.key.id);
    }
    kdfName = KDF_BY_HASH[kdf.params.hash.algorithm];
    if (!kdfName) {
        throw new Error("Unknown cipher " + kdf.params.hash.algorithm);
    }
    enc = asn1.head.pbes2.encryptionScheme;
    spec = CIPHER_SPECS[enc.algorithm];
    if (!spec) {
        throw new Error(enc.algorithm);
    }
    encName = enc.algorithm;
    params = enc.parameters.value;
    if (params === null) {
        throw new Error("Encryption params not passed");
    }
    iv = params.iv;
    sbox = params.dke;
    salt = kdf.params.salt;
    iter = kdf.params.cycles;

    if ((iv.length !== spec.ivLen) || (salt.length !== 32) ||
        (spec.sboxLen !== 0 && (!sbox || sbox.length !== spec.sboxLen))) {
        throw new Error("IV len: " + iv.length + ", S-BOX len: " + (sbox ? sbox.length : 0) + ", SALT len: " + salt.length);
    }
    return {
        "format": "PBES2",
        "kdf": kdfName,
        "enc": encName,
        "iv": iv,
        "sbox": sbox,
        "salt": salt,
        "iters": iter.toNumber(),
        "body": asn1.cryptData,
    };
};


var pbes2_serialize = function(store) {
    return PBES2.encode({
      head: {
        id: 'PBES2',
        pbes2: {
          keyDerivationFunc: {
            id: "PBKDF2",
            params: {
              salt: store.salt,
              cycles: 10000,
              hash: {
                algorithm: 'Gost34311-hmac',
                parameters: {
                  type: 'null_',
                  value: null,
                },
              },
            },
          },
          encryptionScheme: {
            algorithm: 'Gost28147-cfb',
            parameters: {
              type: 'params',
              value: {
                iv: store.iv,
                dke: store.sbox,
              }
            }
          },
        },
      },
      cryptData: store.body,
    }, 'der');
}

module.exports = PBES2;
module.exports.pbes2_parse = pbes2_parse;
module.exports.enc_serialize = pbes2_serialize;
module.exports.obj_parse = pbes2_parse_asn1;
