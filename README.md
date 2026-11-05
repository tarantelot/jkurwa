jkurwa
======

GF2m ellipcit curves library in javascript. 

* Supports short Weierstrass curves used in Ukrainian standard DSTU 4145;
* Provides key deriviation for DSTU block ciphers (see https://github.com/muromec/em-gost);
* Encypted containers can be parsed and decrypted if respective cipher implementation is passed. See gost89 and dstucrypt/agent for reference;
* Encrypted and signed messages in wicked PKCS#7 format used by tax office (sta.gov.ua) are supported for both read and write (see jk.Box, jk.util.transport);
* Includes parsers for signed and encrypted messages, X509.v3 certificates, JKS and Key-6.dat key containers, TSP, CMP, OCSP requests and responses.

Warning
-------

* Jkurwa does not guarranty constant-time calculcation;
* Jkurwa only verifies signature against public key and does not actually check X.509 certificate validity unless CA list is loaded.
  See dstucrypt/agent repo readme for details.

[![Build Status](https://travis-ci.org/dstucrypt/jkurwa.svg?branch=master)](https://travis-ci.org/dstucrypt/jkurwa)
[![codecov](https://codecov.io/gh/dstucrypt/jkurwa/branch/master/graph/badge.svg)](https://codecov.io/gh/dstucrypt/jkurwa)
[![npm module](https://badge.fury.io/js/jkurwa.svg)](https://www.npmjs.org/package/jkurwa)
[![dependencies](https://david-dm.org/dstucrypt/jkurwa.png)](https://david-dm.org/dstucrypt/jkurwa)

Kasa24: the DPS Electronic Cabinet in the browser
-------------------------------------------------

`lib/cabinet.js` (`require("jkurwa/browser").cabinet`, or `require("jkurwa").cabinet` on node) does what
Kasa24's owner cabinet needs from the owner's key -- in the formats mistokasa_dstu (the services' Python
port) makes and mistokasa_documents reads, checked against both (`test/test-cabinet.js`):

```js
import { cabinet } from "jkurwa/browser";

const box = cabinet.openKey({ file, password, certs });   // file: the picked key file's bytes; certs: DER/PEM,
                                                          // needed when the container holds none (Key-6.dat)
cabinet.describeKey(box);          // { commonName, organization, drfo, edrpou, validFrom, validTo, keyId, canEncrypt }
cabinet.isTaxpayersKey(box, tin);  // the certificate names this РНОКПП/ЄДРПОУ

await cabinet.signTin(box, tin);                     // -> signed_tin
await cabinet.signFskoCommand(box, "Objects");       // -> fsko_objects   ({"Command":"Objects"}, byte for byte)
await cabinet.signFskoCommand(box, "Operators");     // -> fsko_operators / the cashier-key check
await cabinet.wrapForCabinet(box, {                  // -> container, for POST /sfs-filings/{id}/send
  xml: toSign.xml_base64, filename: toSign.filename, recipientCert: toSign.recipient_cert, email });
await cabinet.receiptQuery(box, { cabinetId, recipientCert });   // -> receipt_query
cabinet.receiptKey(box, receipt.envelope, dpsCertificates);      // -> receipt_key (32 bytes), never the receipt
```

Byte arguments take a Buffer, a Uint8Array or a base64 string (what the API returns); results are Buffers --
base64 them for the API. Every signature is CAdES-BES with the content inside, the signing certificate
attached and a signing time, and no CA timestamp: what the DPS took from the services for the tin, FSKO's
commands and the receipt query. A filing may still ask for the CA's timestamps (`tsp: "all"`, with a `query`
function given to `openKey` that reaches the CA through a server -- CAs don't answer browsers).

In a browser bundle (webpack 5, vite, esbuild) `jkurwa/browser` sets up `Buffer` from the `buffer` package, and
package.json's `browser` field leaves out node's fs/http (CMP certificate lookup, OCSP, key paths) and uses
`crypto.getRandomValues`.

Usage
-----

See ./test/ and ./examples/ directories. See dstucrypt/agent repo for example app.

Sister libraries: 

* https://github.com/dstucrypt/ukurwa4145 - DSTU 4145 in Python;
* https://github.com/dstucrypt/gost89 - GOST cipher, hash, mac, key wrapper and container loader in pure js;
* https://github.com/dstucrypt/python-gost89 - gost hash for python (2 and 3);
* https://github.com/dstucrypt/jksreader - library to parse java-style key containers used by privatbank;
* https://github.com/muromec/zozol - dumb ASN.1 parser and serialisator for python with X509 and wicked CMS schemas;
* https://github.com/dstucrypt/openssl-dstu - patched OpenSSL with DSTU 4145 and GOST family support (outdated, unmaintained).

Demo site: https://dstucrypt.github.io/signerbox2/

Demo apps:

* https://github.com/dstucrypt/agent -- command line utility and daemon service to sign, encrypt and decrypt files;
* https://github.com/dstucrypt/dstukeys -- web interface with examples of authentication;
* https://github.com/dstucrypt/signerbox2/ -- another web app;
* https://github.com/max1gu/e-rro -- cash register app (прогрманий рро).

To cross-verifiy signatures use https://czo.gov.ua/verify .

References
----------

* Certificate format (in Ukrainian), basically kind of X.509v3: http://zakon4.rada.gov.ua/laws/show/z1398-12
* Private key container format, PBES2-like (effective from 01.01.2016): http://zakon3.rada.gov.ua/laws/show/z2227-13
* See https://github.com/dstucrypt/agent repo for tax report format and implementation details
* Law on Trust Services - http://zakon.rada.gov.ua/laws/show/2155-19

Bonus
---

First known use of the word Kurwa was recorded in 1415. Happy 600 birthday Kurwa!
