'use strict';

const asn1 = require('asn1.js');
const pbes2 = require('./pbes');
const dstszi2010 = require('./dstszi2010.js');

const ContentInfo = dstszi2010.ContentInfo;

// PKCS#12 bag identifiers (RFC 7292 B.2). Only the shrouded key bag carries a
// password-encrypted private key -- its bagValue is an EncryptedPrivateKeyInfo,
// which is exactly the PBES2 structure pbes2.js already models. Every other bag
// (certBag etc.) is captured raw and skipped: a Ukrainian key container's
// certificates are read separately, not from here.
const BAG_OID = {
  '1 2 840 113549 1 12 10 1 1': 'keyBag',
  '1 2 840 113549 1 12 10 1 2': 'pkcs8ShroudedKeyBag',
  '1 2 840 113549 1 12 10 1 3': 'certBag',
  '1 2 840 113549 1 12 10 1 4': 'crlBag',
  '1 2 840 113549 1 12 10 1 5': 'secretBag',
  '1 2 840 113549 1 12 10 1 6': 'safeContentsBag',
};

// Raw capture for a bag value we do not decode (cert/other bags).
const AnyValue = asn1.define('AnyValue', function () {
  this.any();
});

// SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY, bagAttributes SET OPTIONAL }.
// bagValue is decoded per bagId, the same way dstszi2010.ContentInfo picks its
// content model: a shrouded key bag as PBES2, anything else captured raw.
const SafeBag = asn1.define('SafeBag', function () {
  this.seq().obj(
    this.key('bagId').objid(BAG_OID),
    this.key('bagValue').explicit(0).use(function (bag) {
      return bag.bagId === 'pkcs8ShroudedKeyBag' ? pbes2 : AnyValue;
    }),
    this.key('bagAttributes').optional().any()
  );
});

// SafeContents ::= SEQUENCE OF SafeBag
const SafeContents = asn1.define('SafeContents', function () {
  this.seqof(SafeBag);
});

// AuthenticatedSafe ::= SEQUENCE OF ContentInfo. Each ContentInfo of type `data`
// holds a DER-encoded SafeContents; a Ukrainian key splits its DSTU-4145 signing
// key and its GOST key-exchange key into one ContentInfo each, so there are
// usually two. (Password-privacy mode -- an encryptedData ContentInfo wrapping
// the whole SafeContents -- is not produced for these keys; the bags are
// individually shrouded instead, so such a ContentInfo is skipped.)
const AuthenticatedSafe = asn1.define('AuthenticatedSafe', function () {
  this.seqof(ContentInfo);
});

// PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData MacData OPTIONAL }.
// The MAC is not verified here: a wrong password fails later at storeload (the
// bag will not decrypt), which is the "Cant load key from store" the caller
// already reports.
const Pfx = asn1.define('Pfx', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('authSafe').use(ContentInfo),
    this.key('macData').optional().any()
  );
});

// A PKCS#12 / PFX container -> the list of its password-encrypted private keys,
// each as the descriptor pbes2.obj_parse yields (what dstucrypt-algos'
// storeload() reads). The whole container is walked -- every ContentInfo and
// every bag -- so multiple keys and mixed (cert/key) bags are handled. This
// replaces the former fixed 57-byte-header slice, which assumed a single,
// unwrapped SafeContents at one hard-coded offset and failed on any real file
// (the SafeContents is nested inside authSafe -> AuthenticatedSafe ->
// ContentInfo, at an offset that depends on the DER lengths).
function pfx_parse(data) {
  const pfx = Pfx.decode(data, 'der');
  if (pfx.authSafe.contentType !== 'data') {
    throw new Error('PKCS#12 authSafe is ' + pfx.authSafe.contentType + ', expected data');
  }

  const safe = AuthenticatedSafe.decode(pfx.authSafe.content, 'der');
  const keys = [];
  for (const content of safe) {
    if (content.contentType !== 'data') {
      continue;
    }
    for (const bag of SafeContents.decode(content.content, 'der')) {
      if (bag.bagId === 'pkcs8ShroudedKeyBag') {
        keys.push(pbes2.obj_parse(bag.bagValue));
      }
    }
  }

  if (keys.length === 0) {
    throw new Error('PKCS#12 holds no shrouded key bag');
  }
  return keys;
}

module.exports = { pfx_parse };
