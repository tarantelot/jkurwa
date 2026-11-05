/*
 * What Kasa24's owner cabinet does with the owner's key, in the browser -- the DPS Electronic
 * Cabinet's formats exactly as mistokasa_dstu (the services' Python port of this library) makes
 * and reads them (`gate.wrap_for_cabinet`, the receipt query mistokasa_documents takes):
 *
 *   openKey({file, password, certs})        a Box: the key container's bytes, its password, and
 *                                           its certificates (DER/PEM) when the container holds none
 *   hasCertificates(box)                    whether it can sign and encrypt -- false: ask for them
 *   publicKeys(box)                         its public keys (base64, the file's order) -- what
 *                                           POST /api/v1/key/certificates takes; reopen with its answer
 *   describeKey(box)                        whose key: names, РНОКПП/ЄДРПОУ, validity, key id
 *   isTaxpayersKey(box, tin)                the key's certificate names that РНОКПП/ЄДРПОУ
 *   signTin(box, tin)                       CAdES over the ЄДРПОУ/РНОКПП (ASCII) -- `signed_tin`
 *   signFskoCommand(box, "Objects")         CAdES over {"Command":"Objects"} -- `fsko_objects`/`fsko_operators`
 *   wrapForCabinet(box, {xml, filename,     a filing's `container` for POST .../send
 *       recipientCert, edrpou, email})
 *   receiptQuery(box, {cabinetId,           a 1-ПРРО's `receipt_query` for POST .../receipt-query
 *       recipientCert})
 *   receiptKey(box, envelope, dpsCerts)     a receipt's content key (32 bytes) -- `receipt_key` for
 *                                           POST .../receipt-key; never the private key nor the receipt
 *
 * Every signature: CAdES-BES, content inside, the signing certificate attached, a signing time, no
 * CA timestamp -- what the DPS took from the service for the tin, FSKO's commands and the receipt
 * query. A filing may ask for the CA's timestamps (`tsp: "all"`), as the service once added them;
 * they need `query`, a function that gets them through a server (the CAs don't answer a browser).
 * All bytes in and out are Buffers (base64 them for the API).
 */
const Buffer = require("buffer").Buffer;
const gost89 = require("gost89");
const Box = require("./app/ctx");
const Message = require("./models/Message");
const Certificate = require("./models/Certificate");
const transport = require("./util/transport");

const FSKO_COMMANDS = ["Objects", "Operators"];

function openKey({ file, password, certs = [], algo, query } = {}) {
  if (!file) {
    throw new Error("openKey: the key container's bytes (file) are required");
  }
  return new Box({
    keys: [{ file: asBuffer(file), password, certBuffers: certs.map(asBuffer) }],
    algo: algo || gost89.compat.algos(),
    query
  });
}

function hasCertificates(box) {
  try {
    box.keyFor("sign");
    box.keyFor("encrypt");
    return true;
  } catch (ignore) {
    return false;
  }
}

// The keys' public keys as mistokasa_dstu's cmp.request_for_public_keys takes them: priv.pub().serialize().
function publicKeys(box) {
  return box.keys
    .filter(key => key.priv)
    .map(key => Buffer.from(key.priv.pub().serialize()).toString("base64"));
}

function describeKey(box) {
  const sign = box.keyFor("sign").cert;
  const ids = sign.extension.ipn || {};
  let encrypt = null;
  try {
    encrypt = box.keyFor("encrypt").cert;
  } catch (ignore) {} // eslint-disable-line no-empty
  return {
    commonName: sign.subject.commonName || null,
    organization: sign.subject.organizationName || null,
    drfo: ids.DRFO || null, // РНОКПП
    edrpou: ids.EDRPOU || null, // ЄДРПОУ
    validFrom: new Date(sign.valid.from),
    validTo: new Date(sign.valid.to),
    keyId: keyIdOf(sign),
    canEncrypt: Boolean(encrypt)
  };
}

function isTaxpayersKey(box, tin) {
  const { drfo, edrpou } = describeKey(box);
  const wanted = String(tin).replace(/^0+/, "");
  return [drfo, edrpou].some(id => id && id.replace(/^0+/, "") === wanted);
}

async function signTin(box, tin, opts = {}) {
  if (!/^[0-9A-Za-z]+$/.test(String(tin))) {
    throw new Error("signTin: an ЄДРПОУ/РНОКПП (digits) is required");
  }
  return signed(box, Buffer.from(String(tin), "ascii"), opts);
}

async function signFskoCommand(box, command, opts = {}) {
  if (!FSKO_COMMANDS.includes(command)) {
    throw new Error(`signFskoCommand: one of ${FSKO_COMMANDS.join(", ")}`);
  }
  // exactly these bytes -- FSKO checks the command as signed
  return signed(box, Buffer.from(JSON.stringify({ Command: command }), "utf8"), opts);
}

/*
 * UA1_SIGN (the owner's signature, taken off by the service) over
 *     TRANSPORTABLE (headers), CERTCRYPT (the owner's encryption certificate),
 *     UA1_CRYPT: enveloped to `recipientCert` (the cabinet's) from UA1_SIGN CAdES(xml) -- nothing
 *     else: a transport header inside the envelope is answered ERROR_SERTIF by the cabinet.
 */
async function wrapForCabinet(box, { xml, filename, recipientCert, edrpou, email, now, time, tsp } = {}) {
  if (!xml || !xml.length || !filename || !recipientCert || !email) {
    throw new Error("wrapForCabinet: xml, filename, recipientCert and email are required");
  }
  const opts = { time, tsp };
  const headers = transportHeaders(box, { filename, edrpou, email, now });
  const inner = transport.encode([{ type: "UA1_SIGN", contents: await signed(box, asBuffer(xml), opts) }]);
  const encrypter = box.keyFor("encrypt");
  const enveloped = box.encrypt(inner, undefined, certificate(recipientCert)).as_asn1();
  const out = transport.encode(
    [
      { type: "CERTCRYPT", contents: encrypter.cert.as_asn1() },
      { type: "UA1_CRYPT", contents: enveloped }
    ],
    headers
  );
  return transport.encode([{ type: "UA1_SIGN", contents: await signed(box, out, opts) }], headers);
}

/*
 * CERTCRYPT (the owner's encryption certificate), UA1_CRYPT: enveloped to the DPS from
 * UA1_SIGN CAdES(str(cabinetId)) -- no headers. What the cabinet's kvt_by_id takes.
 */
async function receiptQuery(box, { cabinetId, recipientCert, time } = {}) {
  if (!/^[0-9]+$/.test(String(cabinetId)) || !recipientCert) {
    throw new Error("receiptQuery: cabinetId (digits) and recipientCert are required");
  }
  const query = Buffer.from(String(cabinetId), "ascii");
  const signedQuery = transport.encode([{ type: "UA1_SIGN", contents: await signed(box, query, { time }) }]);
  const encrypter = box.keyFor("encrypt");
  const enveloped = box.encrypt(signedQuery, undefined, certificate(recipientCert)).as_asn1();
  return transport.encode([
    { type: "CERTCRYPT", contents: encrypter.cert.as_asn1() },
    { type: "UA1_CRYPT", contents: enveloped }
  ]);
}

/*
 * The content key of a receipt the DPS encrypted to the owner. `envelope`: the receipt as the
 * cabinet gave it (a transport container around the CMS envelope, or the bare envelope);
 * `dpsCerts`: the DPS's certificates (DER/PEM) -- the envelope names the one its key was agreed with.
 */
function receiptKey(box, envelope, dpsCerts = []) {
  const message = new Message(envelopeOf(asBuffer(envelope)));
  if (message.type !== "envelopedData") {
    throw new Error("receiptKey: not an encrypted receipt");
  }
  const ours = box.keyFor("encrypt", undefined, message.receiverKey);
  const senders = dpsCerts.map(certificate);
  const lookup = query => box.lookupCert(senders, query);
  try {
    return message.contentKey(ours.priv, box.algo, lookup);
  } catch (e) {
    if (e instanceof Message.ENOCERT) {
      throw new Error("receiptKey: the DPS certificate the receipt was encrypted with isn't among dpsCerts");
    }
    throw e;
  }
}

// ---- inside --------------------------------------------------------------------------------------

async function signed(box, data, { time, tsp } = {}) {
  const message = await box.sign(data, undefined, undefined, {
    time: time === undefined ? Date.now() / 1000 : time,
    tsp: tsp || false
  });
  return message.as_asn1();
}

// The DPS transport headers, in mistokasa_dstu's order (gate.transport_headers).
function transportHeaders(box, { filename, edrpou, email, now }) {
  const cert = box.keyFor("sign").cert;
  const ids = cert.extension.ipn || {};
  const organization = cert.subject.organizationName || cert.subject.commonName || "";
  const code = edrpou || ids.EDRPOU || ids.DRFO;
  if (!code) {
    throw new Error("wrapForCabinet: no ЄДРПОУ/РНОКПП -- give edrpou");
  }
  return {
    CERTYPE: "UA1",
    RCV_NAME: cp1251(organization),
    PRG_TYPE: "TRANSPORT GATE",
    PRG_VER: "1.0.0",
    SND_DATE: sendDate(now || new Date()),
    FILENAME: filename,
    EDRPOU: String(code),
    RCV_EMAIL: email
  };
}

function sendDate(now) {
  const pad = n => String(n).padStart(2, "0");
  return (
    `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}` +
    `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`
  );
}

const CP1251_EXTRA = {
  "Ё": 0xa8, "ё": 0xb8, "Є": 0xaa, "є": 0xba, "І": 0xb2, "і": 0xb3, "Ї": 0xaf, "ї": 0xbf,
  "Ґ": 0xa5, "ґ": 0xb4, "№": 0xb9, "«": 0xab, "»": 0xbb, "—": 0x97, "–": 0x96, "’": 0x92,
  "“": 0x93, "”": 0x94
};

// Python's str.encode("cp1251", "replace") for the characters a Ukrainian name holds; others "?".
function cp1251(text) {
  const out = Buffer.alloc(text.length);
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const code = ch.charCodeAt(0);
    if (code < 0x80) out[i] = code;
    else if (code >= 0x410 && code <= 0x44f) out[i] = code - 0x410 + 0xc0;
    else if (CP1251_EXTRA[ch] !== undefined) out[i] = CP1251_EXTRA[ch];
    else out[i] = 0x3f;
  }
  return out;
}

function envelopeOf(data) {
  if (data[0] === 0x30) {
    return data; // a bare CMS message
  }
  const { docs } = transport.decode(data);
  const crypt = (docs || []).find(doc => doc.type === "UA1_CRYPT");
  if (!crypt) {
    throw new Error("receiptKey: no UA1_CRYPT in the receipt's transport container");
  }
  return crypt.contents;
}

function certificate(data) {
  return data instanceof Certificate ? data : Certificate.from_pem(asBuffer(data));
}

function keyIdOf(cert) {
  const id = cert.extension.subjectKeyIdentifier;
  return id ? Buffer.from(id).toString("hex") : null;
}

function asBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (typeof data === "string") return Buffer.from(data, "base64");
  return Buffer.from(data);
}

module.exports = {
  openKey,
  hasCertificates,
  publicKeys,
  describeKey,
  isTaxpayersKey,
  signTin,
  signFskoCommand,
  wrapForCabinet,
  receiptQuery,
  receiptKey,
  cp1251
};
