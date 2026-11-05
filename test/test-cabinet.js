/* eslint-env jest */
/*
 * lib/cabinet.js on the DPS's test key (Key-6.dat, its certificates apart -- the container holds
 * none), against what mistokasa_dstu (the services' Python port) makes and reads:
 * data/kasa24/receipt_* is an envelope mistokasa_dstu encrypted to Key-6, and the content key it
 * unwraps from it.
 */
const fs = require("fs");
const assert = require("assert");
const gost89 = require("gost89");
const cabinet = require("../lib/cabinet");
const Message = require("../lib/models/Message");
const Certificate = require("../lib/models/Certificate");
const transport = require("../lib/util/transport");

const DATA = `${__dirname}/data/kasa24`;
const TIN = "2272714854";
const KEY = fs.readFileSync(`${DATA}/Key-6.dat`);
const SIGN_CERT = fs.readFileSync(`${DATA}/key6_sign.cer`);
const ENC_CERT = fs.readFileSync(`${DATA}/key6_encrypt.cer`);
const TIME = Date.UTC(2024, 0, 15, 10, 0, 0) / 1000; // inside the test certificate's validity (2023-08-24 .. 2024-08-22)

function openBox() {
  return cabinet.openKey({ file: KEY, password: TIN, certs: [SIGN_CERT, ENC_CERT] });
}

function decryptedBy(box, enveloped) {
  const message = new Message(enveloped);
  const ours = box.keyFor("encrypt", undefined, message.receiverKey);
  return message.decrypt(ours.priv, box.algo, query => box.lookupCert([new Certificate(Certificate.from_pem(ENC_CERT).ob)], query));
}

function signedContent(box, data) {
  const message = new Message(data);
  assert.equal(message.type, "signedData");
  assert.ok(message.verify(box.algo.hash, () => null), "the signature checks out with the attached certificate");
  return message;
}

describe("cabinet", () => {
  const box = openBox();

  it("opens a key container whose certificates come apart, and says whose key it is", () => {
    const info = cabinet.describeKey(box);
    assert.equal(info.drfo || info.edrpou, TIN);
    assert.ok(info.validTo > info.validFrom);
    assert.ok(info.canEncrypt);
    assert.ok(cabinet.isTaxpayersKey(box, TIN));
    assert.ok(!cabinet.isTaxpayersKey(box, "1234567890"));
  });

  it("refuses a wrong password", () => {
    assert.throws(() => cabinet.openKey({ file: KEY, password: "nope", certs: [SIGN_CERT, ENC_CERT] }), /Cant load key/);
  });

  it("signs the tin: CAdES over its ASCII digits, the certificate attached, signed at the given time, no timestamp", async () => {
    const message = signedContent(box, await cabinet.signTin(box, TIN, { time: TIME }));
    assert.equal(message.content.toString("ascii"), TIN);
    assert.equal(message.info.certificate.length, 1);
    assert.equal(Number(message.pattrs.signingTime), TIME * 1000);
    assert.equal(message.puattrs.timeStampToken, undefined);
    assert.equal(message.pattrs.contentTimeStamp, undefined);
  });

  it("signs FSKO's commands byte for byte, and nothing else", async () => {
    const message = signedContent(box, await cabinet.signFskoCommand(box, "Operators", { time: TIME }));
    assert.equal(message.content.toString("utf8"), '{"Command":"Operators"}');
    await assert.rejects(cabinet.signFskoCommand(box, "Delete"), /one of Objects, Operators/);
  });

  it("wraps a filing for the cabinet: headers, CERTCRYPT and UA1_CRYPT under the signature; inside the envelope only the signed XML", async () => {
    const xml = Buffer.from('<?xml version="1.0" encoding="windows-1251"?><DECLAR/>', "binary");
    const container = await cabinet.wrapForCabinet(box, {
      xml, filename: "26550012345678J1316605100000000111020262655.xml", recipientCert: ENC_CERT,
      email: "owner@example.com", time: TIME, now: new Date(TIME * 1000)
    });

    const outer = transport.decode(container);
    assert.deepEqual(outer.docs.map(d => d.type), ["UA1_SIGN"]);
    assert.equal(outer.header.FILENAME, "26550012345678J1316605100000000111020262655.xml");
    assert.equal(outer.header.EDRPOU, TIN);
    assert.equal(outer.header.SND_DATE, "20240115100000");
    assert.equal(outer.header.RCV_EMAIL, "owner@example.com");

    const middle = transport.decode(signedContent(box, outer.docs[0].contents).content);
    assert.deepEqual(middle.docs.map(d => d.type), ["CERTCRYPT", "UA1_CRYPT"]);
    assert.equal(middle.header.FILENAME, outer.header.FILENAME);
    assert.deepEqual(middle.docs[0].contents, Certificate.from_pem(ENC_CERT).as_asn1());

    const inner = transport.decode(decryptedBy(box, middle.docs[1].contents));
    assert.equal(inner.header, undefined, "no transport header inside the envelope (the cabinet: ERROR_SERTIF)");
    assert.deepEqual(inner.docs.map(d => d.type), ["UA1_SIGN"]);
    assert.deepEqual(signedContent(box, inner.docs[0].contents).content, xml);
  });

  it("writes the organisation's name in cp1251, as the services do", () => {
    assert.deepEqual(cabinet.cp1251("ТОВ «Каса»"), Buffer.from([0xd2, 0xce, 0xc2, 0x20, 0xab, 0xca, 0xe0, 0xf1, 0xe0, 0xbb]));
    assert.deepEqual(cabinet.cp1251("Їжак є і ґ"), Buffer.from([0xaf, 0xe6, 0xe0, 0xea, 0x20, 0xba, 0x20, 0xb3, 0x20, 0xb4]));
  });

  it("makes a 1-ПРРО's receipt query: CERTCRYPT, UA1_CRYPT of the signed cabinet id, no headers", async () => {
    const query = await cabinet.receiptQuery(box, { cabinetId: 98765, recipientCert: ENC_CERT, time: TIME });

    const outer = transport.decode(query);
    assert.equal(outer.header, undefined);
    assert.deepEqual(outer.docs.map(d => d.type), ["CERTCRYPT", "UA1_CRYPT"]);
    const inner = transport.decode(decryptedBy(box, outer.docs[1].contents));
    assert.deepEqual(inner.docs.map(d => d.type), ["UA1_SIGN"]);
    assert.equal(signedContent(box, inner.docs[0].contents).content.toString("ascii"), "98765");
    await assert.rejects(cabinet.receiptQuery(box, { cabinetId: "98a", recipientCert: ENC_CERT }), /cabinetId/);
  });

  it("unwraps a receipt's content key -- the one mistokasa_dstu unwraps, and it decrypts the receipt", () => {
    const envelope = fs.readFileSync(`${DATA}/receipt_envelope.bin`);
    const cek = cabinet.receiptKey(box, envelope, [ENC_CERT]);

    assert.equal(cek.length, 32);
    assert.equal(Buffer.from(cek).toString("hex"), fs.readFileSync(`${DATA}/receipt_cek.hex`, "utf8").trim());
    const message = new Message(transport.decode(envelope).docs[0].contents);
    const enc = message.info.encryptedContentInfo;
    const text = gost89.compat.algos().decrypt(enc.encryptedContent, cek, enc.contentEncryptionAlgorithm.parameters.value.iv);
    assert.deepEqual(Buffer.from(text), fs.readFileSync(`${DATA}/receipt_text.txt`));
  });

  it("takes the envelope as base64 too", () => {
    const envelope = fs.readFileSync(`${DATA}/receipt_envelope.bin`).toString("base64");
    assert.equal(cabinet.receiptKey(box, envelope, [ENC_CERT]).length, 32);
  });
});
