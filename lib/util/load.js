const jksreader = require("jksreader");

const complain = require("./complain");
const Priv = require("../models/Priv");
const Certificate = require("../models/Certificate");

function loadJks(ret, store, password) {
  if (!password) {
    throw new Error("JKS file format requires password to be opened");
  }
  for (let part of store.material) {
    const buf = jksreader.decode(part.key, password);
    if (!buf) {
      throw new Error("Cant load key from store, check password");
    }
    const rawStore = Priv.from_asn1(buf, true);
    for (let cert of part.certs) {
      ret.push({ cert: Certificate.from_pem(cert) });
    }
    for (let priv of rawStore.keys) {
      ret.push({ priv });
    }
  }
  return ret;
}

// A key container's bytes: JKS (its certificates come with it), or IIT Key-6.dat / PKCS#8 / PFX
// protected by the password (certificates given separately, `certBuffers`).
function loadContainer(ret, buf, password, algo) {
  // detect garbage in file header (meeedok)
  const content = buf[0] === 0x51 ? buf.slice(6) : buf;
  const jksStore = jksreader.parse(content);
  if (jksStore) {
    return loadJks(ret, jksStore, password);
  }
  let store;
  try {
    store = Priv.from_protected(content, password, algo);
  } catch (reason) {
    // Keep the historical "Cant load key from store" prefix (callers match on
    // it), but append and attach the real cause: a wrong password, an
    // unsupported container format, and an unsupported cipher all used to look
    // identical, which sent debugging down the wrong path.
    const err = new Error("Cant load key from store: " + reason.message);
    err.cause = reason;
    throw err;
  }
  store.keys.forEach(priv => ret.push({ priv }));
  return ret;
}

// Paths are read from disk on node only -- a browser passes bytes (`file`, `keyBuffers`, `certBuffers`).
function readPaths(paths, what) {
  complain(`keyinfo.${what} is deprecated and would be removed`);
  const fs = require("fs"); // eslint-disable-line global-require
  return (typeof paths === "string" ? [paths] : paths || []).map(path =>
    fs.readFileSync(path)
  );
}

function asBuffer(data) {
  return Buffer.isBuffer(data) ? data : Buffer.from(data);
}

/*
 * keyinfo:
 *   file, password          one key container (bytes) -- what the browser reads from the picked file
 *   keyBuffers, password    several
 *   certBuffers             certificates (DER or PEM) -- needed for a container that holds none
 *   priv / cert             already parsed
 *   privPem / certPem       PEM text or bytes
 *   privPath / certPath     node only, deprecated
 */
function load(keyinfo, algo) {
  const ret = [];
  if (keyinfo.priv && keyinfo.priv.type === "Priv") {
    ret.push({ priv: keyinfo.priv });
  }
  if (keyinfo.cert && keyinfo.cert.format === "x509") {
    ret.push({ cert: keyinfo.cert });
  }
  if (keyinfo.privPem) {
    ret.push({ priv: Priv.from_pem(keyinfo.privPem) });
  }
  if (keyinfo.certPem) {
    ret.push({ cert: Certificate.from_pem(keyinfo.certPem) });
  }

  let keyBuffers = (keyinfo.keyBuffers || []).map(asBuffer);
  if (keyinfo.file) {
    keyBuffers = [asBuffer(keyinfo.file), ...keyBuffers];
  }
  if (keyinfo.privPath) {
    keyBuffers = [...keyBuffers, ...readPaths(keyinfo.privPath, "privPath")];
  }
  let certBuffers = (keyinfo.certBuffers || []).map(asBuffer);
  if (keyinfo.certPath) {
    certBuffers = [...certBuffers, ...readPaths(keyinfo.certPath, "certPath")];
  }

  keyBuffers.forEach(buf => loadContainer(ret, buf, keyinfo.password, algo));
  certBuffers.forEach(cert => ret.push({ cert: Certificate.from_pem(cert) }));
  return ret;
}

module.exports = load;
module.exports.loadJks = loadJks;
