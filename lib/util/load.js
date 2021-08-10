const fs = require("fs");
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

function load(keyInfo, algo) {
  console.log(`KEY INFO: ${keyInfo}`)
  let ret = []; 

  const content  = keyInfo.file[0] === 0x51 ? keyInfo.file.slice(6) : keyInfo.file;
  const jksStore = jksreader.parse(content);

  if (jksStore) {
    return loadJks(ret, jksStore, keyInfo.password);
  }

  let store;
  try {
    store = Priv.from_protected(content, keyInfo.password, algo);
  } catch (ignore) {
    throw new Error("Cant load key from store");
  }

  store.keys.forEach(priv => ret.push({ priv }));

  return ret;
}

module.exports = load;
module.exports.loadJks = loadJks;
