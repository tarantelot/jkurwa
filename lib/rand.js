// This file should be used on node
// Bundler should replace it with
// rand.browser.js for browsers
const crypto = require('crypto');

// crypto.rng (an old alias of randomBytes) is gone from current node; the tests mock it.
const randomBytes = (crypto.rng || crypto.randomBytes).bind(crypto);

module.exports = function(xb) {
  const ret = randomBytes(xb.length);
  for(let i=0; i< xb.length; i++) {
    xb[i] = ret[i];
  }
  return ret;
};
