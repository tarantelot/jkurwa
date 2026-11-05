API changes

# v1.13.0 (tarantelot fork)

- `lib/cabinet.js` / `jkurwa/browser`: the DPS Electronic Cabinet from the browser -- the signed tin and FSKO commands, a filing wrapped for the cabinet, a 1-ПРРО receipt query, a receipt's content key; checked against mistokasa_dstu / mistokasa_documents;
- `Message#contentKey()` / `Priv#unwrapKey()`: an envelope's content key without decrypting the content (`decrypt()` uses them);
- key loading takes `file` (bytes) together with `certBuffers` again, as before 2021's rewrite dropped them (and `keyBuffers`, `priv`/`cert`, PEMs) -- a Key-6.dat holds no certificates; paths are read on node only;
- a browser build: `browser.js`, and package.json's `browser` field leaves out fs/http/url and the CMP lookup;
- node: random bytes from `crypto.randomBytes` when `crypto.rng` (gone from current node) isn't there;
- no `LoadMaterial...` console log.

# v1.7.0

- (breaking change) box.unwrap() is now async and returns a promise to accomodate ocsp checks;
- keyPath and certPath in `new Box(opts.keys)` and `box.load()` are deprecated and would be removed soon.
