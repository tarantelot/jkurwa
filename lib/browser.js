/*
 * The browser entry: `import { cabinet, Box, Certificate, Message, transport } from "jkurwa/browser"`.
 *
 * Nothing here reaches node's fs/http (no CMP lookup, no OCSP, no key paths): a browser gives the key
 * container's bytes and its certificates, and gets timestamps, when it wants them, through its own
 * `query`. Bundle with webpack 5 / vite / esbuild -- package.json's "browser" field swaps the node-only
 * modules out; `Buffer` is set up below from the `buffer` package, which bundlers no longer
 * polyfill on their own.
 */
const { Buffer } = require("buffer");

if (typeof globalThis.Buffer === "undefined") {
  globalThis.Buffer = Buffer;
}
if (typeof globalThis.global === "undefined") {
  globalThis.global = globalThis; // rand.browser.js reads global.crypto
}

const cabinet = require("./cabinet");
const Box = require("./app/ctx");
const models = require("./models/index");
const transport = require("./util/transport");

module.exports = {
  cabinet,
  Box,
  Certificate: models.Certificate,
  Message: models.Message,
  Priv: models.Priv,
  transport
};
