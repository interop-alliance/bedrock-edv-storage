/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc.
 */
import * as base58 from 'base58-universal';
import * as bedrock from '@bedrock/core';
import etag from 'etag';
import forwarded from 'forwarded';
import ipaddr from 'ipaddr.js';
import {promisify} from 'node:util';
import {randomBytes} from 'node:crypto';

const {config, util: {BedrockError}} = bedrock;
const getRandomBytes = promisify(randomBytes);

/**
 * @typedef {import('@interop/data-integrity-core').IEDVConfig} IEDVConfig
 */

/**
 * Asserts that the given ID is a base58-encoded multibase, multicodec array of
 * 16 random bytes (a 128-bit identifier). Throws if it is not.
 *
 * @param {string} id - The identifier to validate.
 */
export function assert128BitId(id) {
  try {
    // verify ID is base58-encoded multibase multicodec encoded 16 bytes
    const buf = base58.decode(id.substr(1));
    // multibase base58 (starts with 'z')
    // 128-bit random number, multicodec encoded
    // 0x00 = identity tag, 0x10 = length (16 bytes) + 16 random bytes
    if(!(id.startsWith('z') &&
      buf.length === 18 && buf[0] === 0x00 && buf[1] === 0x10)) {
      throw new Error('Invalid identifier.');
    }
  } catch {
    throw new BedrockError(
      `Identifier "${id}" must be base58-encoded multibase, ` +
      'multicodec array of 16 random bytes.',
      'SyntaxError',
      {public: true, httpStatusCode: 400});
  }
}

/**
 * Builds the full EDV ID URL from a local 128-bit identifier.
 *
 * @param {object} options - The options to use.
 * @param {string} options.localId - The local 128-bit EDV identifier.
 *
 * @returns {string} The full EDV ID URL.
 */
export function getEdvId({localId} = {}) {
  assert128BitId(localId);
  const {baseUri} = config.server;
  const baseStorageUrl = `${baseUri}${config['edv-storage'].routes.basePath}`;
  return `${baseStorageUrl}/${localId}`;
}

/**
 * Builds the map of EDV HTTP routes derived from the configured base path.
 *
 * @returns {object} The map of route paths keyed by name.
 */
export function getRoutes() {
  const cfg = config['edv-storage'];

  // Note: EDV routes are fixed off of the base path per the spec
  const routes = {...cfg.routes};
  routes.edvs = routes.basePath;
  routes.edv = `${routes.edvs}/:edvId`;
  routes.documents = `${routes.edv}/documents`;
  routes.document = `${routes.documents}/:docId`;
  routes.chunk = `${routes.document}/chunks/:chunkIndex`;
  routes.query = `${routes.edv}/query`;
  routes.revocations = `${routes.edv}/zcaps/revocations/:revocationId`;

  return routes;
}

/**
 * Generates a new random, multibase base58-encoded 128-bit identifier.
 *
 * @returns {Promise<string>} Resolves to the encoded identifier (prefixed with
 *   `z`).
 */
export async function generateRandom() {
  // 128-bit random number, multibase encoded
  // 0x00 = identity tag, 0x10 = length (16 bytes)
  const buf = Buffer.concat([
    Buffer.from([0x00, 0x10]),
    await getRandomBytes(16)
  ]);
  // multibase encoding for base58 starts with 'z'
  return `z${base58.encode(buf)}`;
}

/**
 * Splits a full EDV-namespaced ID into its base URL and decoded local ID.
 *
 * @param {object} options - The options to use.
 * @param {string} options.id - The full ID, formatted as `<base>/<localId>`.
 *
 * @returns {{base: string, localId: Buffer}} The base URL and the decoded
 *   local ID as a `Buffer`.
 */
export function parseLocalId({id}) {
  // format: <base>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.substr(idx + 1);
  return {
    base: id.substring(0, idx),
    localId: decodeLocalId({localId})
  };
}

/**
 * Decodes a multibase base58-encoded local ID into the raw 16-byte value,
 * stripping the multicodec header, for compact storage as a `Buffer`.
 *
 * @param {object} options - The options to use.
 * @param {string} options.localId - The encoded local ID (prefixed with `z`).
 *
 * @returns {Buffer} The decoded 16-byte identifier.
 */
export function decodeLocalId({localId}) {
  // convert to `Buffer` for storage savings (`z<base58-encoded ID>`)
  // where the ID is multicodec encoded 16 byte random value
  // 0x00 = identity tag, 0x10 = length (16 bytes) header
  return Buffer.from(base58.decode(localId.slice(1)).slice(2));
}

/**
 * Validates that the given document sequence number is a non-negative safe
 * integer below `Number.MAX_SAFE_INTEGER`. Throws if it is not.
 *
 * @param {number} sequence - The document sequence number to validate.
 */
export function validateDocSequence(sequence) {
  // doc.sequence is limited to MAX_SAFE_INTEGER - 1 to avoid unexpected
  // behavior when a client attempts to increment the sequence number.
  if(!Number.isSafeInteger(sequence) ||
    !(sequence < Number.MAX_SAFE_INTEGER)) {
    throw new TypeError('"doc.sequence" number is too large.');
  }
  // Note: `doc.sequence === 0` is intentionally not enforced at this time
  // to allow for easier copying of documents from other EDVs, this
  // may change in the future
  if(sequence < 0) {
    throw new TypeError('"doc.sequence" must be a non-negative integer.');
  }
}

/**
 * Verifies that the request originates from an IP permitted by the EDV
 * config's `ipAllowList`. If no allow list is configured, the request is
 * permitted.
 *
 * @param {object} options - The options to use.
 * @param {IEDVConfig} options.edvConfig - The EDV configuration.
 * @param {object} options.req - The Express request to check.
 *
 * @returns {{verified: boolean}} Whether the source IP is allowed.
 */
export function verifyRequestIp({edvConfig, req}) {
  // skip check if no IP allow list configured
  const {ipAllowList} = edvConfig;
  if(!ipAllowList) {
    return {verified: true};
  }

  // the first IP in the sourceAddresses array will *always* be the IP
  // reported by Express.js via `req.connection.remoteAddress`. Any additional
  // IPs will be from the `x-forwarded-for` header.
  const sourceAddresses = forwarded(req);

  // build list of allowed IP ranges from IPv4/IPv6 CIDRs
  const ipAllowRangeList = {
    allow: ipAllowList.map(cidr => ipaddr.parseCIDR(cidr))
  };

  // check if any source address allowed
  const verified = sourceAddresses.some(address => {
    const ip = ipaddr.parse(address);
    // check if in allow list, else deny
    return ipaddr.subnetMatch(ip, ipAllowRangeList, 'deny') === 'allow';
  });

  return {verified};
}

/**
 * Sends a JSON response with an ETag and cache headers set so the response can
 * be revalidated by clients via conditional requests.
 *
 * @param {object} options - The options to use.
 * @param {object} options.res - The Express response to write to.
 * @param {object} options.obj - The object to serialize and send as JSON.
 */
export function sendCacheableJson({res, obj}) {
  // compute e-tag to enable caching
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.header('content-type', 'application/json');
  // "private": store in per-user cache only
  // "no-cache": client must perform the request again, but should send the
  // e-tag so the request can be revalidated against it; the response will
  // send "304 Not Modified" if the hash matches, otherwise it will send the
  // full response
  res.header('cache-control', 'private, no-cache');
  res.header('etag', etag(body));
  res.removeHeader('expires');
  res.removeHeader('pragma');
  res.send(body);
}
