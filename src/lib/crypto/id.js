import { BASE64URL_OPTIONS } from "#src/lib/base64"
import { regexBase64, regexBase64Url } from "#src/lib/regex"


/**
 * This implementation generates a cryptographically secure 144-bit length random value by default.
 * 
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 * 
 * @function createId
 * @param {number} [length] - The length of the ID to generate (18 by default; higher entropy than UUIDv4 [122 vs 144 bits]).
 * @returns {Uint8Array<ArrayBuffer>} A random ID.
 */
export function createId(length = 18) {
  return crypto.getRandomValues(new Uint8Array(length))
}


/**
 * @function createBase64UrlId
 * @param {number} [length] - The length (in bytes) of the ID to generate (18 by default; higher entropy than UUIDv4 [122 vs 144 bits]).
 * @returns {string} A string random ID.
 */
export function createBase64UrlId(length = 18) {
  return createId(length).toBase64(BASE64URL_OPTIONS)
}


/**
 * @function isBase64IdValid
 * @param {string} id
 * @param {number} [length] - The length of a correct ID string (24 by default).
 * @returns {boolean}
 */
export function isBase64IdValid(id, length = 24) {
  return id.length === length && regexBase64.test(id)
}


/**
 * @function isBase64UrlIdValid
 * @param {string} id
 * @param {number} [length] - The length of a correct ID string (24 by default).
 * @returns {boolean}
 */
export function isBase64UrlIdValid(id, length = 24) {
  return id.length === length && regexBase64Url.test(id)
}