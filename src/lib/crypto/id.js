import { regexBase64Url } from "#src/lib/regex"


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
 * @function isBase64UrlIdValid
 * @param {string} id
 * @param {number} [length] - The length of a correct ID string (24 by default).
 * @returns {boolean}
 */
export function isBase64UrlIdValid(id, length = 24) {
  return id.length === length && regexBase64Url.test(id)
}