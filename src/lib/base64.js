/** @type {Parameters<Uint8Array<ArrayBuffer>["toBase64"]>[0]} */
export const BASE64URL_OPTIONS = Object.freeze({
  alphabet: "base64url",
  omitPadding: true
})


/**
 * @function bytesToBase64Length
 * @param {number} bytesLength - The number of bytes to convert
 * @returns {number} The length of the base64 string (without padding).
 */
export function bytesToBase64Length(bytesLength) {
  return Math.ceil(bytesLength / 3 * 4)
}


/**
 * @function base64toUrl
 * @param {string} base64
 * @return {string}
 */
export function base64toUrl(base64) {
  return Uint8Array.fromBase64(base64).toBase64(BASE64URL_OPTIONS)
}