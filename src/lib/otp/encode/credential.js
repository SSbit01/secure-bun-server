/**
 * @function encodeCredential
 * @param {string} credential
 * @returns {string}
 */
export function encodeCredential(credential) {
  return encodeURIComponent(credential)
}


/**
 * @function decodeCredential
 * @param {string} encodedCredential
 * @returns {string}
 */
export function decodeCredential(encodedCredential) {
  return decodeURIComponent(encodedCredential).trim()
}