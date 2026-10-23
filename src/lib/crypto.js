import { BASE64URL_OPTIONS } from "#src/lib/base64";
import { textDecoder, textEncoder } from "#src/lib/codec";

const IV_BYTES = 12;

const KEY_WRAP_ALGORITHM_NAME = "AES-KW";

const SYMMETRIC_ENCRYPTION_ALGORITHM_NAME = "AES-GCM";

/**
 * @type {AesKeyGenParams}
 */
const KEY_ENCRYPTION_PARAMS = Object.freeze({
  length: 256,
  name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME
});

/**
 * @type {Readonly<KeyUsage[]>}
 */
const KEY_ENCRYPTION_USAGES = Object.freeze(["encrypt", "decrypt"]);

/**
 * @type {AesKeyGenParams}
 */
const KEY_WRAP_PARAMS = Object.freeze({
  length: 256,
  name: KEY_WRAP_ALGORITHM_NAME
});

/**
 * @type {readonly KeyUsage[]}
 */
const KEY_WRAP_USAGES = Object.freeze(["wrapKey", "unwrapKey"]);

/**
 * 32 (original DEK size) + 8 (AES-KW overhead) = 40
 */
export const WRAPPED_DEK_BYTES = KEY_ENCRYPTION_PARAMS.length / 8 + 8;

/**
 * @async
 * @function createKek
 * @returns {Promise<CryptoKey>}
 */
export async function createKek() {
  return await crypto.subtle.generateKey(KEY_WRAP_PARAMS, true, KEY_WRAP_USAGES);
}

/**
 * Before encrypting and decrypting values, a symmetric `CryptoKey` must be created.
 *
 * @async
 * @function createDek
 * @returns {Promise<CryptoKey>} A `CryptoKey` containing a SHA-256 hash used to encrypt and decrypt strings.
 */
export async function createDek() {
  return await crypto.subtle.generateKey(KEY_ENCRYPTION_PARAMS, true, KEY_ENCRYPTION_USAGES);
}

/**
 * Encrypts a value with a `CryptoKey` previously generated with `createDek`.
 *
 * @async
 * @function encryptTextSymmetrically
 * @param {CryptoKey} key - Symmetric key generated with `createDek`.
 * @param {string} text - String value to be encrypted.
 * @param {BufferSource} [additionalData] - Additional data for authentication.
 * @returns {Promise<string>} The value encrypted and encoded as a Base64 string.
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed (e.g. AES-GCM plaintext longer than 2^39−256 bytes).
 */
export async function encryptTextSymmetrically(key, text, additionalData) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const encryptedText = new Uint8Array(
    await crypto.subtle.encrypt({ additionalData, iv, name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME }, key, textEncoder.encode(text))
  );

  const result = new Uint8Array(IV_BYTES + encryptedText.length);

  result.set(iv);
  result.set(encryptedText, IV_BYTES);

  return result.toBase64(BASE64URL_OPTIONS);
}

/**
 * @async
 * @function decryptTextSymmetrically
 * @param {CryptoKey} key
 * @param {string} ciphertext
 * @param {BufferSource} [additionalData] - Additional data for authentication.
 * @returns {Promise<string>}
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptTextSymmetrically(key, ciphertext, additionalData) {
  const data = Uint8Array.fromBase64(ciphertext, BASE64URL_OPTIONS);

  return textDecoder.decode(
    await crypto.subtle.decrypt(
      {
        additionalData,
        iv: data.subarray(0, IV_BYTES),
        name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME
      },
      key,
      data.subarray(IV_BYTES)
    )
  );
}

/**
 * @async
 * @function unwrapKey
 * @param {BufferSource} wrappedKey
 * @param {CryptoKey} kek
 * @returns {Promise<CryptoKey>}
 * @throws {InvalidAccessError} Raised when the wrapping key is not a key for the requested wrap algorithm.
 * @throws {NotSupported} Raised when trying to use an algorithm that is either unknown or isn't suitable for encryption or wrapping.
 * @throws {SyntaxError} Raised when `keyUsages` is empty but the unwrapped key is of type `secret` or `private`.
 * @throws {TypeError} Raised when trying to use an invalid format.
 */
export async function unwrapKey(wrappedKey, kek) {
  return await crypto.subtle.unwrapKey("raw", wrappedKey, kek, KEY_WRAP_ALGORITHM_NAME, KEY_ENCRYPTION_PARAMS, false, KEY_ENCRYPTION_USAGES);
}

/**
 * @async
 * @function wrapKey
 * @param {CryptoKey} key
 * @param {CryptoKey} kek
 * @returns {Promise<ArrayBuffer>}
 * @throws {InvalidAccessError} Raised when the wrapping key is not a key for the requested wrap algorithm.
 * @throws {NotSupported} Raised when trying to use an algorithm that is either unknown or isn't suitable for encryption or wrapping.
 * @throws {TypeError} Raised when trying to use an invalid format.
 */
export async function wrapKey(key, kek) {
  return await crypto.subtle.wrapKey("raw", key, kek, KEY_WRAP_ALGORITHM_NAME);
}
