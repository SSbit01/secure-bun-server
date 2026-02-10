import { BASE64URL_OPTIONS } from "#src/lib/base64"
import { KEK_ID_LENGTH, SESSION_MAX_AGE_MS } from "#src/lib/computed"
import { createBase64UrlId, isBase64UrlIdValid } from "#src/lib/crypto/id"
import { WRAPPED_DEK_BYTES, createKek, unwrapKey } from "#src/lib/crypto/symmetric/kek"



/**
 * @typedef {[expires:number,rotate:number,key:CryptoKey]} KeyData
 */



const EXPIRES = 0
const ROTATE = 1
const KEY = 2

const MAX_STORE_ATTEMPTS = 3
const ROTATE_TIME = 7776000000  // 90 days in miliseconds.



/**
 * @type {number}
 */
export const KEK_ID_BYTES = 12



export default class KMS {

  #ageMsAfterRotation

  #name

  /**
   * @type {Map<string,KeyData>}
   */
  #storage = new Map()


  /**
   * @param {number} [ageMsAfterRotation] - In milliseconds.
   * @param {string} [name] - Give it a name. Useful when displaying warnings.
   */
  constructor(ageMsAfterRotation = SESSION_MAX_AGE_MS, name) {
    this.#ageMsAfterRotation = ageMsAfterRotation
    this.#name = name
  }


  /**
   * Retrieves an encryption key by its ID.
   * 
   * @async
   * @function getCurrentId
   * @return {Promise<string>} A promise that resolves to the `CurrentKey`.
   */
  async getCurrentId() {
  
    // Manually clean up expired keys, as this implementation cannot automatically delete them.
  
    /**
     * @type {([string,KeyData]|undefined)}
     */
    let currentKeyEntry
  
    const dateNow = Date.now()
  
    for (const keyEntry of this.#storage) {
      const expires = keyEntry[1][EXPIRES]
      if (expires <= dateNow) {
        this.#storage.delete(keyEntry[0])
      } else if (!currentKeyEntry || expires < currentKeyEntry[1][EXPIRES]) {
        currentKeyEntry = keyEntry
      }
    }
  
    if (!currentKeyEntry || currentKeyEntry[1][ROTATE] <= dateNow) {
      return await this.store(await createKek())
    }
  
    return currentKeyEntry[0]
  
  }
  
  
  /**
   * Retrieves an encryption key by its ID.
   * 
   * @async
   * @function get
   * @param {string} keyId - The ID of the encryption key to retrieve.
   * @return {Promise<CryptoKey|undefined>} A promise that resolves to the `CryptoKey` if found, otherwise `undefined`.
   */
  async get(keyId) {

    if (!isBase64UrlIdValid(keyId, KEK_ID_LENGTH)) {
      return
    }
  
    const keyData = this.#storage.get(keyId)
  
    if (!keyData) {
      return
    }
  
    if (keyData[EXPIRES] <= Date.now()) {
      this.#storage.delete(keyId)
      return
    }
  
    return keyData[KEY]
  
  }


  /**
   * @async
   * @function getDek
   * @param {string} keyId 
   * @param {string} wrappedDekString 
   * @returns {Promise<CryptoKey|undefined>}
   */
  async getDek(keyId, wrappedDekString) {

    const kek = await this.get(keyId)

    if (!kek) {
      return
    }

    /**
     * @type {Uint8Array<ArrayBuffer>}
     */
    let wrappedDek

    try {
      wrappedDek = Uint8Array.fromBase64(wrappedDekString, BASE64URL_OPTIONS)
    } catch {
      return
    }

    if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
      return
    }

    return await unwrapKey(wrappedDek, kek)

  }


  /**
   * Retrieves an encryption key by its ID.
   * 
   * @async
   * @function rotate
   * @param {string} keyId - The ID of the encryption key that is suspicious of being leaked.
   * @return {Promise<string>} The ID of the stored key or an emptry string if the key rotation was not triggered.
   */
  async rotate(keyId) {

    /**
     * @type {string}
     */
    let id = ""

    if (keyId === await this.getCurrentId()) {
      const prefix = this.#name + "/" + keyId + ": "
      console.warn(prefix + "An emergency rotation of the current KEK has been initiated.")
      id = await this.store(await createKek())
      console.log(prefix + "KEK rotation completed.")
    }

    /**
     * Get or generate the key first to ensure that when the `keyId` is deleted, there is at least one key in the KMS.
     */
    this.#storage.delete(keyId)

    return id

  }
  
  
  /**
   * Stores an encryption key with the given ID and expiration time.
   * 
   * If the key could not be saved due to a technical error, an error should be thrown.
   * 
   * @async
   * @function store
   * @param {CryptoKey} key - The encryption key to store.
   * @return {Promise<string>} The ID of the stored key.
   */
  async store(key) {
  
    // Manually clean up expired keys, as this implementation cannot automatically delete them.
    
    const dateNow = Date.now()
  
    for (const [keyId, [expires]] of this.#storage) {
      if (expires <= dateNow) {
        this.#storage.delete(keyId)
      }
    }
  
    const rotate = dateNow + ROTATE_TIME
  
    /**
     * @type {KeyData}
     */
    const data = [rotate + this.#ageMsAfterRotation, rotate, key]
    
    /**
     * @type {string}
     */
    let id

    let i = 0
  
    do {
      id = createBase64UrlId(KEK_ID_BYTES)
      i++
    } while (this.#storage.has(id) && i < MAX_STORE_ATTEMPTS)
    
    if (i >= MAX_STORE_ATTEMPTS) {
      throw new Error("Too many attempts to store a key in: " + this.#name)
    }
  
    this.#storage.set(id, data)
  
    return id
  
  }

}