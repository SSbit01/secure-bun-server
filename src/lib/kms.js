/**
 * This server generates Key Encryption Keys (KEKs) with their IDs, and it needs to store them somewhere.
 * This file defines functions for storing KEKs.
 * 
 * Therefore, a simple in-memory KMS implementation has been defined using a JavaScript Map.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist KEKs, so all KEKs will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g. multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening.
 * - Redis, DynamoDB or similar are the best alternatives.
 * 
 * A custom key rotation implementation with envelope encryption with a specialized KMS is recommended.
 */

import { BASE64URL_OPTIONS } from "#src/lib/base64"
import { KEK_ID_LENGTH, SESSION_MAX_AGE_MS } from "#src/lib/computed"
import { createId, isBase64UrlIdValid } from "#src/lib/crypto/id"
import { WRAPPED_DEK_BYTES, createKek, unwrapKey } from "#src/lib/crypto/symmetric/kek"



/**
 * @typedef {[expires:number,rotate:number,key:CryptoKey]} KeyData
 */



const EXPIRES = 0
const ROTATE = 1
const KEY = 2

const ROTATE_TIME = 7776000000  // 90 days in miliseconds.



/**
 * @type {number}
 */
export const KEK_ID_BYTES = 12

/**
 * @type {number}
 */
export const MAX_KMS_STORE_ATTEMPTS = 3



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
      return await this.pushNewKey()
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
   * Pushes a new encryption key to the KMS.
   * 
   * @async
   * @function pushNewKey
   * @return {Promise<string>} The ID of the stored key.
   */
  async pushNewKey() {

    let newKeyId = ""
  
    let i = 0

    do {
      newKeyId = createId(KEK_ID_BYTES).toBase64(BASE64URL_OPTIONS)
      i++
    } while(!await this.store(newKeyId, await createKek()) && i < MAX_KMS_STORE_ATTEMPTS)
    if (i >= MAX_KMS_STORE_ATTEMPTS) {
      throw new Error("Too many attempts to store a KEK in KMS: " + this.#name)
    }

    return newKeyId
  
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
    let newKeyId = ""

    if (keyId === await this.getCurrentId()) {
      const prefix = this.#name + "/" + keyId + ": "
      console.warn(prefix + "An emergency rotation of the current KEK has been initiated.")
      newKeyId = await this.pushNewKey()
      console.log(prefix + "KEK rotation completed.")
    }

    /**
     * Get or generate the key first to ensure that when the `keyId` is deleted, there is at least one key in the KMS.
     */
    this.#storage.delete(keyId)

    return newKeyId

  }
  
  
  /**
   * Stores an encryption key with the given ID and expiration time.
   * 
   * If the key could not be saved due to a technical error, an error should be thrown.
   * 
   * @async
   * @function store
   * @param {string} keyId - The ID of the encryption key to store.
   * @param {CryptoKey} key - The encryption key to store.
   * @return {Promise<boolean>} Whether the key was stored successfully.
   */
  async store(keyId, key) {
  
    // Manually clean up expired keys, as this implementation cannot automatically delete them.
    
    const dateNow = Date.now()
  
    for (const [currentKeyId, [currentExpires]] of this.#storage) {
      if (currentExpires <= dateNow) {
        this.#storage.delete(currentKeyId)
      }
    }

    if (this.#storage.has(keyId)) {
      return false
    }
  
    const rotate = dateNow + ROTATE_TIME
  
    this.#storage.set(keyId, [rotate + this.#ageMsAfterRotation, rotate, key])
  
    return true
  
  }

}