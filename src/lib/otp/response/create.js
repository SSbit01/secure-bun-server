import otpAttributes from "#shared/otp.json"

import { BASE64URL_OPTIONS } from "#src/lib/base64"
import { compressNumber } from "#src/lib/compression/number"
import { ENVELOPE_ENCRYPTION_WRAP_LENGTH, KEK_ID_LENGTH, OTP_RESEND_BLOCK_MS} from "#src/lib/computed"
import { createId } from "#src/lib/crypto/id"
import { createKek, wrapKey } from "#src/lib/crypto/symmetric/kek"
import { createDek, encryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek"
import { COOKIE_OTP } from "#src/lib/cookie"
import { KEK_ID_BYTES, MAX_KMS_STORE_ATTEMPTS } from "#src/lib/kms"
import { getOtpTokenList, setOtpCookie } from "#src/lib/otp"
import { createOtp } from "#src/lib/otp/custom"

import {
  CREDENTIAL,
  EXPIRES,
  createEncodedOtpToken,
  decodeOtpToken,
  encodeOtpToken,
  encodeOtpTokenData,
  encodeOtpTokenList
} from "#src/lib/otp/encode/token"

import { createOtpTokenListId, deleteOtpTokenId, updateOtpTokenExpires } from "#src/lib/otp/id"
import kmsOtp from "#src/lib/otp/kms"
import sendOtp from "#src/lib/otp/send"
import { APP_RES_INIT_200, APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"
import { msToSeconds } from "#src/lib/time"


/**
 * @async
 * @function generateOtpTokenListCreationResponse
 * @param {Bun.CookieMap} cookies
 * @param {string} credential
 * @return {Promise<Response>}
 */
async function generateOtpTokenListCreationResponse(cookies, credential) {

  const otp = createOtp()

  if (!await sendOtp(credential, otp)) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  let kekId = await kmsOtp.getCurrentId()

  /**
   * @type {(CryptoKey|undefined)}
   */
  let kek

  if (kekId) {
    kek = await kmsOtp.get(kekId)
  }

  /**
   * @type {Uint8Array<ArrayBuffer>}
   */
  let additionalData

  if (kek) {
    additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS)
  } else {
    let i = 0
    do {
      additionalData = createId(KEK_ID_BYTES)
      kekId = additionalData.toBase64(BASE64URL_OPTIONS)
      kek = await createKek()
      i++
    } while(!await kmsOtp.store(kekId, kek) && i < MAX_KMS_STORE_ATTEMPTS)
    if (i >= MAX_KMS_STORE_ATTEMPTS) {
      throw new Error("Too many attempts to store a KEK in KMS: OTP")
    }
  }

  const dek = await createDek()
  const wrappedDekString = new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)

  const [id, expires] = await createOtpTokenListId()

  const expiresSeconds = msToSeconds(expires, Math.trunc)
  const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS

  setOtpCookie(
    cookies,
    kekId +
    wrappedDekString +
    await encryptTextSymmetrically(
      dek,
      encodeOtpTokenList([createEncodedOtpToken(credential, expires, otp, resendBlock), id]),
      additionalData
    ),
    expiresSeconds
  )

  return new Response(
    compressNumber(expiresSeconds) + "," + compressNumber(msToSeconds(resendBlock, Math.ceil)),
    APP_RES_INIT_200
  )

}


/**
 * @async
 * @function
 * @param {Bun.CookieMap} cookies
 * @param {string} credential
 * @returns {Promise<Response>}
 */
export default async function generateOtpCreationResponse(cookies, credential) {

  const otpData = cookies.get(COOKIE_OTP)?.trim()

  if (!otpData) {
    return await generateOtpTokenListCreationResponse(cookies, credential)
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH)

  let dek = await kmsOtp.getDek(kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!dek) {
    return await generateOtpTokenListCreationResponse(cookies, credential)
  }

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!encodedOtpTokenList) {
    return await generateOtpTokenListCreationResponse(cookies, credential)
  }

  const id = encodedOtpTokenList.pop()

  if (!id) {
    cookies.delete(COOKIE_OTP)
    await kmsOtp.rotate(kekId)
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  if (!encodedOtpTokenList.length || encodedOtpTokenList.length > otpAttributes.maxCredentials) {
    cookies.delete(COOKIE_OTP)
    await Promise.allSettled([deleteOtpTokenId(id), kmsOtp.rotate(kekId)])
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  /**
   * @type {string[]}
   */
  const newEncodedOtpTokenList = []

  /**
   * @type {(string|null)}
   */
  let currentEncodedOtpTokenData = null
  let currentEncodedOtpToken = ""
  let expires = 0

  const dateNow = Date.now()

  for (let encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken)
    if (!otpToken) {
      cookies.delete(COOKIE_OTP)
      await Promise.allSettled([deleteOtpTokenId(id), kmsOtp.rotate(kekId)])
      return new Response(null, APP_RES_INIT_DEFAULT_BAD)
    }
    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES]
      }
      encodedOtpToken = encodeOtpToken(otpToken)
      if (!currentEncodedOtpToken && credential === otpToken[CREDENTIAL]) {
        currentEncodedOtpToken = encodedOtpToken
        currentEncodedOtpTokenData = encodeOtpTokenData(otpToken)
      } else {
        newEncodedOtpTokenList.push(encodedOtpToken)
      }
    }
  }

  if (newEncodedOtpTokenList.length >= otpAttributes.maxCredentials) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  if (!expires) {
    // All OTP tokens have expired, create a new list.
    return await generateOtpTokenListCreationResponse(cookies, credential)
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * @type {Uint8Array<ArrayBuffer>}
   */
  let additionalData

  /**
   * Kek ID + Wrapped DEK.
   * 
   * @type {string}
   */
  let envelope

  const currentKekId = await kmsOtp.getCurrentId()

  if (currentKekId === kekId) {
    additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS)
    envelope = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)
  } else {
    /**
     * @type {(CryptoKey|undefined)}
     */
    let kek;
    [dek, kek] = await Promise.all([createDek(), kmsOtp.get(currentKekId)])
    if (kek) {
      kekId = currentKekId
      additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS)
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    } else {
      let i = 0
      do {
        additionalData = createId(KEK_ID_BYTES)
        kekId = additionalData.toBase64(BASE64URL_OPTIONS)
        kek = await createKek()
        i++
      } while(!await kmsOtp.store(kekId, kek) && i < MAX_KMS_STORE_ATTEMPTS)
      if (i >= MAX_KMS_STORE_ATTEMPTS) {
        throw new Error("Too many attempts to store a KEK in KMS: OTP")
      }
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    }
  }

  if (currentEncodedOtpToken) {
    newEncodedOtpTokenList.push(currentEncodedOtpToken)
  } else {
    /**
     * `updateOtpTokenExpires` is used to verify too.
     * Verify OTP Token List ID before sending the OTP.
     */
    expires = await updateOtpTokenExpires(id, expires)
    if (!expires) {
      cookies.delete(COOKIE_OTP)
      return new Response(null, APP_RES_INIT_DEFAULT_BAD)
    }
    const otp = createOtp()
    if (!await sendOtp(credential, otp)) {
      return new Response(null, APP_RES_INIT_DEFAULT_BAD)
    }
    const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS
    currentEncodedOtpToken = createEncodedOtpToken(credential, expires, otp, resendBlock)
    newEncodedOtpTokenList.push(currentEncodedOtpToken)
    currentEncodedOtpTokenData = (
      compressNumber(msToSeconds(expires, Math.trunc)) +
      "," +
      compressNumber(msToSeconds(resendBlock, Math.ceil))
    )
  }

  newEncodedOtpTokenList.push(id)

  setOtpCookie(
    cookies,
    envelope + await encryptTextSymmetrically(
      dek,
      encodeOtpTokenList(newEncodedOtpTokenList),
      additionalData
    ),
    msToSeconds(expires, Math.trunc)
  )
  
  return new Response(currentEncodedOtpTokenData, APP_RES_INIT_200)

}