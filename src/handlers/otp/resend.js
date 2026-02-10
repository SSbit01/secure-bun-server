import { canonicalize } from "canonical-email"
import { isValid as isEmailValid } from "mailchecker"

import { BASE64URL_OPTIONS } from "#src/lib/base64"
import { compressNumber } from "#src/lib/compression/number"
import { ENVELOPE_ENCRYPTION_WRAP_LENGTH, KEK_ID_LENGTH } from "#src/lib/computed"
import { createKek, wrapKey } from "#src/lib/crypto/symmetric/kek"
import { createDek, encryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek"
import { COOKIE_OTP } from "#src/lib/cookie"
import { blockOtpToken, getOtpTokenList, setOtpCookie } from "#src/lib/otp"
import { createOtp } from "#src/lib/otp/custom"

import {
  CREDENTIAL,
  EXPIRES,
  OTP,
  RESEND_BLOCK,
  decodeOtpToken,
  encodeOtpToken,
  encodeOtpTokenList
} from "#src/lib/otp/encode/token"

import { deleteOtpTokenId, updateOtpTokenExpires } from "#src/lib/otp/id"
import kmsOtp from "#src/lib/otp/kms"
import sendOtp from "#src/lib/otp/send"
import { APP_RES_INIT_200, APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"
import { msToSeconds } from "#src/lib/time"

import otpAttributes from "#src/shared/otp.json"


/**
 * @import { OtpToken } from "#src/lib/otp/encode/token"
 */


/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleOtpResending(req) {

  const { cookies } = req

  const otpData = cookies.get(COOKIE_OTP)?.trim()?.trim()
  
  if (!otpData) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH)

  let dek = await kmsOtp.getDek(kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!dek) {
    cookies.delete(COOKIE_OTP)
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!encodedOtpTokenList) {
    cookies.delete(COOKIE_OTP)
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
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
   * @type {(OtpToken|undefined)}
   */
  let currentOtpToken
  let expires = 0
  let email = (await req.text()).trim()

  if (email && isEmailValid(email)) {
    email = canonicalize(email)
  } else {
    currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "")
    if (!currentOtpToken) {
      cookies.delete(COOKIE_OTP)
      await Promise.allSettled([deleteOtpTokenId(id), kmsOtp.rotate(kekId)])
      return new Response(null, APP_RES_INIT_DEFAULT_BAD)
    }
    expires = currentOtpToken[EXPIRES]
  }

  /**
   * @type {string[]}
   */
  const newEncodedOtpTokenList = []
  const dateNow = Date.now()

  for (const encodedOtpToken of encodedOtpTokenList) {
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
      if (!currentOtpToken && email === otpToken[CREDENTIAL]) {
        currentOtpToken = otpToken
      } else {
        newEncodedOtpTokenList.push(encodeOtpToken(otpToken))
      }
    }
  }

  if (
    !currentOtpToken ||
    dateNow >= currentOtpToken[EXPIRES] ||
    (currentOtpToken[RESEND_BLOCK] && dateNow >= currentOtpToken[RESEND_BLOCK])
  ) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  /**
   * Kek ID + Wrapped DEK.
   * 
   * @type {string}
   */
  let envelope

  const currentKekId = await kmsOtp.getCurrentId()

  if (currentKekId === kekId) {
    envelope = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)
  } else {
    /**
     * @type {(CryptoKey|undefined)}
     */
    let kek;
    [dek, kek] = await Promise.all([createDek(), kmsOtp.get(currentKekId)])
    if (kek) {
      kekId = currentKekId
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    } else {
      kek = await createKek()
      /**
       * @type {ArrayBuffer}
       */
      let wrappedDek;
      [kekId, wrappedDek] = await Promise.all([kmsOtp.store(kek), wrapKey(dek, kek)])
      envelope = kekId + new Uint8Array(wrappedDek).toBase64(BASE64URL_OPTIONS)
    }
  }

  currentOtpToken[EXPIRES] = await updateOtpTokenExpires(id, expires)

  if (!currentOtpToken[EXPIRES]) {
    cookies.delete(COOKIE_OTP)
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  const expiresSeconds = msToSeconds(currentOtpToken[EXPIRES], Math.trunc)

  currentOtpToken[OTP] = createOtp()

  /**
   * @type {string|null}
   */
  let responseBody = null

  /**
   * @type {ResponseInit}
   */
  let init = APP_RES_INIT_DEFAULT_BAD

  if (await sendOtp(currentOtpToken[CREDENTIAL], currentOtpToken[OTP])) {
    delete currentOtpToken[RESEND_BLOCK]
    responseBody = compressNumber(expiresSeconds)
    init = APP_RES_INIT_200
  } else {
    blockOtpToken(currentOtpToken)
  }

  newEncodedOtpTokenList.push(encodeOtpToken(currentOtpToken), id)

  setOtpCookie(
    cookies,
    envelope + await encryptTextSymmetrically(
      dek,
      encodeOtpTokenList(newEncodedOtpTokenList)
    ),
    expiresSeconds
  )
  
  return new Response(responseBody, init)

}