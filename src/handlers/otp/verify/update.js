import { canonicalize } from "canonical-email"
import { isValid as isEmailValid } from "mailchecker"

import { BASE64URL_OPTIONS } from "#src/lib/base64"
import { compressNumber } from "#src/lib/compression/number"
import { OTP_INVALID_BLOCK_MS, ENVELOPE_ENCRYPTION_WRAP_LENGTH, KEK_ID_LENGTH } from "#src/lib/computed"
import { createKek, wrapKey } from "#src/lib/crypto/symmetric/kek"
import { createDek, encryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek"
import { COOKIE_OTP } from "#src/lib/cookie"
import { blockOtpToken, getOtpTokenList, isOtpValid, setOtpCookie } from "#src/lib/otp"
import { OTP_ATTEMPTS_BLOCK } from "#src/lib/otp/custom"
import { deleteOtpTokenId, replaceOtpTokenId } from "#src/lib/otp/id"

import {
  CREDENTIAL,
  EXPIRES,
  OTP,
  ATTEMPTS,
  OTP_BLOCK,
  decodeOtpToken,
  encodeOtpToken,
  encodeOtpTokenList
} from "#src/lib/otp/encode/token"

import kmsOtp from "#src/lib/otp/kms"
import { APP_RES_INIT_204, APP_RES_INIT_403, APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"
import { getSession } from "#src/lib/session"
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
export default async function handleOtpUpdateVerification(req) {

  let [otp, email] = (await req.text()).split(",")

  otp = otp?.trim().toLowerCase()

  if (!otp || !isOtpValid(otp)) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  const { cookies } = req

  const otpData = cookies.get(COOKIE_OTP)?.trim()?.trim()
  
  if (!otpData) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  const session = await getSession(req.cookies)
  
  if (!session) {
    cookies.delete(COOKIE_OTP)
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

  let id = encodedOtpTokenList.pop()

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
    /**
     * [OTP_BLOCK] already filtered in `decodeOtpString`.
     */
    currentOtpToken[OTP_BLOCK] ||
    !currentOtpToken[ATTEMPTS]
  ) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }


  if (currentOtpToken[OTP] !== otp) {

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

    id = await replaceOtpTokenId(id, expires)

    if (!id) {
      cookies.delete(COOKIE_OTP)
      return new Response(null, APP_RES_INIT_DEFAULT_BAD)
    }

    /**
     * @type {string|null}
     */
    let responseBody = null

    let init = APP_RES_INIT_403

    currentOtpToken[ATTEMPTS]--

    if (!currentOtpToken[ATTEMPTS]) {
      blockOtpToken(currentOtpToken)
      init = APP_RES_INIT_DEFAULT_BAD
    } else if (currentOtpToken[ATTEMPTS] <= OTP_ATTEMPTS_BLOCK) {
      currentOtpToken[OTP_BLOCK] = Date.now() + OTP_INVALID_BLOCK_MS
      /**
       * If the OTP block time is greater than or similar to the OTP expiration time, block the OTP.
       */
      if ((currentOtpToken[EXPIRES] - currentOtpToken[OTP_BLOCK]) <= 1000) {
        blockOtpToken(currentOtpToken)
        init = APP_RES_INIT_DEFAULT_BAD
      } else {
        responseBody = compressNumber(msToSeconds(currentOtpToken[OTP_BLOCK], Math.ceil))
      }
    }

    newEncodedOtpTokenList.push(encodeOtpToken(currentOtpToken), id)

    setOtpCookie(
      cookies,
      envelope + await encryptTextSymmetrically(
        dek,
        encodeOtpTokenList(newEncodedOtpTokenList)
      ),
      msToSeconds(expires, Math.trunc)
    )
    
    return new Response(responseBody, init)
    
  }


  /**
   * VERIFIED
   */

  const otpTokenIdDeletion = await deleteOtpTokenId(id, expires)

  cookies.delete(COOKIE_OTP)

  if (
    !otpTokenIdDeletion ||
    !await session.updateEmail(currentOtpToken[CREDENTIAL], new URL(req.url).searchParams.get("b") === "1")
  ) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  await session.save()
  
  return new Response(null, APP_RES_INIT_204)

}