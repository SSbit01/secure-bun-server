import { canonicalize } from "canonical-email"
import { isValid as isEmailValid } from "mailchecker"

import { BASE64URL_OPTIONS } from "#src/lib/base64"
import { compressNumber } from "#src/lib/compression/number"

import {
  OTP_INVALID_BLOCK_MS,
  ENVELOPE_ENCRYPTION_WRAP_LENGTH,
  KEK_ID_LENGTH
} from "#src/lib/computed"

import { createId } from "#src/lib/crypto/id"
import { createDek, encryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek"
import { createKek, wrapKey } from "#src/lib/crypto/symmetric/kek"
import { COOKIE_OTP } from "#src/lib/cookie"
import { KEK_ID_BYTES, MAX_KMS_STORE_ATTEMPTS } from "#src/lib/kms"
import sql from "#src/lib/sql"
import { OTP_TOKEN_SEPARATOR, blockOtpToken, getOtpTokenList, isOtpValid, setOtpCookie } from "#src/lib/otp"
import { OTP_ATTEMPTS_BLOCK } from "#src/lib/otp/custom"
import { deleteOtpTokenId, replaceOtpTokenId } from "#src/lib/otp/id"

import {
  CREDENTIAL,
  EXPIRES,
  OTP,
  ATTEMPTS,
  OTP_BLOCK,
  decodeOtpToken,
  encodeOtpToken
} from "#src/lib/otp/encode/token"

import kmsOtp from "#src/lib/otp/kms"

import {
  APP_RES_INIT_200,
  APP_RES_INIT_204,
  APP_RES_INIT_403,
  APP_RES_INIT_DEFAULT_BAD
} from "#src/lib/response/app"

import Session from "#src/lib/session"
import { msToSeconds } from "#src/lib/time"

import otpAttributes from "#shared/otp.json"



/**
 * @import { OtpToken } from "#src/lib/otp/encode/token"
 */



/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleOtpEnterVerification(req) {

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

  let kekId = otpData.substring(0, KEK_ID_LENGTH)

  let dek = await kmsOtp.getDek(kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH))

  if (!dek) {
    cookies.delete(COOKIE_OTP)
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  let additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS)

  const encodedOtpTokenList = await getOtpTokenList(
    dek,
    otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH),
    additionalData
  )

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
    !currentOtpToken[ATTEMPTS] ||
    (currentOtpToken[OTP_BLOCK] && currentOtpToken[OTP_BLOCK] > dateNow)
  ) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  delete currentOtpToken[OTP_BLOCK]


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
      if ((currentOtpToken[EXPIRES] - currentOtpToken[OTP_BLOCK]) <= 2000) {
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
        newEncodedOtpTokenList.join(OTP_TOKEN_SEPARATOR),
        additionalData
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

  if (!otpTokenIdDeletion) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  email = currentOtpToken[CREDENTIAL]

  const [emailData] = await sql
`SELECT e.id,u.display_name,e2.email,ue2.is_backup,u.session_id
FROM emails e
INNER JOIN user_emails ue ON e.id=ue.email_id
INNER JOIN users u ON ue.user_id=u.id
LEFT JOIN user_emails ue2 ON u.id=ue2.user_id AND ue2.is_backup!=ue.is_backup
LEFT JOIN emails e2 ON ue2.email_id=e2.id
WHERE e.email=${email}`

  if (emailData?.session_id) {
    await new Session(cookies, emailData.session_id.toBase64(BASE64URL_OPTIONS)).save()
    if (emailData.is_backup) {
      emailData.email2 = emailData.email
      delete emailData.email
    } else if (!emailData.email) {
      delete emailData.email
    }
    if (!emailData.display_name) {
      delete emailData.display_name
    }
    /**
     * Delete `email.id`, `is_backup` and `session_id` from the response body.
     */
    delete emailData.id
    delete emailData.is_backup
    delete emailData.session_id
    return Response.json(emailData, APP_RES_INIT_200)
  }

  /**
   * @type {Uint8Array<ArrayBuffer>}
   */
  let sessionId

  await sql.begin(async tx => {
    let i = 0
    /**
     * @type {(number|bigint)}
     */
    let userId
    do {
      sessionId = createId()
      userId = (await tx`INSERT IGNORE INTO users (session_id) VALUES (${sessionId})`).lastInsertRowid
      i++
    } while (userId == undefined && i < 2)
    if (!userId) {
      throw new Error("Too many attempts to create a user.")
    }
    const emailId = emailData?.id ?? (await tx`INSERT INTO emails (email) VALUES (${email})`).lastInsertRowid
    await tx`INSERT INTO user_emails (is_backup,email_id,user_id) VALUES (FALSE,${emailId},${userId})`
  })
  
  // @ts-expect-error: `sessionId` is declared in the try block.
  await new Session(cookies, sessionId.toBase64(BASE64URL_OPTIONS)).save()

  return new Response(null, APP_RES_INIT_204)

}