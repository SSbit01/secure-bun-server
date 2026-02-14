import otpAttributes from "#shared/otp.json"

import { decryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek"
import { COOKIE_OTP } from "#src/lib/cookie"
import { OTP, ATTEMPTS, RESEND_BLOCK, OTP_BLOCK } from "#src/lib/otp/encode/token"
import production from "#src/lib/production"
import { regexOtp } from "#src/lib/regex"



/**
 * @import { OtpToken } from "#src/lib/otp/encode/token"
 */



export const OTP_TOKEN_SEPARATOR = ","


/**
 * @function blockOtpToken
 * @param {OtpToken} otpToken
 */
export function blockOtpToken(otpToken) {
  delete otpToken[OTP]
  delete otpToken[ATTEMPTS]
  delete otpToken[RESEND_BLOCK]
  delete otpToken[OTP_BLOCK]
}



/**
 * @function getOtpTokenList
 * @param {CryptoKey} key
 * @param {string} ciphertext
 * @param {Uint8Array<ArrayBuffer>} additionalData
 * @returns {Promise<string[]|undefined>}
 */
export async function getOtpTokenList(key, ciphertext, additionalData) {

  try {
    return (
      await decryptTextSymmetrically(key, ciphertext, additionalData)
    ).split(OTP_TOKEN_SEPARATOR)
  } catch {
    // It simply returns `undefined`.
  }

}



/**
 * @function isOtpValid
 * @param {string} otp 
 * @returns {boolean}
 */
export function isOtpValid(otp) {
  return otp.length === otpAttributes.length && regexOtp.test(otp)
}



/**
 * @function setOtpCookie
 * @param {Bun.CookieMap} cookies
 * @param {string} otpData
 * @param {Bun.CookieInit["expires"]} expires
 */
export function setOtpCookie(cookies, otpData, expires) {

  cookies.set(
    COOKIE_OTP,
    otpData,
    {
      path: "/",
      expires,
      secure: production,
      httpOnly: true,
      sameSite: "strict",
      partitioned: false
    }
  )
  
}