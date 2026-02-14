/**
 * IMPORTANT!
 * 
 * ORDER IS SET MANUALLY IN `createEncodedOtpToken` AND `decodeOtpToken` FOR BETTER PERFORMANCE
 * (no need to create additional objects and arrays).
 */

import { isValid as isEmailValid } from "mailchecker"

import otpAttributes from "#shared/otp.json"

import { OTP_ATTEMPTS_BLOCK, OTP_MAX_ATTEMPTS } from "#src/lib/otp/custom"
import { decodeCredential, encodeCredential } from "#src/lib/otp/encode/credential"
import { compressNumber, decompressNumber } from "#src/lib/compression/number"
import { OTP_INVALID_BLOCK_MS, OTP_MAX_AGE_MS, OTP_RESEND_BLOCK_MS } from "#src/lib/computed"
import { regexOtp } from "#src/lib/regex"


/**
 * @typedef {[
 *  credential: string,
 *  expires: number,
 *  otp?: string,
 *  attempts?: number,
 *  resendBlock?: number,
 *  otpBlock?: number
 * ]} OtpToken
 */


export const CREDENTIAL = 0
export const EXPIRES = 1
export const OTP = 2
export const ATTEMPTS = 3
export const RESEND_BLOCK = 4
export const OTP_BLOCK = 5

const OTP_SEPARATOR = "|"


/**
 * @function createOtpToken
 * @param {OtpToken[CREDENTIAL]} credential
 * @param {OtpToken[EXPIRES]} expires
 * @param {NonNullable<OtpToken[OTP]>} otp
 * @param {NonNullable<OtpToken[RESEND_BLOCK]>} resendBlock
 * @returns {string}
 */
export function createEncodedOtpToken(
  credential,
  expires,
  otp,
  resendBlock
) {

  return (
    encodeCredential(credential) + OTP_SEPARATOR +
    compressNumber(expires) + OTP_SEPARATOR +
    otp + OTP_SEPARATOR +
    OTP_MAX_ATTEMPTS + OTP_SEPARATOR +
    compressNumber(resendBlock)
  )

}


/**
 * @function decodeOtpToken
 * @param {string} encodedOtpToken 
 * @param {number} [dateNow]
 * @returns {OtpToken|undefined} If it doesn't return anything, it means the token is invalid, and maybe the keys were compromised.
 */
export function decodeOtpToken(encodedOtpToken, dateNow = Date.now()) {

  /**
   * @type {any}
   */
  const otpToken = encodedOtpToken.split(OTP_SEPARATOR)

  otpToken[EXPIRES] = decompressNumber(otpToken[EXPIRES])

  // (dateNow - time) < delay

  if ((otpToken[EXPIRES] - dateNow) > OTP_MAX_AGE_MS) {
    return
  }

  try {
    otpToken[CREDENTIAL] = decodeCredential(otpToken[CREDENTIAL])
  } catch {
    return
  }

  if (!isEmailValid(otpToken[CREDENTIAL])) {
    return
  }

  if (otpToken[OTP]) {
    if (otpToken[OTP].length !== otpAttributes.length || !regexOtp.test(otpToken[OTP])) {
      return
    }
    otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
    /**
     * `otpToken[ATTEMPTS]` can't be zero because it's automatically deleted.
     */
    if (isNaN(otpToken[ATTEMPTS]) || otpToken[ATTEMPTS] <= 0 || otpToken[ATTEMPTS] > OTP_MAX_ATTEMPTS) {
      return
    }
    if (otpToken[RESEND_BLOCK]) {
      otpToken[RESEND_BLOCK] = decompressNumber(otpToken[RESEND_BLOCK])
      if ((otpToken[RESEND_BLOCK] - dateNow) > OTP_RESEND_BLOCK_MS) {
        return
      }
    }
    if (otpToken[OTP_BLOCK]) {
      if (otpToken[ATTEMPTS] > OTP_ATTEMPTS_BLOCK) {
        return
      }
      otpToken[OTP_BLOCK] = decompressNumber(otpToken[OTP_BLOCK])
      if ((otpToken[OTP_BLOCK] - dateNow) > OTP_INVALID_BLOCK_MS) {
        return
      }
    }
  } else if (otpToken[ATTEMPTS] || otpToken[RESEND_BLOCK] || otpToken[OTP_BLOCK]) {
    return
  }

  return otpToken

}


/**
 * @function encodeOtpToken
 * @param {OtpToken} otpToken
 * @returns {string}
 */
export function encodeOtpToken(otpToken) {

  /**
   * @type {any}
   */
  const otpTokenCopy = otpToken.slice()

  otpTokenCopy[CREDENTIAL] = encodeCredential(otpTokenCopy[CREDENTIAL])

  otpTokenCopy[EXPIRES] = compressNumber(otpTokenCopy[EXPIRES])

  if (otpTokenCopy[OTP]) {
    otpTokenCopy[RESEND_BLOCK] &&= compressNumber(otpTokenCopy[RESEND_BLOCK])
    otpTokenCopy[OTP_BLOCK] &&= compressNumber(otpTokenCopy[OTP_BLOCK])
  }

  /**
   * Remove empty elements from the end of the array.
   */

  let i = otpTokenCopy.length - 1

  while (!otpTokenCopy[i]) {
    i--
  }

  otpTokenCopy.length = i + 1

  return otpTokenCopy.join(OTP_SEPARATOR)

}


/**
 * @function getOtpTokenData
 * @param {OtpToken} otpToken
 * @returns {string}
 */
export function encodeOtpTokenData(otpToken) {

  let result = (
    encodeCredential(otpToken[CREDENTIAL]) + OTP_SEPARATOR +
    compressNumber(otpToken[EXPIRES])
  )

  if (otpToken[OTP]) {
    result += (
      OTP_SEPARATOR +
      otpToken[OTP] + OTP_SEPARATOR +
      otpToken[ATTEMPTS]
    )
  }

  if (otpToken[RESEND_BLOCK]) {
    result += (
      OTP_SEPARATOR +
      compressNumber(otpToken[RESEND_BLOCK])
    )
  }

  if (otpToken[OTP_BLOCK]) {
    result += (
      OTP_SEPARATOR +
      compressNumber(otpToken[OTP_BLOCK])
    )
  }

  return result

}