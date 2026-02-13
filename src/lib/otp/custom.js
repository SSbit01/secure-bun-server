import process from "node:process"
import otpAttributes from "#shared/otp.json"


const isTest = process.env.NODE_ENV === "test"


/**
 * When the user enters the code incorrectly many times and reaches this number of attempts,
 * a timeout of seconds defined in `OTP_INVALID_BLOCK_SECONDS` can be set.
 * 
 * - It needs to be lower than `OTP_MAX_ATTEMPTS`.
 * - Disable OTP blocking by setting it to `0`.
 * 
 * @type {number}
 */
export const OTP_ATTEMPTS_BLOCK = 1


/**
 * When the user enters the code incorrectly many times and reaches the number of attempts defined in `OTP_ATTEMPTS_BLOCK`,
 * a timeout of a few seconds can be set.
 * 
 * - It is recommended to set it to 20 seconds.
 * 
 * @type {number}
 */
export const OTP_INVALID_BLOCK_SECONDS = isTest ? 3 : 20


/**
 * The maximum validity period of an OTP token in seconds.
 * 
 * - If it is too low, tests may fail.
 * 
 * @type {number}
 */
export const OTP_MAX_AGE = 300  // 5 minutes


/**
 * The maximum number of attempts a user can verify an OTP.
 * 
 * @type {number}
 */
export const OTP_MAX_ATTEMPTS = 3


/**
 * When sending an OTP, you may want to ask users to wait a few seconds until they have the option to resend another OTP.
 * 
 * - It is recommended to set it to 20 seconds.
 * 
 * @type {number}
 */
export const OTP_RESEND_BLOCK_SECONDS = isTest ? 3 : 20


/**
 * This implenetation creates an OTP with lowercase letters and numbers.
 * 
 * - The OTP length with this implementation can be up to 11 characters.
 * 
 * @function createOtp
 */
export function createOtp() {
  return (
    (crypto.getRandomValues(new BigUint64Array(1))[0]?.toString(36).substring(0, otpAttributes.length) ?? "")
      .padStart(otpAttributes.length, "0")
  )
}