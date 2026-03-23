import receivesEmail from "#src/lib/email/receives"

/**
 * @async
 * @param {string} email - Email address.
 * @param {string} otp - OTP string code.
 * @returns {Promise<boolean>} Indicates whether the sending was successful or not. In case an internal error happened, just throw it.
 */
export default async function sendOtp(email, otp) {

  const hostname = email.split("@")?.[1]

  if (!hostname || !await receivesEmail(hostname)) {
    return false
  }

  // Set logic to send the OTP code to the email address.

  return true

}