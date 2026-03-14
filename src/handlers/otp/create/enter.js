import normalizeEmail from "validator/es/lib/normalizeEmail"
import { isValid as isEmailValid } from "mailchecker"

import generateOtpCreationResponse from "#src/lib/otp/response/create"
import { APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"


/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleOtpEnterCreation(req) {

  /**
   * @type {ReturnType<normalizeEmail>}
   */
  let email = (await req.text()).trim()

  if (!isEmailValid(email)) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  email = normalizeEmail(email)

  if (!email) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  return await generateOtpCreationResponse(req.cookies, email)

}