import { canonicalize } from "canonical-email"
import { isValid as isEmailValid } from "mailchecker"

import generateOtpCreationResponse from "#src/lib/otp/response/create"
import { APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"
import { getSession } from "#src/lib/session"


/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleOtpUpdateCreation(req) {

  const email = (await req.text()).trim()

  if (!isEmailValid(email)) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  const session = await getSession(req.cookies)

  if (!session || await session.isEmailTaken(email)) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  const res = await generateOtpCreationResponse(req.cookies, canonicalize(email))

  if (res.ok) {
    await session.save()
  }

  return res

}