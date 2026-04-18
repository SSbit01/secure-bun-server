import { isValid as isEmailValid } from "mailchecker";
import normalizeEmail from "validator/es/lib/normalizeEmail";
import generateOtpCreationResponse from "#src/lib/otp/response/create";
import { APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app";
import { getSession } from "#src/lib/session";

/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleOtpUpdateCreation(req) {
  /**
   * @type {ReturnType<normalizeEmail>}
   */
  let email = (await req.text()).trim();

  if (!isEmailValid(email)) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD);
  }

  email = normalizeEmail(email);

  if (!email) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD);
  }

  const session = await getSession(req.cookies);

  if (!session) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD);
  }

  const emailTaken = await session.isEmailTaken(email);

  if (emailTaken !== false) {
    if (emailTaken) {
      await session.save();
    } else {
      session.deleteCookie();
    }

    return new Response(null, APP_RES_INIT_DEFAULT_BAD);
  }

  const res = await generateOtpCreationResponse(req.cookies, email);

  if (res.ok) {
    await session.save();
  }

  return res;
}
