import { APP_RES_INIT_204, APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"
import { getSession } from "#src/lib/session"


/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleUserOtherSessionsLogout(req) {

  const session = await getSession(req.cookies)
    
  if (!session) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  if (!await session.updateSessionId()) {
    session.deleteCookie()
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  await session.save()

  return new Response(null, APP_RES_INIT_204)

}