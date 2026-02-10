import { isDisplayNameValid, normalizeDisplayName } from "#src/lib/name"
import { APP_RES_INIT_204, APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"
import { getSession } from "#src/lib/session"


/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleUserDisplayNameUpdate(req) {

  const displayName = normalizeDisplayName(await req.text())

  if (!isDisplayNameValid(displayName)) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  const session = await getSession(req.cookies)
    
  if (!session) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  if (!await session.updateDisplayName(displayName)) {
    session.deleteCookie()
    return new Response(null, APP_RES_INIT_DEFAULT_BAD)
  }

  await session.save()

  return new Response(null, APP_RES_INIT_204)

}