import { COOKIE_SESSION } from "#src/lib/cookie"
import { APP_RES_INIT_204 } from "#src/lib/response/app"


/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleUserLogout({ cookies }) {

  cookies.delete(COOKIE_SESSION)

  return new Response(null, APP_RES_INIT_204)

}