import { APP_RES_INIT_200, APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app";
import { getSession } from "#src/lib/session";

/**
 * @async
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Promise<Response>}
 */
export default async function handleUserAllSessionsLogout(req) {
  const session = await getSession(req.cookies);

  if (!session) {
    return new Response(null, APP_RES_INIT_DEFAULT_BAD);
  }
  
  const result = await session.updateSessionIdFast();

  /**
   * Delete the cookie only after calling `updateSessionIdFast()`, as it may throw an error.
   */
  session.deleteCookie();

  return new Response(null, result ? APP_RES_INIT_200 : APP_RES_INIT_DEFAULT_BAD);
}
