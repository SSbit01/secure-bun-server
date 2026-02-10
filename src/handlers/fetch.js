import { APP_RES_INIT_DEFAULT_BAD } from "#src/lib/response/app"


/**
 * @this Bun.Server<any>
 * @function
 * @param {Bun.BunRequest} req
 * @returns {Response}
 */
export default function handleFetch(req) {
  return new Response(null, APP_RES_INIT_DEFAULT_BAD)
}