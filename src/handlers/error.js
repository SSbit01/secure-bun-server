import { APP_RES_INIT_500 } from "#src/lib/response/app"

/**
 * @this Bun.Server<any>
 * @function
 * @param {Bun.ErrorLike} error
 * @returns {Response}
 */
export default function handleError(error) {
  console.error(error)
  return new Response(null, APP_RES_INIT_500)
}