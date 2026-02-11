/**
 * `Strict-Transport-Security` HSTS should be handled in the CDN or reverse proxy.
 */

const APP_ORIGIN = process.env.APP_ORIGIN


/**
 * @type {HeadersInit}
 */
const APP_RES_HEADERS = APP_ORIGIN
  ? Object.freeze({
      // CORS
      "Access-Control-Allow-Origin": APP_ORIGIN,
      "Access-Control-Allow-Credentials": "true"
    })
  : Object.freeze({})


export default APP_RES_HEADERS