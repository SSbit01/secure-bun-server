/**
 * `Strict-Transport-Security` HSTS should be handled in the CDN or reverse proxy.
 */

/**
 * @type {HeadersInit}
 */
const APP_RES_HEADERS = process.env.APP_ORIGIN
  ? Object.freeze({
      "Access-Control-Allow-Credentials": "true",
      // CORS
      "Access-Control-Allow-Origin": process.env.APP_ORIGIN
    })
  : Object.freeze({});

export default APP_RES_HEADERS;
