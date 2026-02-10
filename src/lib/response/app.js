/**
 * Create responses with the app headers.
 */

import APP_RES_HEADERS from "#src/lib/response/headers/app"


/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_200 = Object.freeze({
  headers: APP_RES_HEADERS
})

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_204 = Object.freeze({
  status: 204,
  headers: APP_RES_HEADERS
})

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_403 = Object.freeze({
  status: 403,
  headers: APP_RES_HEADERS
})

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_404 = Object.freeze({
  status: 404,
  headers: APP_RES_HEADERS
})

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_409 = Object.freeze({
  status: 409,
  headers: APP_RES_HEADERS
})

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_500 = Object.freeze({
  status: 500,
  headers: APP_RES_HEADERS
})

/**
 * 404
 * 
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_DEFAULT_BAD = APP_RES_INIT_404