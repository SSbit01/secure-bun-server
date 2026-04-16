/**
 * Create responses with the app headers.
 */

import APP_RES_HEADERS from "#src/lib/response/headers/app";

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_200 = Object.freeze({
  headers: APP_RES_HEADERS
});

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_204 = Object.freeze({
  headers: APP_RES_HEADERS,
  status: 204
});

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_403 = Object.freeze({
  headers: APP_RES_HEADERS,
  status: 403
});

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_404 = Object.freeze({
  headers: APP_RES_HEADERS,
  status: 404
});

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_409 = Object.freeze({
  headers: APP_RES_HEADERS,
  status: 409
});

/**
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_500 = Object.freeze({
  headers: APP_RES_HEADERS,
  status: 500
});

/**
 * 404
 *
 * @type {Readonly<ResponseInit>}
 */
export const APP_RES_INIT_DEFAULT_BAD = APP_RES_INIT_404;
