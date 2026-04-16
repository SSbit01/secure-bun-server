import production from "#src/lib/production"

/**
 * It applies a prefix in production.
 * 
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#cookie_prefixes|MDN}
 * 
 * @callback GetCookieName
 * @param {string} name
 * @param {string} [prefix]
 * @returns {string}
 */

/**
 * @type {GetCookieName}
 */
const getCookieName = production
  ? (name, prefix = "__Host-Http-") => (prefix + name)
  : (name) => name

export const COOKIE_NAME_OTP = getCookieName("o")
export const COOKIE_NAME_SESSION = getCookieName("s")
