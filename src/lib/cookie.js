import production from "#src/lib/production"


/**
 * It applies a prefix in production.
 * 
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#cookie_prefixes|MDN}
 * 
 * @function getCookieName
 * @param {string} name
 * @param {string} prefix
 * @returns {string}
 */
function getCookieName(name, prefix = "__Host-Http-") {
  return production
    ? (prefix + name)
    : name
}


export const COOKIE_OTP = getCookieName("o")
export const COOKIE_SESSION = getCookieName("s")