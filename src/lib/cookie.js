import { production } from "#src/config";
import { SESSION_MAX_AGE } from "#src/lib/session/custom";

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
const getCookieName = production ? (name, prefix = "__Host-Http-") => prefix + name : name => name;

export const COOKIE_NAME_OTP = getCookieName("o");

export const COOKIE_NAME_SESSION = getCookieName("s");

/**
 * @type {Bun.CookieInit}
 */
export const COOKIE_OPTIONS_SESSION = Object.freeze({
  httpOnly: true,
  maxAge: SESSION_MAX_AGE,
  partitioned: false,
  path: "/",
  sameSite: "lax",
  secure: production
});
