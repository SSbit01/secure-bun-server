import production from "#src/lib/production"
import { SESSION_MAX_AGE } from "#src/lib/session/custom"

/**
 * @type {Bun.CookieInit}
 */
export const COOKIE_OPTIONS_SESSION = Object.freeze({
  path: "/",
  secure: production,
  sameSite: "lax",
  httpOnly: true,
  partitioned: false,
  maxAge: SESSION_MAX_AGE
})
