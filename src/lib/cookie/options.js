import production from "#src/lib/production";
import { SESSION_MAX_AGE } from "#src/lib/session/custom";

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
