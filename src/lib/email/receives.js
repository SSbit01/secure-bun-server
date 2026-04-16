import { resolveMx } from "node:dns/promises";

/**
 * @async
 * @function receivesEmail
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
export default async function receivesEmail(hostname) {
  try {
    return (await resolveMx(hostname)).length > 0;
  } catch {
    return false;
  }
}
