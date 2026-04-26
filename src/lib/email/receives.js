import { resolveMx, setServers } from "node:dns/promises";

setServers([
  // Quad9
  "9.9.9.9",
  "149.112.112.112",

  // Cloudflare (protection against malware and adult content)
  "1.1.1.3",
  "1.0.0.3",

  // Cloudflare (protection against malware)
  "1.1.1.2",
  "1.0.0.2"
]);

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
