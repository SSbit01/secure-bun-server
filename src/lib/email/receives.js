import { Resolver, resolveMx, NODATA, NOTFOUND, REFUSED } from "node:dns/promises";
import { msToSeconds } from "#src/lib/time";

const resolver = new Resolver({
  timeout: 3000,
  tries: 3
});

resolver.setServers([
  // Cloudflare (protection against malware and adult content)
  "1.1.1.3",
  "1.0.0.3"
]);

/**
 * @type {number}
 */
const RECEIVES_EMAIL_CACHE_SECONDS = 15;

/**
 * Hostname - Created (in seconds)
 * 
 * @type {Map<string,number>}
 */
const receivesEmailMap = new Map();

setInterval(() => {
  const maxCacheDateSeconds = msToSeconds(Date.now()) - RECEIVES_EMAIL_CACHE_SECONDS;

  for (const [hostname, cachedAtSeconds] of receivesEmailMap) {
    if (cachedAtSeconds < maxCacheDateSeconds) {
      receivesEmailMap.delete(hostname);
    }
  }
}, 120000);

/**
 * @async
 * @function receivesEmail
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
export default async function receivesEmail(hostname) {
  const cacheCreatedSeconds = receivesEmailMap.get(hostname);

  if (
    cacheCreatedSeconds &&
    cacheCreatedSeconds >= (msToSeconds(Date.now()) - RECEIVES_EMAIL_CACHE_SECONDS)
  ) {
    return true;
  }

  try {
    const result = (await resolveMx(hostname)).length > 0;

    if (result) {
      receivesEmailMap.set(hostname, msToSeconds(Date.now()));
    } else {
      receivesEmailMap.delete(hostname);
    }

    return result;
  } catch (error) {
    if (!error) {
      return false;
    }

    // @ts-expect-error
    switch (error.code) {
      case NODATA:
      case NOTFOUND:
      case REFUSED:
        return false;
    }

    throw error;
  }
}
