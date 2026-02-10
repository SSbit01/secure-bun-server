/**
 * @callback NumberFunction
 * @param {number} x
 * @returns {number}
 */


/**
 * Reduces the precission of a time value (milliseconds elapsed since the epoch) to offer protection against timing attacks and fingerprinting.
 * 
 * @function getReducedTimePrecision
 * @param {number} [time] - The time value in milliseconds to reduce precision for. Defaults to the current time.
 * @param {NumberFunction} [roundFunction] - The rounding function to use (e.g., Math.trunc, Math.ceil, Math.round). Defaults to Math.trunc.
 * @returns {number} - The time value with reduced precision.
 */
export function getReducedTimePrecision(time = Date.now(), roundFunction = Math.trunc) {
  return secondsToMs(msToSeconds(time, roundFunction))
}


/**
 * @function msToSeconds
 * @param {number} ms
 * @param {NumberFunction} [roundFunction] - The rounding function to use (e.g., Math.trunc, Math.ceil, Math.round). Defaults to Math.trunc.
 */
export function msToSeconds(ms, roundFunction = Math.trunc) {
  return roundFunction(ms / 1000)
}


/**
 * @function secondsToMs
 * @param {number} seconds
 */
export function secondsToMs(seconds) {
  return seconds * 1000
}