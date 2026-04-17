import displayNameAttributes from "#shared/display.json";
import { regexDisallowedDisplayNameCharacters, regexSeparators } from "#src/lib/regex";

/**
 * @function
 * @param {string} value
 * @returns {string}
 */
export function normalizeDisplayName(value) {
  return value.replaceAll(regexDisallowedDisplayNameCharacters, "").replaceAll(regexSeparators, " ").trim();
}

/**
 * @function isDisplayNameLengthValid
 * @param {string} value
 * @returns {boolean}
 */
export function isDisplayNameLengthValid(value) {
  return value.length > displayNameAttributes.minLength && value.length < displayNameAttributes.maxLength;
}
