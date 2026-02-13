import nameAttributes from "#shared/name.json"
import { regexDisallowedName, regexSeparators } from "#src/lib/regex"


/**
 * @function
 * @param {string} value 
 * @returns {string}
 */
export function normalizeDisplayName(value) {
  return value.replaceAll(regexDisallowedName, "").replaceAll(regexSeparators, " ").trim()
}


/**
 * @function isDisplayNameValid
 * @param {string} value 
 * @returns {boolean}
 */
export function isDisplayNameValid(value) {
  return value.length > nameAttributes.minLength && value.length < nameAttributes.maxLength
}