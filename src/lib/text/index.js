import { regexDisallowedMarkdown, regexOtherLineSeparators } from "#src/lib/regex"


/**
 * @function purifyText
 * @param {string} text
 * @returns {string}
 */
export function purifyText(text) {
  return text.replaceAll(regexOtherLineSeparators, "\n").replaceAll(regexDisallowedMarkdown, "").trim()
}