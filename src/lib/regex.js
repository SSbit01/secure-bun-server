import nameAttributes from "#src/shared/name.json"
import otpAttributes from "#src/shared/otp.json"

export const regexBase64 = /^[a-zA-Z0-9+/]+$/
export const regexBase64Url = /^[\w-]+$/
export const regexDisallowedName = new RegExp(nameAttributes.regexDisallowedName, "gu")
export const regexDisallowedMarkdown = /[\p{Cf}\p{Co}\p{Cs}\p{Cn}]+|(?<=\n{2})\n+|\p{Z}+(?=\n)|^\p{Z}{1,3}(?=\S)/gmu
export const regexOtherLineSeparators = /[\p{Zl}\p{Zp}]/gu
export const regexOtp = new RegExp(otpAttributes.regex)
export const regexSeparators = /\p{Z}+/gu
export const regexTrailingSlash = /\/+$/