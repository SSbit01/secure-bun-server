import nameAttributes from "#src/shared/name.json"
import otpAttributes from "#src/shared/otp.json"

export const regexBase64 = /^[a-zA-Z0-9+/]+$/
export const regexBase64Url = /^[\w-]+$/
export const regexDisallowedName = new RegExp(nameAttributes.regexDisallowedName, "gu")
export const regexOtp = new RegExp(otpAttributes.regex)
export const regexSeparators = /\p{Z}+/gu