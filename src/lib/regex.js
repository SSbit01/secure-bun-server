import nameAttributes from "#shared/name.json"
import otpAttributes from "#shared/otp.json"

export const regexBase64Url = /^[\w-]+$/
export const regexDisallowedName = new RegExp(nameAttributes.regexDisallowedName, "gu")
export const regexOtp = new RegExp(otpAttributes.regex)
export const regexSeparators = /\p{Z}+/gu