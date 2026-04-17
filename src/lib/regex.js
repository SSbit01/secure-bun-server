import displayNameAttributes from "#shared/display.json";
import otpAttributes from "#shared/otp.json";

export const regexBase64Url = /^[\w-]+$/;
export const regexDisallowedDisplayNameCharacters = new RegExp(displayNameAttributes.regexDisallowed, "gu");
export const regexOtp = new RegExp(otpAttributes.regex);
export const regexSeparators = /\p{Z}+/gu;
