import nameAttributes from "#shared/display.json";
import otpAttributes from "#shared/otp.json";

export const regexBase64Url = /^[\w-]+$/;
export const regexDisallowedDisplayNameCharacters = new RegExp(nameAttributes.regexDisallowed, "gu");
export const regexOtp = new RegExp(otpAttributes.regex);
export const regexSeparators = /\p{Z}+/gu;
