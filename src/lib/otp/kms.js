import { OTP_MAX_AGE_MS } from "#src/lib/computed"
import KMS from "#src/lib/kms"


const kmsOtp = new KMS(OTP_MAX_AGE_MS, "OTP")


export default kmsOtp