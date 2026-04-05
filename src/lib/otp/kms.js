import { OTP_MAX_AGE_MS } from "#src/lib/computed"
import getKms from "#src/lib/kms"

const kmsOtp = await getKms(OTP_MAX_AGE_MS, "OTP")

export default kmsOtp
