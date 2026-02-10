import { SESSION_MAX_AGE_MS } from "#src/lib/computed"
import KMS from "#src/lib/kms"


const kmsSession = new KMS(SESSION_MAX_AGE_MS, "SESSION")


export default kmsSession