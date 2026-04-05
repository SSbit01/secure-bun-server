import { SESSION_MAX_AGE_MS } from "#src/lib/computed"
import getKms from "#src/lib/kms"

const kmsSession = await getKms(SESSION_MAX_AGE_MS, "SESSION")

export default kmsSession
