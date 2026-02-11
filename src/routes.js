import handleOtpEnterCreation from "#src/handlers/otp/create/enter"
import handleOtpUpdateCreation from "#src/handlers/otp/create/update"
import handleOtpEnterVerification from "#src/handlers/otp/verify/enter"
import handleOtpUpdateVerification from "#src/handlers/otp/verify/update"
import handleOtpResending from "#src/handlers/otp/resend"
import handleUserDeletion from "#src/handlers/user/delete"
import handleUserDisplayNameUpdate from "#src/handlers/user/name"
import handleUserLogout from "#src/handlers/user/logout"
import handleUserOtherSessionsLogout from "#src/handlers/user/logout/other"
import handleUserAllSessionsLogout from "#src/handlers/user/logout/all"


/**
 * POST is used instead of other methods to avoid CORS preflight requests.
 */


const ROUTES = Object.freeze({

  "/s/otp": { POST: handleOtpEnterCreation },
  "/s/otp/verify": { POST: handleOtpEnterVerification },

  "/s/otp/update": { POST: handleOtpUpdateCreation },
  "/s/otp/verify/update": { POST: handleOtpUpdateVerification },
  
  "/s/otp/resend": { POST: handleOtpResending },

  "/s/user/delete": { POST: handleUserDeletion },
  "/s/user/name": { POST: handleUserDisplayNameUpdate },
  "/s/user/logout": { POST: handleUserLogout },
  "/s/user/logout/other": { POST: handleUserOtherSessionsLogout },
  "/s/user/logout/all": { POST: handleUserAllSessionsLogout }

})


export default ROUTES