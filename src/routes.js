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

  "/otp": { POST: handleOtpEnterCreation },
  "/otp/verify": { POST: handleOtpEnterVerification },

  "/otp/update": { POST: handleOtpUpdateCreation },
  "/otp/verify/update": { POST: handleOtpUpdateVerification },
  
  "/otp/resend": { POST: handleOtpResending },

  "/user/delete": { POST: handleUserDeletion },
  "/user/name": { POST: handleUserDisplayNameUpdate },
  "/user/logout": { POST: handleUserLogout },
  "/user/logout/other": { POST: handleUserOtherSessionsLogout },
  "/user/logout/all": { POST: handleUserAllSessionsLogout }

})


export default ROUTES