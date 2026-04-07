import handleOtpEnterCreation from "#src/handlers/otp/create/enter"
import handleOtpUpdateCreation from "#src/handlers/otp/create/update"
import handleOtpResending from "#src/handlers/otp/resend"
import handleOtpEnterVerification from "#src/handlers/otp/verify/enter"
import handleOtpUpdateVerification from "#src/handlers/otp/verify/update"
import handleUserDelete from "#src/handlers/user/delete"
import handleUserDisplayNameUpdate from "#src/handlers/user/display"
import handleUserLogout from "#src/handlers/user/logout"
import handleUserAllSessionsLogout from "#src/handlers/user/logout/all"


/**
 * POST is used instead of other methods to avoid CORS preflight requests.
 */


const ROUTES = Object.freeze({

  "/s/health": new Response("OK"),

  "/s/otp": { POST: handleOtpEnterCreation },
  "/s/otp/verify": { POST: handleOtpEnterVerification },

  "/s/otp/update": { POST: handleOtpUpdateCreation },
  "/s/otp/verify/update": { POST: handleOtpUpdateVerification },
  
  "/s/otp/resend": { POST: handleOtpResending },

  "/s/user/delete": { POST: handleUserDelete },
  "/s/user/display": { POST: handleUserDisplayNameUpdate },
  "/s/user/logout": { POST: handleUserLogout },
  "/s/user/logout/all": { POST: handleUserAllSessionsLogout }

})


export default ROUTES