import fetch from "#src/handlers/fetch"
import error from "#src/handlers/error"
import ROUTES from "#src/routes"
import photoAttributes from "#src/shared/photo.json"


const OPTIONS = Object.freeze({
  maxRequestBodySize: photoAttributes.maxPhotoSize,
  routes: ROUTES,
  fetch,
  error
})


export default OPTIONS