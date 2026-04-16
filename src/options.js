import photoAttributes from "#shared/photo.json";
import error from "#src/handlers/error";
import fetch from "#src/handlers/fetch";
import ROUTES from "#src/routes";

const OPTIONS = Object.freeze({
  error,
  fetch,
  maxRequestBodySize: photoAttributes.maxPhotoSize,
  routes: ROUTES
});

export default OPTIONS;
