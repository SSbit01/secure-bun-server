import error from "#src/handlers/error";
import fetch from "#src/handlers/fetch";
import ROUTES from "#src/routes";

const OPTIONS = Object.freeze({
  error,
  fetch,
  routes: ROUTES
});

export default OPTIONS;
