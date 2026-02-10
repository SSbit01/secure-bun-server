const PRODUCTION = "production"

/**
 * Returns whether the server is running in a production environment or not.
 * 
 * @type {boolean}
 */
const production = (
  process.env.NODE_ENV?.toLowerCase() === PRODUCTION ||
  process.env.ENVIRONMENT?.toLowerCase() === PRODUCTION
)


export default production