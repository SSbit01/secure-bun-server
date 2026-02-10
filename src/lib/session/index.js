import { BASE64URL_OPTIONS, base64toUrl } from "#src/lib/base64"
import { compressNumber, decompressNumber } from "#src/lib/compression/number"
import { ENVELOPE_ENCRYPTION_WRAP_LENGTH, KEK_ID_LENGTH, SESSION_MAX_AGE_MS } from "#src/lib/computed"
import { createId, isBase64IdValid } from "#src/lib/crypto/id"
import { createDek } from "#src/lib/crypto/symmetric/dek"
import { createKek, wrapKey } from "#src/lib/crypto/symmetric/kek"
import { COOKIE_SESSION } from "#src/lib/cookie"
import { encryptTextSymmetrically, decryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek"
import sql from "#src/lib/sql"
import production from "#src/lib/production"
import { SESSION_MAX_AGE } from "#src/lib/session/custom"
import kmsSession from "#src/lib/session/kms"



/**
 * @type {Bun.CookieInit}
 */
const COOKIE_SESSION_OPTIONS = Object.freeze({
  path: "/",
  secure: production,
  sameSite: "lax",
  httpOnly: true,
  partitioned: false,
  maxAge: SESSION_MAX_AGE
})

/**
 * 200ms as default time between requests.
 * 
 * @type {number}
 */
const MINIMUM_DELAY = 200

const TOKEN_SEPARATOR = ","



/**
 * @async
 * @function getSession
 * @param {Bun.CookieMap} cookies
 * @returns {Promise<Session|undefined>}
 */
export async function getSession(cookies) {

  const sessionData = cookies.get(COOKIE_SESSION)

  if (!sessionData) {
    return
  }

  const envelope = sessionData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)

  const kekId = envelope.substring(0, KEK_ID_LENGTH)

  const dek = await kmsSession.getDek(
    kekId,
    envelope.substring(KEK_ID_LENGTH)
  )

  if (!dek) {
    cookies.delete(COOKIE_SESSION)
    return
  }

  /**
   * @type {Array<string|undefined>}
   */
  let sessionInfo

  try {
    /**
     * All dates are compressed.
     * [sessionId: string, dekRotationDate: string, lastFetchDate: string lastValidAccessDate: string]
     */
    sessionInfo = (await decryptTextSymmetrically(
      dek,
      sessionData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH)
    )).split(TOKEN_SEPARATOR)
  } catch {
    cookies.delete(COOKIE_SESSION)
    return
  }

  const idString = isBase64IdValid(sessionInfo[0] || "") && sessionInfo[0]
  const dekRotationDate = decompressNumber(sessionInfo[1] || "")
  const lastFetchDate = decompressNumber(sessionInfo[2] || "")
  const lastValidAccessDate = decompressNumber(sessionInfo[3] || "")

  const dateNow = Date.now()


  if (
    sessionInfo.length !== 4 ||
    !idString ||
    !dekRotationDate ||
    (dekRotationDate - dateNow) > SESSION_MAX_AGE_MS ||
    !lastFetchDate ||
    !lastValidAccessDate ||
    lastValidAccessDate > dekRotationDate ||
    lastFetchDate > lastValidAccessDate ||
    lastValidAccessDate > dateNow
  ) {

    cookies.delete(COOKIE_SESSION)

    /**
     * Delete key too.
     */
    const promises = [kmsSession.rotate(kekId)]

    if (idString) {
      promises.push(sql`UPDATE users SET session_id=RANDOM_BYTES(18) WHERE session_id=${Uint8Array.fromBase64(idString)}`)
    }

    // @ts-expect-error: promises has already keyRotation
    const [{ status: keyRotationStatus }] = await Promise.allSettled(promises)

    if (keyRotationStatus === "rejected") {
      console.warn("Key rotation failed: " + kekId)
    }

    return

  }


  const elapsed = Date.now() - lastValidAccessDate

  if (elapsed < MINIMUM_DELAY) {
    return
  }

  if (elapsed >= SESSION_MAX_AGE_MS) {
    cookies.delete(COOKIE_SESSION)
    return
  }

  return new Session(
    cookies,
    idString,
    dek,
    dekRotationDate,
    envelope,
    lastFetchDate
  )

}



export default class Session {

  #cookies
  #dek
  #dekRotationDate
  #envelope
  #id
  #idString
  #lastFetchDate


  /**
   * @param {Bun.CookieMap} cookies
   * @param {string} idString
   * @param {CryptoKey} [dek]
   * @param {number} [dekRotationDate]
   * @param {string} [envelope]
   * @param {number} [lastFetchDate]
   */
  constructor(cookies, idString, dek, dekRotationDate, envelope = "", lastFetchDate) {
    this.#cookies = cookies
    this.#dek = dek
    this.#dekRotationDate = dekRotationDate
    this.#envelope = envelope
    this.#id = Uint8Array.fromBase64(idString)
    this.#idString = idString
    this.#lastFetchDate = lastFetchDate
  }


  /**
   * @function deleteCookie
   */
  deleteCookie() {
    this.#cookies.delete(COOKIE_SESSION)
  }


  /**
   * @async
   * @function deleteAccount
   * @returns {Promise<boolean>}
   */
  async deleteAccount() {

    const emails = await sql
    `SELECT ue.email_id FROM users u INNER JOIN user_emails ue ON u.id=ue.user_id WHERE u.session_id=${this.#id}`

    if (!emails.length) {
      return false
    }

    await sql.begin(async tx => {
      await Promise.all([
        tx`DELETE FROM users WHERE session_id=${this.#id}`,
        tx`DELETE FROM emails WHERE id IN (${tx(emails, "email_id")})`
      ])
    })

    return true

  }


  /**
   * @async
   * @function deleteEmailBackup
   * @returns {Promise<boolean>}
   */
  async deleteEmailBackup() {
    return Boolean((
      await sql
      `DELETE ue FROM user_emails ue INNER JOIN users u ON ue.user_id=u.id WHERE ue.is_backup=1 AND u.session_id=${this.#id}`
    ).affectedRows)
  }


  /**
   * @async
   * @function isEmailTaken
   * @param {string} email 
   * @returns {Promise<boolean>}
   */
  async isEmailTaken(email) {

    const [result] = await sql
`SELECT EXISTS(SELECT 1 FROM user_emails WHERE email=${email} AND user_id IS NOT NULL) AS r
FROM users
WHERE session_id=${this.#id}`

    if (!result) {
      this.deleteCookie()
      return true
    }

    return Boolean(result?.r)

  }


  /**
   * @async
   * @function isValid
   * @returns {Promise<boolean>}
   */
  async isValid() {
    return Boolean((await sql`SELECT 1 FROM users WHERE session_id=${this.#id}`).length)
  }


  /**
   * @async
   * @function save
   */
  async save() {

    let kekId = await kmsSession.getCurrentId()

    if (!this.#dek || !this.#dekRotationDate || this.#dekRotationDate <= Date.now() || !this.#envelope.startsWith(kekId)) {
      let kek = await kmsSession.get(kekId)
      if (!kek) {
        kek = await createKek()
        kekId = await kmsSession.store(kek)
      }
      this.#dek = await createDek()
      this.#envelope = kekId + new Uint8Array(await wrapKey(this.#dek, kek)).toBase64(BASE64URL_OPTIONS)
      this.#dekRotationDate = Date.now() + SESSION_MAX_AGE_MS
    }

    const compressedDateNow = compressNumber(Date.now())

    this.#cookies.set(
      COOKIE_SESSION,
      this.#envelope + await encryptTextSymmetrically(
        this.#dek,
        this.#idString + TOKEN_SEPARATOR +
        compressNumber(this.#dekRotationDate) + TOKEN_SEPARATOR +
        (this.#lastFetchDate ? compressNumber(this.#lastFetchDate) : compressedDateNow) + TOKEN_SEPARATOR +
        compressedDateNow
      ),
      COOKIE_SESSION_OPTIONS
    )

  }


  /**
   * @async
   * @function swapEmails
   * @returns {Promise<boolean>}
   */
  async swapEmails() {
    return Boolean((
      await sql
      `UPDATE user_emails ue INNER JOIN users u ON u.id=ue.user_id SET ue.is_backup=!ue.is_backup WHERE u.session_id=${this.#id}`
    ).affectedRows)
  }


  /**
   * @async
   * @function updateDisplayName
   * @param {string} newDisplayName
   * @returns {Promise<boolean>}
   */
  async updateDisplayName(newDisplayName) {
    return Boolean((
      await sql`UPDATE users SET display_name=${newDisplayName} WHERE session_id=${this.#id}`
    ).affectedRows)
  }


  /**
   * It works with concurrent requests.
   * If the previous email gets an invitation during this request, that email address doesn't change.
   * 
   * @async
   * @function updateEmail
   * @param {string} newEmail
   * @param {boolean} backup
   * @returns {Promise<boolean>}
   */
  async updateEmail(newEmail, backup = false) {

    let result = false

    await sql.begin(async tx => {
      // If the previous email address has no invitations, it will be deleted by the event `delete_expired_rows`.
      if ((await tx
`DELETE ue FROM user_emails ue
INNER JOIN users u ON ue.user_id=u.id
WHERE
ue.is_backup=${backup} AND
u.session_id=${this.#id}`
      ).affectedRows || backup) {
        result = Boolean((await tx
`INSERT INTO user_emails (user_id,is_backup,email)
SELECT id,${backup},${newEmail}
FROM users
WHERE session_id=${this.#id}
AS new
ON DUPLICATE KEY
UPDATE user_id=IF(user_id IS NULL,new.user_id,user_id),is_backup=IF(is_backup IS NULL,new.is_backup,is_backup)`
        ).affectedRows)
      }
    })

    return result

  }


  /**
   * This function also updates the internal `id` state, so the session can be saved.
   * 
   * @async
   * @function updateSessionId
   * @returns {Promise<boolean>}
   */
  async updateSessionId() {

    const newSessionId = createId()

    if (!(await sql`UPDATE users SET session_id=${newSessionId} WHERE session_id=${this.#id}`).affectedRows) {
      return false
    }

    this.#id = newSessionId
    this.#idString = newSessionId.toBase64(BASE64URL_OPTIONS)

    return true

  }


  /**
   * This function (unlike `updateSessionId`) doesn't update the internal `id` state, so the session cannot be reused.
   * 
   * @async
   * @function updateSessionIdFast
   * @returns {Promise<boolean>}
   */
  async updateSessionIdFast() {

    return Boolean((
      await sql`UPDATE users SET session_id=RANDOM_BYTES(18) WHERE session_id=${this.#id}`
    ).affectedRows)

  }

}