import { BASE64URL_OPTIONS } from "#src/lib/base64";
import { compressNumber, decompressNumber } from "#src/lib/compression/number";
import { ENVELOPE_ENCRYPTION_WRAP_LENGTH, KEK_ID_LENGTH, SESSION_MAX_AGE_MS } from "#src/lib/computed";
import { COOKIE_NAME_SESSION } from "#src/lib/cookie";
import { COOKIE_OPTIONS_SESSION } from "#src/lib/cookie/options";
import { createId, isBase64UrlIdValid } from "#src/lib/crypto/id";
import { createDek, decryptTextSymmetrically, encryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek";
import { createKek, wrapKey } from "#src/lib/crypto/symmetric/kek";
import { KEK_ID_BYTES, MAX_KMS_STORE_ATTEMPTS } from "#src/lib/kms";
import kmsSession from "#src/lib/session/kms";
import sql from "#src/lib/sql";

const TOKEN_SEPARATOR = ",";

/**
 * @async
 * @function getSession
 * @param {Bun.CookieMap} cookies
 * @returns {Promise<Session|undefined>}
 */
export async function getSession(cookies) {
  const sessionData = cookies.get(COOKIE_NAME_SESSION);

  if (!sessionData) {
    return;
  }

  const envelope = sessionData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH);

  const kekId = envelope.substring(0, KEK_ID_LENGTH);

  const dek = await kmsSession.getDek(kekId, envelope.substring(KEK_ID_LENGTH));

  if (!dek) {
    cookies.delete(COOKIE_NAME_SESSION);
    return;
  }

  /**
   * @type {Array<string|undefined>}
   */
  let sessionInfo;

  try {
    /**
     * All dates are compressed.
     * [sessionId: string, dekRotationDateMs: string, lastFetchDate: string lastValidAccessDateMs: string]
     */
    sessionInfo = (
      await decryptTextSymmetrically(
        dek,
        sessionData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH),
        Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS)
      )
    ).split(TOKEN_SEPARATOR);
  } catch {
    cookies.delete(COOKIE_NAME_SESSION);
    return;
  }

  const idString = isBase64UrlIdValid(sessionInfo[0] || "") && sessionInfo[0];
  const dekRotationDateMs = decompressNumber(sessionInfo[1] || "");
  const lastFetchDate = decompressNumber(sessionInfo[2] || "");
  const lastValidAccessDateMs = decompressNumber(sessionInfo[3] || "");

  const dateNow = Date.now();

  if (
    sessionInfo.length !== 4 ||
    !idString ||
    !dekRotationDateMs ||
    dekRotationDateMs - dateNow > SESSION_MAX_AGE_MS ||
    !lastFetchDate ||
    !lastValidAccessDateMs ||
    lastValidAccessDateMs > dekRotationDateMs ||
    lastFetchDate > lastValidAccessDateMs ||
    lastValidAccessDateMs > dateNow
  ) {
    cookies.delete(COOKIE_NAME_SESSION);

    /**
     * Rotate the KEK.
     */
    try {
      await kmsSession.rotate(kekId);
    } catch {
      console.error("Key rotation failed:", kekId);
    }

    if (idString) {
      await sql.begin(async tx => {
        const { affectedRows } =
          await tx`UPDATE users SET session_id=RANDOM_BYTES(18) WHERE session_id=${Uint8Array.fromBase64(idString, BASE64URL_OPTIONS)}`;

        if (affectedRows > 1) {
          throw new Error(
            `While trying to rotate a compromised session_id (${idString}), ${affectedRows} users were affected. That should not happen.`
          );
        }

        if (affectedRows) {
          console.log("Compromised session_id successfully rotated.");
        } else {
          console.log("Compromised session_id does not exist.");
        }
      });
    }

    return;
  }

  if (Date.now() - lastValidAccessDateMs >= SESSION_MAX_AGE_MS) {
    cookies.delete(COOKIE_NAME_SESSION);
    return;
  }

  return new Session(cookies, idString, dek, dekRotationDateMs, envelope, lastFetchDate);
}

export default class Session {
  #cookies;
  #dek;
  #dekRotationDateMs;
  #envelope;
  #id;
  #idString;
  #lastFetchDate;

  /**
   * @param {Bun.CookieMap} cookies
   * @param {string} idString
   * @param {CryptoKey} [dek]
   * @param {number} [dekRotationDateMs]
   * @param {string} [envelope]
   * @param {number} [lastFetchDate]
   */
  constructor(cookies, idString, dek, dekRotationDateMs, envelope = "", lastFetchDate) {
    this.#cookies = cookies;
    this.#dek = dek;
    this.#dekRotationDateMs = dekRotationDateMs;
    this.#envelope = envelope;
    this.#id = Uint8Array.fromBase64(idString, BASE64URL_OPTIONS);
    this.#idString = idString;
    this.#lastFetchDate = lastFetchDate;
  }

  /**
   * @function deleteCookie
   */
  deleteCookie() {
    this.#cookies.delete(COOKIE_NAME_SESSION);
  }

  /**
   * @async
   * @function deleteAccount
   * @returns {Promise<boolean>}
   */
  async deleteAccount() {
    this.deleteCookie();
    return (await sql`DELETE FROM users WHERE session_id=${this.#id}`).affectedRows > 0;
  }

  /**
   * @async
   * @function deleteEmailBackup
   * @returns {Promise<boolean>}
   */
  async deleteEmailBackup() {
    return (
      (
        await sql`DELETE e,ue FROM emails e
INNER JOIN user_emails ue ON e.id=ue.email_id
INNER JOIN users u ON ue.user_id=u.id
WHERE
ue.is_backup=1 AND
u.session_id=${this.#id}`
      ).affectedRows > 0
    );
  }

  /**
   * @async
   * @function getUserData
   * @returns {Promise<{email:string,display_name?:string,email2?:string}|undefined>}
   */
  async getUserData() {
    const [data] = await sql`SELECT
u.display_name,ANY_VALUE(CASE WHEN ue.is_backup=FALSE THEN e.email END)
AS email,ANY_VALUE(CASE WHEN ue.is_backup=TRUE THEN e.email END)
AS email2
FROM users u
INNER JOIN user_emails ue ON u.id=ue.user_id
INNER JOIN emails e ON ue.email_id=e.id
WHERE u.session_id=${this.#id}
GROUP BY u.id`;

    if (!data) {
      return;
    }

    if (!data.display_name) {
      delete data.display_name;
    }

    if (!data.email2) {
      delete data.email2;
    }

    return data;
  }

  /**
   * @async
   * @function getUserId
   * @returns {Promise<bigint|number|undefined>}
   */
  async getUserId() {
    return (await sql`SELECT id FROM users WHERE session_id=${this.#id}`)[0]?.id;
  }

  /**
   * @async
   * @function isEmailTaken
   * @param {string} email
   * @returns {Promise<boolean|undefined>} `undefined` means the session is invalid.
   */
  async isEmailTaken(email) {
    const [result] = await sql`SELECT
EXISTS(SELECT 1 FROM emails e INNER JOIN user_emails ue ON e.id=ue.email_id WHERE e.email=${email})
FROM users
WHERE session_id=${this.#id}`.values();

    if (!result) {
      return;
    }

    return result[0] ?? false;
  }

  /**
   * @async
   * @function save
   */
  async save() {
    /**
     * @type {Uint8Array<ArrayBuffer>}
     */
    let additionalData;

    let kekId = await kmsSession.getCurrentId();

    if (this.#dek && this.#dekRotationDateMs && this.#dekRotationDateMs > Date.now() && this.#envelope.startsWith(kekId)) {
      additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);
    } else {
      let kek = await kmsSession.get(kekId);

      if (kek) {
        additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);
      } else {
        let i = 0;

        do {
          additionalData = createId(KEK_ID_BYTES);
          kekId = additionalData.toBase64(BASE64URL_OPTIONS);
          kek = await createKek();
          i++;
        } while (!(await kmsSession.store(kekId, kek)) && i < MAX_KMS_STORE_ATTEMPTS);

        if (i >= MAX_KMS_STORE_ATTEMPTS) {
          throw new Error("Too many attempts to store a KEK in KMS: SESSION");
        }
      }

      this.#dek = await createDek();
      this.#envelope = kekId + new Uint8Array(await wrapKey(this.#dek, kek)).toBase64(BASE64URL_OPTIONS);
      this.#dekRotationDateMs = Date.now() + 86400000; // Rotate DEK after one day.
    }

    const compressedDateNow = compressNumber(Date.now());

    this.#cookies.set(
      COOKIE_NAME_SESSION,
      this.#envelope +
        (await encryptTextSymmetrically(
          this.#dek,
          this.#idString +
            TOKEN_SEPARATOR +
            compressNumber(this.#dekRotationDateMs) +
            TOKEN_SEPARATOR +
            (this.#lastFetchDate ? compressNumber(this.#lastFetchDate) : compressedDateNow) +
            TOKEN_SEPARATOR +
            compressedDateNow,
          additionalData
        )),
      COOKIE_OPTIONS_SESSION
    );
  }

  /**
   * @async
   * @function swapEmails
   * @returns {Promise<boolean>}
   */
  async swapEmails() {
    /**
     * Checks if backup email is set too.
     */

    const { affectedRows } = await sql`UPDATE user_emails ue
INNER JOIN users u ON u.id=ue.user_id
SET ue.is_backup=!ue.is_backup
WHERE
u.session_id=${this.#id} AND
EXISTS(SELECT 1 FROM user_emails ue2 WHERE ue2.user_id=u.id AND ue2.is_backup=TRUE)`;

    return affectedRows > 0;
  }

  /**
   * @async
   * @function updateDisplayName
   * @param {string} newDisplayName
   * @returns {Promise<boolean>}
   */
  async updateDisplayName(newDisplayName) {
    const [user] = await sql`SELECT id,display_name FROM users WHERE session_id=${this.#id}`;

    if (!user) {
      return false;
    }

    if (user.display_name !== newDisplayName) {
      await sql`UPDATE users SET display_name=${newDisplayName} WHERE id=${user.id}`;
    }

    return true;
  }

  /**
   * @async
   * @function updateEmail
   * @param {string} newEmail
   * @param {boolean} backup
   * @returns {Promise<boolean>}
   */
  async updateEmail(newEmail, backup = false) {
    /**
     * Old email address will be deleted by the `delete_expired_rows` scheduler, see `setup.sql`.
     */

    const [data] = await sql`SELECT u.id,ue.is_backup,e.id AS email_id,ue.user_id=u.id AS owned
FROM users u
LEFT JOIN emails e ON e.email=${newEmail}
LEFT JOIN user_emails ue ON e.id=ue.email_id
WHERE u.session_id=${this.#id}`;

    if (!data || data.owned === false) {
      return false;
    }

    if (
      data.owned &&
      (data.is_backup === backup || (await sql`UPDATE user_emails SET is_backup=!is_backup WHERE user_id=${data.id}`).affectedRows)
    ) {
      return true;
    }

    const [currentUserEmail] = await sql`SELECT id,email_id FROM user_emails WHERE user_id=${data.id} AND is_backup=${backup}`;

    if (data.email_id != null) {
      if (currentUserEmail) {
        /**
         * In case that multiple concurrent requests from the same user try to set the same email,
         * `currentUserEmail.email_id` might have changed.
         */
        if (data.email_id === currentUserEmail.email_id) {
          return true;
        }

        return (await sql`UPDATE user_emails SET email_id=${data.email_id} WHERE id=${currentUserEmail.id}`).affectedRows > 0;
      }

      await sql`INSERT INTO user_emails (is_backup,email_id,user_id) VALUES (${backup},${data.email_id},${data.id})`;

      return true;
    }

    let result = false;

    await sql.begin(async tx => {
      data.email_id = (await tx`INSERT INTO emails (email) VALUES (${newEmail})`).lastInsertRowid;

      if (data.email_id == null) {
        console.error(
          "The email address was not saved in the database while trying to update an existing one: ",
          newEmail
        )
      } else if (currentUserEmail) {
        result = (
          await tx`UPDATE user_emails SET email_id=${data.email_id} WHERE id=${currentUserEmail.id}`
        ).affectedRows > 0;
      } else {
        result = (
          await tx`INSERT INTO user_emails (is_backup,email_id,user_id) VALUES (${backup},${data.email_id},${data.id})`
        ).affectedRows > 0;
      }
    });

    return result;
  }

  /**
   * This function (unlike `updateSessionId`) doesn't update the internal `id` state, so the session cannot be reused.
   *
   * @async
   * @function updateSessionIdFast
   * @returns {Promise<boolean>}
   */
  async updateSessionIdFast() {
    return (await sql`UPDATE users SET session_id=RANDOM_BYTES(18) WHERE session_id=${this.#id}`).affectedRows > 0;
  }
}
