/**
 * `DATETIME` does not hold any timezone information, so set the global timezone to UTC.
 */
SET GLOBAL time_zone = '+00:00';


CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  /**
   * If `NULL`, the user is set to be deleted.
   */
  session_id BINARY(18) UNIQUE,
  display_name VARCHAR(32),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME ON UPDATE CURRENT_TIMESTAMP
);

/**
 * Emails are stored in a separate table to allow the implementation of invitations easily.
 */
CREATE TABLE IF NOT EXISTS emails (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(254) UNIQUE NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_emails (
  email_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  is_backup BOOLEAN NOT NULL DEFAULT FALSE,
  user_id BIGINT UNSIGNED NOT NULL,
  updated_at DATETIME ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT uk_user_emails_is_backup_user_id UNIQUE (is_backup, user_id),
  CONSTRAINT fk_user_emails_emails FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_emails_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);