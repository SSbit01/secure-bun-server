import { describe, expect, test } from "bun:test"

import { createDek, encryptTextSymmetrically, decryptTextSymmetrically } from "#src/lib/crypto/symmetric/dek"
import { createBase64UrlId } from "#src/lib/crypto/id"



describe("DEK", () => {

  test("Generate a random symmetric CryptoKey", async () => {
    const key = await createDek()
    expect(key).toBeDefined()
  })
  
  test("Encrypt a random value", async () => { 
    const key = await createDek()
    expect(await encryptTextSymmetrically(key, createBase64UrlId())).toBeString()
  })
  
  test("Decrypt a random value", async () => {
    const symCryptoKey = await createDek()
    const randomValue = createBase64UrlId()
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue)
    const decrypted = await decryptTextSymmetrically(symCryptoKey, ciphertext)
    expect(randomValue).toBe(decrypted)
  })
  
  test("Check if encrypting and decrypting with different CryptoKey objects returns an error", async () => {
    const symCryptoKey = await createDek()
    const symCryptoKey2 = await createDek()
    const randomValue = createBase64UrlId()
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue)
    await expect(decryptTextSymmetrically(symCryptoKey2, ciphertext)).rejects.toThrow()
  })

})