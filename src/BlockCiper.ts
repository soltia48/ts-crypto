/*
 * BlockCipher.ts
 * @author soltia48
 * @date 2019-02-22
 */

export default interface BlockCipher {
  blockSize: number;
  key: number[];
  encrypt(plaintext: number[], offset?: number): number[];
  decrypt(ciphertext: number[], offset?: number): number[];
}
