/*
 * TWINE.ts
 * @author soltia48
 * @date 2019-02-21
 */

import BlockCipher from "./BlockCiper";

export default class TWINE implements BlockCipher {
  readonly blockSize = 8;

  private static readonly sbox = [
    0x0c,
    0x00,
    0x0f,
    0x0a,
    0x02,
    0x0b,
    0x09,
    0x05,
    0x08,
    0x03,
    0x0d,
    0x07,
    0x01,
    0x0e,
    0x06,
    0x04,
  ];
  private static readonly rcon = [
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x03,
    0x06,
    0x0c,
    0x18,
    0x30,
    0x23,
    0x05,
    0x0a,
    0x14,
    0x28,
    0x13,
    0x26,
    0x0f,
    0x1e,
    0x3c,
    0x3b,
    0x35,
    0x29,
    0x11,
    0x22,
    0x07,
    0x0e,
    0x1c,
    0x38,
    0x33,
    0x25,
    0x09,
    0x12,
    0x24,
    0x0b,
  ];
  private static readonly pi = [5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14];
  private static readonly invPi = [1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12];

  private _key!: number[];
  private _rk!: number[];

  constructor(key: number[]) {
    this.key = key;
  }

  get key(): number[] {
    return this._key.concat();
  }

  set key(key) {
    if (key.length === 10) {
      this.keySchedule80(key);
    } else if (key.length === 16) {
      this.keySchedule128(key);
    } else {
      throw new Error("Key length is invalid.");
    }
    this._key = key.concat();
  }

  private keySchedule80(key: number[]): void {
    const wk: number[] = Array(20);
    for (let i = 0; i < 10; i++) {
      wk[2 * i] = key[i] >> 4;
      wk[2 * i + 1] = key[i] & 0x0f;
    }

    this._rk = Array(36);
    for (let i = 0; i < 35; i++) {
      this._rk[i] =
        (wk[1] << 28) |
        (wk[3] << 24) |
        (wk[4] << 20) |
        (wk[6] << 16) |
        (wk[13] << 12) |
        (wk[14] << 8) |
        (wk[15] << 4) |
        wk[16];

      wk[1] ^= TWINE.sbox[wk[0]];
      wk[4] ^= TWINE.sbox[wk[16]];
      wk[7] ^= TWINE.rcon[i] >> 3;
      wk[19] ^= TWINE.rcon[i] & 0x07;

      const temp = wk.slice(0, 4);
      for (let j = 0; j < 4; j++) {
        const index = j * 4;
        wk[index] = wk[index + 4];
        wk[index + 1] = wk[index + 5];
        wk[index + 2] = wk[index + 6];
        wk[index + 3] = wk[index + 7];
      }
      wk[16] = temp[1];
      wk[17] = temp[2];
      wk[18] = temp[3];
      wk[19] = temp[0];
    }
    this._rk[35] =
      (wk[1] << 28) |
      (wk[3] << 24) |
      (wk[4] << 20) |
      (wk[6] << 16) |
      (wk[13] << 12) |
      (wk[14] << 8) |
      (wk[15] << 4) |
      wk[16];
  }

  private keySchedule128(key: number[]): void {
    const wk: number[] = Array(32);
    for (let i = 0; i < 16; i++) {
      wk[2 * i] = key[i] >> 4;
      wk[2 * i + 1] = key[i] & 0x0f;
    }

    this._rk = Array(36);
    for (let i = 0; i < 35; i++) {
      this._rk[i] =
        (wk[2] << 28) |
        (wk[3] << 24) |
        (wk[12] << 20) |
        (wk[15] << 16) |
        (wk[17] << 12) |
        (wk[18] << 8) |
        (wk[28] << 4) |
        wk[31];

      wk[1] ^= TWINE.sbox[wk[0]];
      wk[4] ^= TWINE.sbox[wk[16]];
      wk[23] ^= TWINE.sbox[wk[30]];
      wk[7] ^= TWINE.rcon[i] >> 3;
      wk[19] ^= TWINE.rcon[i] & 0x07;

      const temp = wk.slice(0, 4);
      for (let j = 0; j < 7; j++) {
        const index = j * 4;
        wk[index] = wk[index + 4];
        wk[index + 1] = wk[index + 5];
        wk[index + 2] = wk[index + 6];
        wk[index + 3] = wk[index + 7];
      }
      wk[28] = temp[1];
      wk[29] = temp[2];
      wk[30] = temp[3];
      wk[31] = temp[0];
    }
    this._rk[35] =
      (wk[2] << 28) |
      (wk[3] << 24) |
      (wk[12] << 20) |
      (wk[15] << 16) |
      (wk[17] << 12) |
      (wk[18] << 8) |
      (wk[28] << 4) |
      wk[31];
  }

  encrypt(plaintext: number[], offset?: number): number[] {
    offset = offset || 0;

    const x: number[] = Array(16);
    for (let i = 0; i < 8; i++) {
      x[2 * i] = plaintext[offset + i] >> 4;
      x[2 * i + 1] = plaintext[offset + i] & 0x0f;
    }

    for (let i = 0; i < 35; i++) {
      for (let j = 0; j < 8; j++) {
        x[2 * j + 1] ^= TWINE.sbox[x[2 * j] ^ ((this._rk[i] >> (28 - j * 4)) & 0x0f)];
      }

      const temp = x.concat();
      for (let h = 0; h < 16; h++) {
        x[TWINE.pi[h]] = temp[h];
      }
    }
    for (let j = 0; j < 8; j++) {
      x[2 * j + 1] ^= TWINE.sbox[x[2 * j] ^ ((this._rk[35] >> (28 - j * 4)) & 0x0f)];
    }

    const ciphertext: number[] = Array(8);
    for (let i = 0; i < 8; i++) {
      ciphertext[i] = (x[2 * i] << 4) | x[2 * i + 1];
    }
    return ciphertext;
  }

  decrypt(ciphertext: number[]): number[] {
    const x: number[] = Array(16);
    for (let i = 0; i < 8; i++) {
      x[2 * i] = ciphertext[i] >> 4;
      x[2 * i + 1] = ciphertext[i] & 0x0f;
    }

    for (let i = 35; i >= 1; i--) {
      for (let j = 0; j < 8; j++) {
        x[2 * j + 1] ^= TWINE.sbox[x[2 * j] ^ ((this._rk[i] >> (28 - j * 4)) & 0x0f)];
      }

      const temp = x.concat();
      for (let h = 0; h < 16; h++) {
        x[TWINE.invPi[h]] = temp[h];
      }
    }
    for (let j = 0; j < 8; j++) {
      x[2 * j + 1] ^= TWINE.sbox[x[2 * j] ^ ((this._rk[0] >> (28 - j * 4)) & 0x0f)];
    }

    const plaintext: number[] = Array(8);
    for (let i = 0; i < 8; i++) {
      plaintext[i] = (x[2 * i] << 4) | x[2 * i + 1];
    }
    return plaintext;
  }
}
