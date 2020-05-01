/*
 * OMAC.ts
 * @author soltia48
 * @date 2019-02-23
 */

import BlockCipher from "./BlockCiper";
import * as ArrayHelper from "./helpers/ArrayHelper";

export default class OMAC {
  private _cipher!: BlockCipher;
  private _k1!: number[];
  private _k2!: number[];
  private _lastBlock!: number[];

  constructor(cipher: BlockCipher) {
    this.cipher = cipher;
  }

  get cipher(): BlockCipher {
    return this._cipher;
  }

  set cipher(cipher) {
    this._cipher = cipher;
    this.initialize();
  }

  initialize(): void {
    this._lastBlock = Array(this.cipher.blockSize).fill(0x00);
    this.keySchedule();
  }

  private keySchedule(): void {
    let c: number[];
    switch (this.cipher.blockSize) {
      case 8:
        c = Array(1);
        c[0] = 0x1b;
        break;
      case 16:
        c = Array(1);
        c[0] = 0x87;
        break;
      case 32:
        c = Array(2);
        c[0] = 0x04;
        c[1] = 0x25;
        break;
      case 64:
        c = Array(2);
        c[0] = 0x01;
        c[1] = 0x25;
        break;
      case 128:
        c = Array(2);
        c[0] = 0x87;
        c[1] = 0x43;
        break;
      default:
        throw new Error("Invalid cipher key length.");
    }

    const k0 = this.cipher.encrypt(Array(this.cipher.blockSize));

    this._k1 = Array(this.cipher.blockSize);
    for (let i = 0; i < this.cipher.blockSize; i++) {
      if (i === this.cipher.blockSize - 1) {
        this._k1[i] = (k0[i] << 1) | (k0[i + 1] >> 7);
      } else {
        this._k1[i] = k0[i] << 1;
      }
    }
    if (!(k0[0] & 0x80)) {
      for (let i = 0; i < c.length; i++) {
        this._k1[this.cipher.blockSize - i - 1] ^= c[c.length - i - 1];
      }
    }

    this._k2 = Array(this.cipher.blockSize);
    for (let i = 0; i < this.cipher.blockSize; i++) {
      if (i === this.cipher.blockSize - 1) {
        this._k2[i] = (this._k1[i] << 1) | (this._k1[i + 1] >> 7);
      } else {
        this._k2[i] = this._k1[i] << 1;
      }
    }
    if (!(this._k1[0] & 0x80)) {
      for (let i = 0; i < c.length; i++) {
        this._k2[this.cipher.blockSize - i - 1] ^= c[c.length - i - 1];
      }
    }
  }

  update(message: number[], isLast: boolean): void {
    let fraction = message.length % this.cipher.blockSize;
    if (!isLast && fraction) {
      throw new Error("Invalid message length of not last block.");
    }

    const messageCopy = message.concat();

    if (!messageCopy.length || fraction) {
      if (fraction) {
        messageCopy.push(0x80);
      }
      fraction = messageCopy.length % this.cipher.blockSize;
      if (fraction) {
        ArrayHelper.resize(
          messageCopy,
          messageCopy.length + this.cipher.blockSize - fraction,
          0x00
        );
      }
    }
    const blockCount = messageCopy.length / this.cipher.blockSize;
    for (let i = 0; i < blockCount; i++) {
      const offset = this.cipher.blockSize * i;
      if (i === blockCount - 1) {
        for (let j = 0; j < this.cipher.blockSize; j++) {
          if (!fraction) {
            messageCopy[offset + i] ^= this._k1[j];
          } else {
            messageCopy[offset + i] ^= this._k2[j];
          }
        }
      }
      for (let j = 0; j < this.cipher.blockSize; j++) {
        messageCopy[offset + j] ^= this._lastBlock[j];
      }
      this._lastBlock = this.cipher.encrypt(messageCopy, offset);
    }
  }

  digest(): number[] {
    return this._lastBlock.concat();
  }
}
