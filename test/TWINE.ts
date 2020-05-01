/*
 * TWINE.ts
 * @author soltia48
 * @date 2019-02-21
 */

import TWINE from "../src/TWINE";
import * as ArrayHelper from "../src/helpers/ArrayHelper";

const testVectorPlaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const testVectorKey80 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
const testVectorCiphertext80 = [0x7c, 0x1f, 0x0f, 0x80, 0xb1, 0xdf, 0x9c, 0x28];
const testVectorKey128 = [
  0x00,
  0x11,
  0x22,
  0x33,
  0x44,
  0x55,
  0x66,
  0x77,
  0x88,
  0x99,
  0xaa,
  0xbb,
  0xcc,
  0xdd,
  0xee,
  0xff,
];
const testVectorCiphertext128 = [0x97, 0x9f, 0xf9, 0xb3, 0x79, 0xb5, 0xa9, 0xb8];

export const run80 = (): void => {
  console.log("Begin TWINE-80 test.");
  const twine = new TWINE(testVectorKey80);
  const ciphertext80 = twine.encrypt(testVectorPlaintext);
  if (!ArrayHelper.equal(ciphertext80, testVectorCiphertext80)) {
    throw new Error("Ciphertext-80 is invalid.");
  }
  const plaintext80 = twine.decrypt(ciphertext80);
  if (!ArrayHelper.equal(plaintext80, testVectorPlaintext)) {
    throw new Error("Plaintext-80 is invalid.");
  }
  console.log("TWINE-80 test was successful.");
};

export const run128 = (): void => {
  console.log("Begin TWINE-128 test.");
  const twine = new TWINE(testVectorKey128);
  const ciphertext128 = twine.encrypt(testVectorPlaintext);
  if (!ArrayHelper.equal(ciphertext128, testVectorCiphertext128)) {
    throw new Error("Ciphertext-128 is invalid.");
  }
  const plaintext128 = twine.decrypt(ciphertext128);
  if (!ArrayHelper.equal(plaintext128, testVectorPlaintext)) {
    throw new Error("Plaintext-128 is invalid.");
  }
  console.log("TWINE-128 test was successful.");
};

export const runAll = (): void => {
  run80();
  run128();
};
