/*
 * ArrayHelper.ts
 * @author soltia48
 * @date 2019-02-23
 */

export const equal = <T>(a: Array<T>, b: Array<T>): boolean => {
  if (a === b) {
    return true;
  }
  // if (a === null || b === null) {
  //   return false
  // }
  if (a.length !== b.length) {
    return false;
  }

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
};

export const resize = <T>(array: Array<T>, newSize: number, defaultValue: T): void => {
  while (newSize > array.length) {
    array.push(defaultValue);
  }
  array.length = newSize;
};
