/*
 * index.ts
 * @author soltia48
 * @date 2020-05-01
 */

import * as TWINE from "./TWINE";

(async (): Promise<void> => {
  TWINE.runAll();
})().catch((e) => {
  throw e;
});
