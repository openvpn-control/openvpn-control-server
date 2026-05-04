import test from "node:test";
import assert from "node:assert/strict";
import { rootCaRemainingValidityDays } from "./serverNodeCertificateService.js";

test("rootCaRemainingValidityDays returns 0 for invalid PEM", () => {
  assert.equal(rootCaRemainingValidityDays("not-a-cert"), 0);
});
