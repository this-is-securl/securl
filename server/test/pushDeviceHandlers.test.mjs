import assert from "node:assert/strict";
import test from "node:test";
import { classifyDeviceHealth } from "../pushDeviceHandlers.mjs";

const NOW = Date.parse("2026-06-19T12:00:00.000Z");

function buildDevice(overrides = {}) {
  return {
    id: "device-1",
    lastSeenAt: "2026-06-19T11:55:00.000Z",
    lastPushStatus: null,
    disabledAt: null,
    ...overrides,
  };
}

test("push device health classifies recently seen devices as ready", () => {
  assert.deepEqual(classifyDeviceHealth(buildDevice(), NOW), {
    status: "ready",
    stale: false,
    needsRegistration: false,
    reason: null,
  });
});

test("push device health flags stale registrations", () => {
  assert.deepEqual(
    classifyDeviceHealth(buildDevice({
      lastSeenAt: "2026-05-01T12:00:00.000Z",
    }), NOW),
    {
      status: "stale",
      stale: true,
      needsRegistration: true,
      reason: "last_seen_stale",
    },
  );
});

test("push device health flags APNs token rejections as needing registration", () => {
  assert.deepEqual(
    classifyDeviceHealth(buildDevice({
      lastPushStatus: "apns_410",
    }), NOW),
    {
      status: "rejected",
      stale: false,
      needsRegistration: true,
      reason: "apns_410",
    },
  );
});

test("push device health reports transient send failures without forcing registration", () => {
  assert.deepEqual(
    classifyDeviceHealth(buildDevice({
      lastPushStatus: "send_failed",
    }), NOW),
    {
      status: "push_failed",
      stale: false,
      needsRegistration: false,
      reason: "last_push_failed",
    },
  );
});
