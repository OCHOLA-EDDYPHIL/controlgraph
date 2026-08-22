import { afterEach, describe, expect, it, vi } from "vitest";

import { OperatorApiError } from "./api/operator";
import {
  GoogleOperatorIdentityBridge,
  installGoogleOperatorIdentity,
  type GoogleIdentityApi,
} from "./googleOperatorIdentity";

const CLIENT_ID = "32555940559.apps.googleusercontent.com";
const NOW = 1_776_236_400;

function base64Url(value: string): string {
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function idToken(nonce: string, changes: Record<string, unknown> = {}): string {
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({
    iss: "https://accounts.google.com",
    aud: CLIENT_ID,
    email: "operator@example.com",
    email_verified: true,
    sub: "123456789012345678901",
    iat: NOW - 30,
    exp: NOW + 600,
    nonce,
    ...changes,
  }));
  return `${header}.${payload}.synthetic-signature`;
}

class FakeGoogleIdentity implements GoogleIdentityApi {
  configuration: Parameters<GoogleIdentityApi["initialize"]>[0] | null = null;
  prompts = 0;
  changes: Record<string, unknown> = {};
  holdPrompt = false;

  initialize(configuration: Parameters<GoogleIdentityApi["initialize"]>[0]): void {
    this.configuration = configuration;
  }

  prompt(): void {
    this.prompts += 1;
    if (this.holdPrompt) {
      return;
    }
    const configuration = this.configuration;
    if (configuration === null) {
      throw new Error("not initialized");
    }
    queueMicrotask(() => {
      configuration.callback({
        credential: idToken(configuration.nonce, this.changes),
      });
    });
  }
}

afterEach(() => {
  delete window.controlGraphOperatorIdentity;
  vi.restoreAllMocks();
});

describe("Google operator identity bridge", () => {
  it("returns a bounded human credential with a Google-signed session nonce", async () => {
    const identity = new FakeGoogleIdentity();
    const bridge = new GoogleOperatorIdentityBridge(CLIENT_ID, {
      identityApi: identity,
      now: () => NOW,
    });

    const credential = await bridge.getCredential({ fresh: false });

    expect(credential).toMatchObject({
      principal: "operator@example.com",
      subject: "123456789012345678901",
      expiresAtEpochSeconds: NOW + 600,
      csrfToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      idToken: expect.stringMatching(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/),
    });
    expect(identity.configuration).toMatchObject({
      client_id: CLIENT_ID,
      nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      auto_select: false,
      cancel_on_tap_outside: false,
      use_fedcm_for_prompt: true,
    });
    const digest = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(
          `controlgraph.operator-csrf-sha256/v1\0${credential.csrfToken}`,
        ),
      ),
    );
    let binary = "";
    for (const byte of digest) {
      binary += String.fromCharCode(byte);
    }
    expect(
      btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""),
    ).toBe(identity.configuration?.nonce);
  });

  it("keeps credentials only in memory and reacquires when freshness is required", async () => {
    const identity = new FakeGoogleIdentity();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const bridge = new GoogleOperatorIdentityBridge(CLIENT_ID, {
      identityApi: identity,
      now: () => NOW,
    });

    const first = await bridge.getCredential({ fresh: false });
    const cached = await bridge.getCredential({ fresh: false });
    const refreshed = await bridge.getCredential({ fresh: true });

    expect(cached).toBe(first);
    expect(refreshed.csrfToken).toBe(first.csrfToken);
    expect(identity.prompts).toBe(2);
    expect(setItem).not.toHaveBeenCalled();
  });

  it("rejects substituted identity, audience, lifetime, and nonce claims", async () => {
    for (const changes of [
      { email: "service@project.iam.gserviceaccount.com" },
      { aud: "another.apps.googleusercontent.com" },
      { exp: NOW + 4_000 },
      { nonce: "a".repeat(43) },
    ]) {
      const identity = new FakeGoogleIdentity();
      identity.changes = changes;
      const bridge = new GoogleOperatorIdentityBridge(CLIENT_ID, {
        identityApi: identity,
        now: () => NOW,
      });

      await expect(bridge.getCredential({ fresh: true })).rejects.toEqual(
        new OperatorApiError(
          "AUTHENTICATION_REQUIRED",
          "GOOGLE_IDENTITY_RESPONSE_INVALID",
        ),
      );
    }
  });

  it("honors cancellation without exposing a credential", async () => {
    const identity = new FakeGoogleIdentity();
    identity.holdPrompt = true;
    const bridge = new GoogleOperatorIdentityBridge(CLIENT_ID, {
      identityApi: identity,
      now: () => NOW,
    });
    const controller = new AbortController();
    const result = bridge.getCredential({ fresh: true, signal: controller.signal });

    controller.abort();

    await expect(result).rejects.toMatchObject({ name: "AbortError" });
  });

  it("does not let one cancelled waiter discard another credential request", async () => {
    const identity = new FakeGoogleIdentity();
    identity.holdPrompt = true;
    const bridge = new GoogleOperatorIdentityBridge(CLIENT_ID, {
      identityApi: identity,
      now: () => NOW,
    });
    const controller = new AbortController();

    const cancelled = bridge.getCredential({ fresh: true, signal: controller.signal });
    const retained = bridge.getCredential({ fresh: true });
    controller.abort();

    await expect(cancelled).rejects.toMatchObject({ name: "AbortError" });
    await vi.waitFor(() => expect(identity.configuration).not.toBeNull());
    const configuration = identity.configuration!;
    configuration.callback({ credential: idToken(configuration.nonce) });

    await expect(retained).resolves.toMatchObject({
      principal: "operator@example.com",
      subject: "123456789012345678901",
    });
    expect(identity.prompts).toBe(1);
  });

  it("installs only for an exact Google OAuth client audience", () => {
    installGoogleOperatorIdentity(undefined);
    expect(window.controlGraphOperatorIdentity).toBeUndefined();

    installGoogleOperatorIdentity("not-an-oauth-client");
    expect(window.controlGraphOperatorIdentity).toBeUndefined();

    installGoogleOperatorIdentity(CLIENT_ID);
    expect(window.controlGraphOperatorIdentity).toBeInstanceOf(
      GoogleOperatorIdentityBridge,
    );
  });
});
