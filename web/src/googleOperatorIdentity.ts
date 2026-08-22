import {
  OperatorApiError,
  type ControlGraphOperatorIdentityBridge,
  type OperatorCredential,
} from "./api/operator";

const GOOGLE_IDENTITY_SCRIPT = "https://accounts.google.com/gsi/client";
const GOOGLE_IDENTITY_SCRIPT_ID = "controlgraph-google-identity";
const CSRF_SHA256_DOMAIN = "controlgraph.operator-csrf-sha256/v1\0";
const MAX_ID_TOKEN_BYTES = 6_144;
const MAX_TOKEN_LIFETIME_SECONDS = 3_660;
const CACHED_TOKEN_MARGIN_SECONDS = 60;
const oauthClientAudience =
  /^[0-9]{6,32}(?:-[a-z0-9]{6,128})?\.apps\.googleusercontent\.com$/;
const jwtSegment = /^[A-Za-z0-9_-]+$/;
const nonceDigest = /^[A-Za-z0-9_-]{43}$/;
const googleSubject = /^[1-9][0-9]{5,31}$/;
const humanEmail =
  /^[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;

interface GoogleCredentialResponse {
  readonly credential?: string;
}

interface GooglePromptMomentNotification {
  isNotDisplayed?(): boolean;
  isSkippedMoment?(): boolean;
  isDismissedMoment?(): boolean;
}

interface GoogleIdentityConfiguration {
  readonly client_id: string;
  readonly callback: (response: GoogleCredentialResponse) => void;
  readonly nonce: string;
  readonly auto_select: false;
  readonly cancel_on_tap_outside: false;
  readonly context: "signin";
  readonly itp_support: true;
  readonly use_fedcm_for_prompt: true;
}

export interface GoogleIdentityApi {
  initialize(configuration: GoogleIdentityConfiguration): void;
  prompt(
    listener?: (notification: GooglePromptMomentNotification) => void,
  ): void;
}

declare global {
  interface Window {
    controlGraphOperatorConfig?: {
      readonly oauthClientAudience: string;
    };
    google?: {
      readonly accounts?: {
        readonly id?: GoogleIdentityApi;
      };
    };
  }
}

interface BridgeDependencies {
  readonly identityApi?: GoogleIdentityApi;
  readonly crypto?: Crypto;
  readonly now?: () => number;
}

interface PendingCredential {
  readonly promise: Promise<OperatorCredential>;
  readonly resolve: (credential: OperatorCredential) => void;
  readonly reject: (error: OperatorApiError) => void;
}

function authenticationFailure(code: string): OperatorApiError {
  return new OperatorApiError("AUTHENTICATION_REQUIRED", code);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function randomCsrfToken(cryptoProvider: Crypto): string {
  const bytes = new Uint8Array(32);
  cryptoProvider.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

async function csrfNonce(cryptoProvider: Crypto, csrfToken: string): Promise<string> {
  const digest = new Uint8Array(
    await cryptoProvider.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`${CSRF_SHA256_DOMAIN}${csrfToken}`),
    ),
  );
  return bytesToBase64Url(digest);
}

function decodePayload(idToken: string): Record<string, unknown> {
  if (idToken.length > MAX_ID_TOKEN_BYTES) {
    throw authenticationFailure("OPERATOR_ID_TOKEN_INVALID");
  }
  const segments = idToken.split(".");
  if (
    segments.length !== 3 ||
    segments.some((segment) => segment.length === 0 || !jwtSegment.test(segment))
  ) {
    throw authenticationFailure("OPERATOR_ID_TOKEN_INVALID");
  }
  const payloadSegment = segments[1]!;
  const paddingLength = (4 - (payloadSegment.length % 4)) % 4;
  const encoded = payloadSegment.replaceAll("-", "+").replaceAll("_", "/") +
    "=".repeat(paddingLength);
  try {
    const binary = atob(encoded);
    if (binary.length > 4_096) {
      throw authenticationFailure("OPERATOR_ID_TOKEN_INVALID");
    }
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
      throw authenticationFailure("OPERATOR_ID_TOKEN_INVALID");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof OperatorApiError) {
      throw error;
    }
    throw authenticationFailure("OPERATOR_ID_TOKEN_INVALID");
  }
}

function parseCredential(
  idToken: string,
  csrfToken: string,
  expectedAudience: string,
  expectedNonce: string,
  now: number,
): OperatorCredential {
  const claims = decodePayload(idToken);
  const principal = claims.email;
  const subject = claims.sub;
  const issuedAt = claims.iat;
  const expiresAt = claims.exp;
  if (
    !["accounts.google.com", "https://accounts.google.com"].includes(
      String(claims.iss),
    ) ||
    claims.aud !== expectedAudience ||
    claims.email_verified !== true ||
    typeof principal !== "string" ||
    !humanEmail.test(principal) ||
    principal.endsWith(".iam.gserviceaccount.com") ||
    typeof subject !== "string" ||
    !googleSubject.test(subject) ||
    !Number.isSafeInteger(issuedAt) ||
    !Number.isSafeInteger(expiresAt) ||
    (issuedAt as number) >= (expiresAt as number) ||
    (expiresAt as number) - (issuedAt as number) > MAX_TOKEN_LIFETIME_SECONDS ||
    (expiresAt as number) <= now + 15 ||
    claims.nonce !== expectedNonce
  ) {
    throw authenticationFailure("OPERATOR_ID_TOKEN_INVALID");
  }
  return Object.freeze({
    principal,
    subject,
    expiresAtEpochSeconds: expiresAt as number,
    idToken,
    csrfToken,
  });
}

function abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal?.aborted) {
    return Promise.reject(new DOMException("aborted", "AbortError"));
  }
  if (signal === undefined) {
    return promise;
  }
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(new DOMException("aborted", "AbortError"));
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

function loadGoogleIdentityApi(): Promise<GoogleIdentityApi> {
  const available = window.google?.accounts?.id;
  if (available !== undefined) {
    return Promise.resolve(available);
  }
  return new Promise((resolve, reject) => {
    const existing = document.getElementById(GOOGLE_IDENTITY_SCRIPT_ID);
    const script = existing instanceof HTMLScriptElement
      ? existing
      : document.createElement("script");
    const loaded = (): void => {
      const identityApi = window.google?.accounts?.id;
      if (identityApi === undefined) {
        reject(authenticationFailure("GOOGLE_IDENTITY_UNAVAILABLE"));
      } else {
        resolve(identityApi);
      }
    };
    const failed = (): void => {
      reject(authenticationFailure("GOOGLE_IDENTITY_UNAVAILABLE"));
    };
    script.addEventListener("load", loaded, { once: true });
    script.addEventListener("error", failed, { once: true });
    if (existing === null) {
      script.id = GOOGLE_IDENTITY_SCRIPT_ID;
      script.src = GOOGLE_IDENTITY_SCRIPT;
      script.async = true;
      script.defer = true;
      script.referrerPolicy = "no-referrer";
      document.head.append(script);
    }
  });
}

export class GoogleOperatorIdentityBridge
implements ControlGraphOperatorIdentityBridge {
  private readonly cryptoProvider: Crypto;
  private readonly now: () => number;
  private readonly csrfToken: string;
  private readonly nonce: Promise<string>;
  private readonly suppliedIdentityApi: GoogleIdentityApi | undefined;
  private initialization: Promise<GoogleIdentityApi> | null = null;
  private initializedApi: GoogleIdentityApi | null = null;
  private pending: PendingCredential | null = null;
  private cached: OperatorCredential | null = null;

  constructor(
    private readonly clientId: string,
    dependencies: BridgeDependencies = {},
  ) {
    if (!oauthClientAudience.test(clientId)) {
      throw authenticationFailure("OPERATOR_OAUTH_CLIENT_INVALID");
    }
    this.cryptoProvider = dependencies.crypto ?? globalThis.crypto;
    if (
      this.cryptoProvider === undefined ||
      typeof this.cryptoProvider.getRandomValues !== "function" ||
      this.cryptoProvider.subtle === undefined
    ) {
      throw authenticationFailure("OPERATOR_SESSION_ENTROPY_UNAVAILABLE");
    }
    this.now = dependencies.now ?? (() => Math.floor(Date.now() / 1_000));
    this.csrfToken = randomCsrfToken(this.cryptoProvider);
    this.nonce = csrfNonce(this.cryptoProvider, this.csrfToken);
    this.suppliedIdentityApi = dependencies.identityApi;
  }

  private async initialize(signal?: AbortSignal): Promise<GoogleIdentityApi> {
    if (this.initializedApi !== null) {
      return this.initializedApi;
    }
    this.initialization ??= (async () => {
      const identityApi = this.suppliedIdentityApi ?? await loadGoogleIdentityApi();
      const nonce = await this.nonce;
      identityApi.initialize({
        client_id: this.clientId,
        callback: (response) => this.receiveCredential(response),
        nonce,
        auto_select: false,
        cancel_on_tap_outside: false,
        context: "signin",
        itp_support: true,
        use_fedcm_for_prompt: true,
      });
      this.initializedApi = identityApi;
      return identityApi;
    })();
    return abortable(this.initialization, signal);
  }

  private receiveCredential(response: GoogleCredentialResponse): void {
    const pending = this.pending;
    if (pending === null) {
      return;
    }
    void (async () => {
      try {
        if (typeof response.credential !== "string") {
          throw authenticationFailure("GOOGLE_IDENTITY_RESPONSE_INVALID");
        }
        const credential = parseCredential(
          response.credential,
          this.csrfToken,
          this.clientId,
          await this.nonce,
          this.now(),
        );
        this.cached = credential;
        pending.resolve(credential);
      } catch {
        pending.reject(authenticationFailure("GOOGLE_IDENTITY_RESPONSE_INVALID"));
      } finally {
        if (this.pending === pending) {
          this.pending = null;
        }
      }
    })();
  }

  private prompt(identityApi: GoogleIdentityApi): Promise<OperatorCredential> {
    if (this.pending !== null) {
      return this.pending.promise;
    }
    let resolveCredential!: (credential: OperatorCredential) => void;
    let rejectCredential!: (error: OperatorApiError) => void;
    const promise = new Promise<OperatorCredential>((resolve, reject) => {
      resolveCredential = resolve;
      rejectCredential = reject;
    });
    const pending = {
      promise,
      resolve: resolveCredential,
      reject: rejectCredential,
    };
    this.pending = pending;
    try {
      identityApi.prompt((notification) => {
        if (
          notification.isNotDisplayed?.() === true ||
          notification.isSkippedMoment?.() === true ||
          notification.isDismissedMoment?.() === true
        ) {
          if (this.pending === pending) {
            this.pending = null;
          }
          pending.reject(authenticationFailure("GOOGLE_IDENTITY_NOT_AVAILABLE"));
        }
      });
    } catch {
      this.pending = null;
      pending.reject(authenticationFailure("GOOGLE_IDENTITY_UNAVAILABLE"));
    }
    return promise;
  }

  async getCredential(options: {
    readonly fresh: boolean;
    readonly signal?: AbortSignal;
  }): Promise<OperatorCredential> {
    if (
      !options.fresh &&
      this.cached !== null &&
      this.cached.expiresAtEpochSeconds > this.now() + CACHED_TOKEN_MARGIN_SECONDS
    ) {
      return this.cached;
    }
    if (options.fresh) {
      this.cached = null;
    }
    const identityApi = await this.initialize(options.signal);
    const prompt = this.prompt(identityApi);
    return abortable(prompt, options.signal);
  }
}

export function installGoogleOperatorIdentity(clientId: string | undefined): void {
  if (clientId === undefined || !oauthClientAudience.test(clientId)) {
    return;
  }
  window.controlGraphOperatorIdentity = new GoogleOperatorIdentityBridge(clientId);
}
