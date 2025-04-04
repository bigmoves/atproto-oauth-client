// deno-lint-ignore-file require-await
import type { NodeSavedSession, NodeSavedState } from "./node-dpop-store.ts";
import { assert } from "@std/assert";
import { AtprotoOAuthClient } from "./mod.ts";

const PORT = 3000;

Deno.test("Creates authorize url", async () => {
  const url = `http://127.0.0.1:${PORT}`;
  const enc = encodeURIComponent;

  const stateStore = createInMemoryStore<NodeSavedState>();
  const sessionStore = createInMemoryStore<NodeSavedSession>();

  const oauthClient = new AtprotoOAuthClient({
    responseMode: "query",
    clientMetadata: {
      client_name: "ATProto Deno Client",
      client_id: `http://localhost?redirect_uri=${enc(
        `${url}/oauth/callback`
      )}&scope=${enc("atproto transition:chat.bsky transition:generic")}`,
      client_uri: url,
      redirect_uris: [`${url}/oauth/callback`],
      scope: "atproto transition:chat.bsky transition:generic",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      application_type: "web",
      token_endpoint_auth_method: "none",
      dpop_bound_access_tokens: true,
    },
    stateStore: stateStore,
    sessionStore: sessionStore,
  });

  const authorizeUrl = await oauthClient.authorize("bsky.app");

  assert(authorizeUrl, "Authorize URL should be created");
});

export function createInMemoryStore<T>(initialStore?: Map<string, T>): {
  get: (key: string) => Promise<T | undefined>;
  set: (key: string, val: T) => Promise<void>;
  del: (key: string) => Promise<void>;
} {
  const store = initialStore || new Map<string, T>();

  return {
    async get(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined;
    },

    async set(key: string, val: T) {
      store.set(key, val);
    },

    async del(key: string) {
      store.delete(key);
    },
  };
}
