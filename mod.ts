import { createHash, randomBytes } from "node:crypto";
import { JoseKey } from "./jose-key.ts";
import {
  OAuthClient,
  type Key,
  type OAuthClientFetchMetadataOptions,
  type OAuthClientOptions,
  type RuntimeLock,
} from "@atproto/oauth-client";
import type { OAuthResponseMode } from "@atproto/oauth-types";
import {
  AtprotoHandleResolverNode,
  type AtprotoHandleResolverNodeOptions,
} from "@atproto-labs/handle-resolver-node";
import {
  type NodeSavedSessionStore,
  type NodeSavedStateStore,
  toDpopKeyStore,
} from "./node-dpop-store.ts";

export type * from "./node-dpop-store.ts";
export type { OAuthClientOptions, OAuthResponseMode, RuntimeLock };

export type AtprotoOAuthClientOptions = Omit<
  OAuthClientOptions,
  // Overridden by this lib
  | "responseMode"
  | "stateStore"
  | "sessionStore"
  // Provided by this lib
  | "runtimeImplementation" // only "requestLock" needed
  | "handleResolver" // Will be build based on "fallbackNameservers"
> & {
  responseMode?: Exclude<OAuthResponseMode, "fragment">;

  stateStore: NodeSavedStateStore;
  sessionStore: NodeSavedSessionStore;

  fallbackNameservers?: AtprotoHandleResolverNodeOptions["fallbackNameservers"];
  requestLock?: RuntimeLock;
};

export type AtprotoOAuthClientFromMetadataOptions =
  OAuthClientFetchMetadataOptions &
    Omit<AtprotoOAuthClientOptions, "clientMetadata">;

export class AtprotoOAuthClient extends OAuthClient {
  static async fromClientId(
    options: AtprotoOAuthClientFromMetadataOptions
  ): Promise<AtprotoOAuthClient> {
    const clientMetadata = await OAuthClient.fetchMetadata(options);
    return new AtprotoOAuthClient({ ...options, clientMetadata });
  }

  constructor({
    fetch,
    responseMode = "query",
    fallbackNameservers,

    stateStore,
    sessionStore,
    requestLock = undefined,

    ...options
  }: AtprotoOAuthClientOptions) {
    if (!requestLock) {
      // Ok if only one instance of the client is running at a time.
      console.warn(
        "No lock mechanism provided. Credentials might get revoked."
      );
    }

    super({
      ...options,

      fetch,
      responseMode,
      handleResolver: new AtprotoHandleResolverNode({
        fetch,
        fallbackNameservers,
      }),
      runtimeImplementation: {
        requestLock,
        createKey: async (algs): Promise<Key> => {
          return (await JoseKey.generate(algs)) as unknown as Key;
        },
        getRandomValues: randomBytes,
        digest: (bytes, algorithm) =>
          createHash(algorithm.name).update(bytes).digest(),
      },

      stateStore: toDpopKeyStore(stateStore),
      sessionStore: toDpopKeyStore(sessionStore),
    });
  }
}
