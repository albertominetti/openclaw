// Ollama native embedding link-local opt-in: Podman host gateway only.
import { coerceErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import type { OpenClawConfig } from "openclaw/plugin-sdk/provider-auth";
import type { fetchConfiguredLocalOriginWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime-internal";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { createOllamaEmbeddingProvider } from "./embedding-provider.runtime.js";

type ConfiguredLocalOriginRequest = Parameters<typeof fetchConfiguredLocalOriginWithSsrFGuard>[0];

const { fetchConfiguredLocalOriginWithSsrFGuardMock } = vi.hoisted(() => ({
  fetchConfiguredLocalOriginWithSsrFGuardMock: vi.fn(
    async (_request: ConfiguredLocalOriginRequest) => ({
      response: new Response(JSON.stringify({ embeddings: [[1, 0]] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
      release: async () => {},
    }),
  ),
}));

// mock-isolation: embedding tests must not reach the real network fetch guard
vi.mock("openclaw/plugin-sdk/ssrf-runtime", () => ({
  fetchWithSsrFGuard: vi.fn(),
  formatErrorMessage: coerceErrorMessage,
  ssrfPolicyFromHttpBaseUrlAllowedOrigin: (baseUrl: string) => {
    const parsed = new URL(baseUrl);
    return { allowedOrigins: [parsed.origin] };
  },
}));

// mock-isolation: embedding tests must not reach the real configured-origin helper
vi.mock("openclaw/plugin-sdk/ssrf-runtime-internal", () => ({
  fetchConfiguredLocalOriginWithSsrFGuard: fetchConfiguredLocalOriginWithSsrFGuardMock,
}));

beforeEach(() => {
  fetchConfiguredLocalOriginWithSsrFGuardMock.mockClear();
});

function providerConfig(provider: Record<string, unknown>, providerId = "ollama") {
  return {
    models: { providers: { [providerId]: provider } },
  } as unknown as OpenClawConfig;
}

describe("ollama native embedding podman gateway opt-in", () => {
  it("opts in for the provider-owned Podman host gateway", async () => {
    const { client } = await createOllamaEmbeddingProvider({
      config: providerConfig({
        baseUrl: "http://host.containers.internal:11434",
      }),
      provider: "ollama",
      model: "nomic-embed-text",
    } as never);
    expect(client.allowPodmanHostGatewayLinkLocal).toBe(true);
    expect(client.ssrfPolicy).toEqual({
      allowedOrigins: ["http://host.containers.internal:11434"],
    });
    // No global private/link-local allowance: scoping lives in the host-only
    // fetch helper, not in the public policy object.
    expect(client.ssrfPolicy).not.toHaveProperty("allowPrivateNetwork");
    expect(client.ssrfPolicy).not.toHaveProperty("allowedHostnames");

    const embeddings = await client.embedBatch(["hello"]);
    expect(embeddings).toHaveLength(1);
    expect(fetchConfiguredLocalOriginWithSsrFGuardMock).toHaveBeenCalledOnce();
    expect(
      fetchConfiguredLocalOriginWithSsrFGuardMock.mock.calls[0]?.[0]
        .allowPodmanHostGatewayLinkLocal,
    ).toBe(true);
  });

  it("opts in for a remote override equivalent to the provider gateway host", async () => {
    const { client } = await createOllamaEmbeddingProvider({
      config: providerConfig({
        baseUrl: "http://host.containers.internal:11434/v1",
      }),
      provider: "ollama",
      model: "nomic-embed-text",
      remote: { baseUrl: "http://host.containers.internal:11434" },
    } as never);
    expect(client.allowPodmanHostGatewayLinkLocal).toBe(true);
    const embeddings = await client.embedBatch(["hello"]);
    expect(embeddings).toHaveLength(1);
    expect(
      fetchConfiguredLocalOriginWithSsrFGuardMock.mock.calls[0]?.[0]
        .allowPodmanHostGatewayLinkLocal,
    ).toBe(true);
  });

  it("does not opt in for a separate remote embedding host", async () => {
    const { client } = await createOllamaEmbeddingProvider({
      config: providerConfig({
        baseUrl: "http://host.containers.internal:11434",
      }),
      provider: "ollama",
      model: "nomic-embed-text",
      remote: { baseUrl: "http://embeddings-remote.test:11435" },
    } as never);
    expect(client.allowPodmanHostGatewayLinkLocal).toBe(false);
    const embeddings = await client.embedBatch(["hello"]);
    expect(embeddings).toHaveLength(1);
    expect(
      fetchConfiguredLocalOriginWithSsrFGuardMock.mock.calls[0]?.[0]
        .allowPodmanHostGatewayLinkLocal,
    ).toBe(false);
  });

  it("does not opt in for another provider-owned host that is not the Podman gateway", async () => {
    const { client } = await createOllamaEmbeddingProvider({
      config: providerConfig({
        baseUrl: "http://ollama.lan:11434",
      }),
      provider: "ollama",
      model: "nomic-embed-text",
    } as never);
    expect(client.allowPodmanHostGatewayLinkLocal).toBe(false);
    const embeddings = await client.embedBatch(["hello"]);
    expect(embeddings).toHaveLength(1);
    expect(
      fetchConfiguredLocalOriginWithSsrFGuardMock.mock.calls[0]?.[0]
        .allowPodmanHostGatewayLinkLocal,
    ).toBe(false);
  });
});
