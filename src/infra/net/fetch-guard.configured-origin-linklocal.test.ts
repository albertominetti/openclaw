// Focused tests for the rootless-Podman host gateway link-local exemption.
// Covers host.containers.internal -> 169.254.1.2 through the real
// fetchConfiguredLocalOriginWithSsrFGuard entry point.
import { describe, expect, it, vi, afterEach } from "vitest";
import { fetchConfiguredLocalOriginWithSsrFGuard } from "./fetch-guard.js";

const GATEWAY_BASE = "http://host.containers.internal:11434";
const GATEWAY_URL = `${GATEWAY_BASE}/api/embed`;

const lookup = (address: string) =>
  vi.fn(async () => [{ address, family: address.includes(":") ? 6 : 4 }]);

const okResponse = () => new Response("ok");
const fetchStub = () => vi.fn(async () => okResponse());
const redirectResponse = (location: string, status = 302) =>
  new Response(null, { status, headers: { location } });

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("podman host gateway link-local exemption", () => {
  it("reaches host.containers.internal resolving to 169.254.1.2 with opt-in", async () => {
    const fetchImpl = fetchStub();
    const result = await fetchConfiguredLocalOriginWithSsrFGuard({
      url: GATEWAY_URL,
      configuredLocalOriginBaseUrl: GATEWAY_BASE,
      allowPodmanHostGatewayLinkLocal: true,
      policy: { allowedOrigins: [GATEWAY_BASE] },
      lookupFn: lookup("169.254.1.2"),
      fetchImpl,
    });
    expect(fetchImpl).toHaveBeenCalledOnce();
    await result.release();
  });

  it("rejects 169.254.1.2 without opt-in (exact-origin trust alone is not enough)", async () => {
    const fetchImpl = fetchStub();
    await expect(
      fetchConfiguredLocalOriginWithSsrFGuard({
        url: GATEWAY_URL,
        configuredLocalOriginBaseUrl: GATEWAY_BASE,
        policy: { allowedOrigins: [GATEWAY_BASE] },
        lookupFn: lookup("169.254.1.2"),
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("still rejects cloud metadata 169.254.169.254 with opt-in", async () => {
    const fetchImpl = fetchStub();
    await expect(
      fetchConfiguredLocalOriginWithSsrFGuard({
        url: GATEWAY_URL,
        configuredLocalOriginBaseUrl: GATEWAY_BASE,
        allowPodmanHostGatewayLinkLocal: true,
        policy: { allowedOrigins: [GATEWAY_BASE] },
        lookupFn: lookup("169.254.169.254"),
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("still rejects mapped IPv6 link-local with opt-in", async () => {
    const fetchImpl = fetchStub();
    await expect(
      fetchConfiguredLocalOriginWithSsrFGuard({
        url: GATEWAY_URL,
        configuredLocalOriginBaseUrl: GATEWAY_BASE,
        allowPodmanHostGatewayLinkLocal: true,
        policy: { allowedOrigins: [GATEWAY_BASE] },
        lookupFn: lookup("::ffff:169.254.1.2"),
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("grants no exemption on a cross-origin redirect", async () => {
    const otherBase = "http://other.example:11434";
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(redirectResponse(`${otherBase}/api/embed`))
      .mockResolvedValueOnce(okResponse());
    const lookupFn = vi.fn(async (hostname: string) => {
      if (hostname === "host.containers.internal") {
        return [{ address: "169.254.1.2", family: 4 as const }];
      }
      return [{ address: "169.254.1.2", family: 4 as const }];
    });
    await expect(
      fetchConfiguredLocalOriginWithSsrFGuard({
        url: GATEWAY_URL,
        configuredLocalOriginBaseUrl: GATEWAY_BASE,
        allowPodmanHostGatewayLinkLocal: true,
        policy: { allowedOrigins: [GATEWAY_BASE, otherBase] },
        lookupFn,
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    // First hop reaches the configured origin; the redirected hop is blocked
    // before any second request I/O.
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("grants no exemption to a separate origin under the same opt-in", async () => {
    const otherBase = "http://embeddings-remote.test:11435";
    const fetchImpl = fetchStub();
    await expect(
      fetchConfiguredLocalOriginWithSsrFGuard({
        url: `${otherBase}/api/embed`,
        configuredLocalOriginBaseUrl: GATEWAY_BASE,
        allowPodmanHostGatewayLinkLocal: true,
        policy: { allowedOrigins: [GATEWAY_BASE, otherBase] },
        lookupFn: lookup("169.254.1.2"),
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("does not bypass the public guard (no managedProxyBypass smuggling)", async () => {
    const { fetchWithSsrFGuard } = await import("./fetch-guard.js");
    const fetchImpl = fetchStub();
    await expect(
      fetchWithSsrFGuard({
        url: GATEWAY_URL,
        fetchImpl,
        lookupFn: lookup("169.254.1.2"),
        policy: { allowedOrigins: [GATEWAY_BASE] },
        // @ts-expect-error - managedProxyBypass is intentionally not public
        managedProxyBypass: {
          kind: "configured-local-origin",
          baseUrl: GATEWAY_BASE,
          allowPodmanHostGatewayLinkLocal: true,
        },
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
