// Host-granted exemption for the rootless-Podman container host gateway
// (host.containers.internal -> 169.254.1.2, link-local 169.254.0.0/16).
// Keyed by policy identity instead of a policy field so the Plugin SDK
// SsrFPolicy contract (including the infra-runtime star export) cannot
// express it. Only host code holding this module can mark a policy.
// Distinct from PR #149589's nonzero 0.0.0.0/8 exemption: that range and this
// link-local gateway range are disjoint, and each keeps its own WeakSet so the
// two opt-ins merge additively instead of overwriting each other.
//
// This module intentionally imports nothing from ssrf.ts: ssrf.ts imports the
// helpers back, so even a type-only import would close an import cycle.
// The helpers are generic over the policy object shape instead.
const podmanGatewayLinkLocalExemptPolicies = new WeakSet<object>();

/**
 * Copy a policy whose trusted hostname may resolve into the Podman host
 * gateway link-local address (169.254.0.0/16, excluding cloud metadata).
 * Callers must already scope this copy to the exact configured origin hop
 * (see resolveConfiguredLocalOriginLinkLocalHopPolicy); the copy itself
 * carries no origin information.
 */
export function withTrustedHostPodmanGatewayLinkLocalExemption<T extends object>(policy: T): T {
  const exempt = { ...policy };
  podmanGatewayLinkLocalExemptPolicies.add(exempt);
  return exempt;
}

export function hasTrustedHostPodmanGatewayLinkLocalExemption(policy: object | undefined): boolean {
  return policy !== undefined && podmanGatewayLinkLocalExemptPolicies.has(policy);
}
