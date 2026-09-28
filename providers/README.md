# Provider boundary

Phase 0 implements its internal provider trait and SyntheticDiscoveryProvider in
`core/src/providers/`. No external scanner adapters, installers, or public plugin
ABI exist. This directory remains the reserved boundary for later independent
adapters; see [provider design](../docs/providers.md).
