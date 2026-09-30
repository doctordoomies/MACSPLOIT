//! Native DNS resolution for the `native_dns` provider.
//!
//! Resolution sits behind the [`DnsResolver`] trait so the orchestrator and the
//! provider stay synchronous and testable. The production [`SystemDnsResolver`]
//! uses `hickory-resolver` with the host's own resolver configuration; tests use
//! [`StaticDnsResolver`], which performs no network activity. This boundary also
//! lets a future `DnsxProvider` supply the same DNS_RESOLUTION capability.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// The classified outcome of resolving one hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnsOutcome {
    Resolved,
    NoRecords,
    NxDomain,
    Timeout,
    TemporaryFailure,
    InvalidName,
    ResolverFailure,
    Cancelled,
}

/// Resolution result for a single hostname. `a`/`aaaa` are de-duplicated,
/// order-preserving address lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResolution {
    pub host: String,
    pub a: Vec<Ipv4Addr>,
    pub aaaa: Vec<Ipv6Addr>,
    pub outcome: DnsOutcome,
}

impl HostResolution {
    pub fn empty(host: &str, outcome: DnsOutcome) -> Self {
        Self {
            host: host.to_owned(),
            a: Vec::new(),
            aaaa: Vec::new(),
            outcome,
        }
    }
}

/// Bounded resolution parameters shared by resolver implementations.
#[derive(Debug, Clone, Copy)]
pub struct ResolveLimits {
    pub per_query_timeout: Duration,
    pub max_concurrency: usize,
}

impl Default for ResolveLimits {
    fn default() -> Self {
        Self {
            per_query_timeout: Duration::from_secs(5),
            max_concurrency: 16,
        }
    }
}

/// Synchronous resolver boundary. Implementations must honor `deadline` and
/// `cancelled`, bound concurrency, and never panic on resolution failure.
pub trait DnsResolver: Send + Sync {
    fn resolve(&self, hosts: &[String], deadline: Instant, cancelled: &AtomicBool)
        -> Vec<HostResolution>;
    /// True for the built-in native resolver; false for external tools.
    fn built_in(&self) -> bool {
        true
    }
}

/// Choose a resolver from the environment: `MACSPLOIT_DNS_FAKE` selects an offline
/// static resolver (used by the Swift bridge test and manual offline runs);
/// otherwise the system resolver is used.
pub fn resolver_from_env() -> Arc<dyn DnsResolver> {
    if let Some(spec) = std::env::var_os("MACSPLOIT_DNS_FAKE") {
        Arc::new(StaticDnsResolver::parse(&spec.to_string_lossy()))
    } else {
        Arc::new(SystemDnsResolver::default())
    }
}

// ---------------------------------------------------------------------------
// Static (offline) resolver — used by all automated tests and by the optional
// MACSPLOIT_DNS_FAKE environment override. No network activity.
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
pub struct StaticDnsResolver {
    table: HashMap<String, HostResolution>,
}

impl StaticDnsResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Program a host with explicit addresses (outcome is Resolved, or NoRecords
    /// when empty).
    pub fn with(mut self, host: &str, a: &[Ipv4Addr], aaaa: &[Ipv6Addr]) -> Self {
        // Honor the DnsResolver contract: address lists are de-duplicated.
        let mut a4 = Vec::new();
        for ip in a {
            if !a4.contains(ip) {
                a4.push(*ip);
            }
        }
        let mut a6 = Vec::new();
        for ip in aaaa {
            if !a6.contains(ip) {
                a6.push(*ip);
            }
        }
        let outcome = if a4.is_empty() && a6.is_empty() {
            DnsOutcome::NoRecords
        } else {
            DnsOutcome::Resolved
        };
        self.table.insert(
            host.to_owned(),
            HostResolution {
                host: host.to_owned(),
                a: a4,
                aaaa: a6,
                outcome,
            },
        );
        self
    }

    /// Program a host with a specific non-success outcome.
    pub fn with_outcome(mut self, host: &str, outcome: DnsOutcome) -> Self {
        self.table
            .insert(host.to_owned(), HostResolution::empty(host, outcome));
        self
    }

    /// Parse `MACSPLOIT_DNS_FAKE` of the form
    /// `host=ip[,ip];host2=ip` (IPv4 or IPv6). Unknown hosts resolve to NXDOMAIN.
    pub fn parse(spec: &str) -> Self {
        let mut resolver = Self::new();
        for entry in spec.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            let Some((host, addresses)) = entry.split_once('=') else {
                continue;
            };
            let mut a = Vec::new();
            let mut aaaa = Vec::new();
            for address in addresses.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Ok(ip) = address.parse::<Ipv4Addr>() {
                    a.push(ip);
                } else if let Ok(ip) = address.parse::<Ipv6Addr>() {
                    aaaa.push(ip);
                }
            }
            resolver = resolver.with(host.trim(), &a, &aaaa);
        }
        resolver
    }
}

impl DnsResolver for StaticDnsResolver {
    fn resolve(
        &self,
        hosts: &[String],
        _deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Vec<HostResolution> {
        hosts
            .iter()
            .map(|host| {
                if cancelled.load(Ordering::SeqCst) {
                    return HostResolution::empty(host, DnsOutcome::Cancelled);
                }
                self.table
                    .get(host)
                    .cloned()
                    .unwrap_or_else(|| HostResolution::empty(host, DnsOutcome::NxDomain))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// System resolver — production path. Uses hickory-resolver with the host's own
// resolver configuration (never a hardcoded public resolver). Only used for
// manual, explicitly authorized live testing; automated tests use the static
// resolver above.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct SystemDnsResolver {
    pub limits: ResolveLimits,
}

impl Default for SystemDnsResolver {
    fn default() -> Self {
        Self {
            limits: ResolveLimits::default(),
        }
    }
}

impl DnsResolver for SystemDnsResolver {
    fn resolve(
        &self,
        hosts: &[String],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Vec<HostResolution> {
        use hickory_resolver::TokioAsyncResolver;

        let limits = self.limits;
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                return hosts
                    .iter()
                    .map(|h| HostResolution::empty(h, DnsOutcome::ResolverFailure))
                    .collect()
            }
        };

        runtime.block_on(async move {
            // Respect the system resolver configuration. If it cannot be read we
            // fail closed rather than silently using a hardcoded public resolver.
            let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
                Ok(resolver) => resolver,
                Err(_) => {
                    return hosts
                        .iter()
                        .map(|h| HostResolution::empty(h, DnsOutcome::ResolverFailure))
                        .collect()
                }
            };
            let resolver = Arc::new(resolver);
            let semaphore = Arc::new(tokio::sync::Semaphore::new(limits.max_concurrency.max(1)));
            let mut tasks = Vec::with_capacity(hosts.len());
            for host in hosts {
                if cancelled.load(Ordering::SeqCst) {
                    tasks.push(ready_task(HostResolution::empty(host, DnsOutcome::Cancelled)));
                    continue;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    tasks.push(ready_task(HostResolution::empty(host, DnsOutcome::Timeout)));
                    continue;
                }
                let per_query = limits.per_query_timeout.min(remaining);
                let host = host.clone();
                let resolver = resolver.clone();
                let semaphore = semaphore.clone();
                tasks.push(tokio::spawn(async move {
                    let _permit = semaphore.acquire_owned().await.ok();
                    resolve_one(&resolver, &host, per_query).await
                }));
            }
            let mut results = Vec::with_capacity(tasks.len());
            for task in tasks {
                match task.await {
                    Ok(resolution) => results.push(resolution),
                    Err(_) => {} // a panicked/aborted task is simply dropped
                }
            }
            results
        })
    }
}

fn ready_task(resolution: HostResolution) -> tokio::task::JoinHandle<HostResolution> {
    tokio::spawn(async move { resolution })
}

async fn resolve_one(
    resolver: &hickory_resolver::TokioAsyncResolver,
    host: &str,
    per_query: Duration,
) -> HostResolution {
    use tokio::time::timeout;

    let mut a = Vec::new();
    let mut aaaa = Vec::new();
    let mut errors = Vec::new();

    match timeout(per_query, resolver.ipv4_lookup(host)).await {
        Ok(Ok(lookup)) => {
            for record in lookup.iter() {
                let ip = Ipv4Addr::from(record.0);
                if !a.contains(&ip) {
                    a.push(ip);
                }
            }
        }
        Ok(Err(error)) => errors.push(classify(error.kind())),
        Err(_) => errors.push(DnsOutcome::Timeout),
    }
    match timeout(per_query, resolver.ipv6_lookup(host)).await {
        Ok(Ok(lookup)) => {
            for record in lookup.iter() {
                let ip = Ipv6Addr::from(record.0);
                if !aaaa.contains(&ip) {
                    aaaa.push(ip);
                }
            }
        }
        Ok(Err(error)) => errors.push(classify(error.kind())),
        Err(_) => errors.push(DnsOutcome::Timeout),
    }

    // Any successful record means the host resolved (partial success is success).
    let outcome = if !a.is_empty() || !aaaa.is_empty() {
        DnsOutcome::Resolved
    } else {
        // No records: prefer the most specific classified error.
        errors
            .iter()
            .copied()
            .find(|o| *o == DnsOutcome::NxDomain)
            .or_else(|| errors.first().copied())
            .unwrap_or(DnsOutcome::NoRecords)
    };
    HostResolution {
        host: host.to_owned(),
        a,
        aaaa,
        outcome,
    }
}

fn classify(kind: &hickory_resolver::error::ResolveErrorKind) -> DnsOutcome {
    use hickory_resolver::error::ResolveErrorKind;
    use hickory_resolver::proto::op::ResponseCode;
    match kind {
        ResolveErrorKind::NoRecordsFound { response_code, .. } => {
            if *response_code == ResponseCode::NXDomain {
                DnsOutcome::NxDomain
            } else {
                DnsOutcome::NoRecords
            }
        }
        ResolveErrorKind::Timeout => DnsOutcome::Timeout,
        ResolveErrorKind::Proto(_) => DnsOutcome::TemporaryFailure,
        _ => DnsOutcome::ResolverFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn static_resolver_returns_programmed_records() {
        let resolver = StaticDnsResolver::new()
            .with("api.example.test", &["192.0.2.10".parse().unwrap()], &[])
            .with(
                "v6.example.test",
                &[],
                &["2001:db8::10".parse().unwrap()],
            );
        let cancelled = AtomicBool::new(false);
        let results = resolver.resolve(
            &hosts(&["api.example.test", "v6.example.test"]),
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        );
        assert_eq!(results[0].a, vec!["192.0.2.10".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(results[0].outcome, DnsOutcome::Resolved);
        assert_eq!(results[1].aaaa, vec!["2001:db8::10".parse::<Ipv6Addr>().unwrap()]);
    }

    #[test]
    fn static_resolver_unknown_host_is_nxdomain() {
        let resolver = StaticDnsResolver::new();
        let cancelled = AtomicBool::new(false);
        let results = resolver.resolve(&hosts(&["missing.example.test"]), Instant::now(), &cancelled);
        assert_eq!(results[0].outcome, DnsOutcome::NxDomain);
    }

    #[test]
    fn static_resolver_honors_cancellation() {
        let resolver = StaticDnsResolver::new().with("x.example.test", &["192.0.2.1".parse().unwrap()], &[]);
        let cancelled = AtomicBool::new(true);
        let results = resolver.resolve(&hosts(&["x.example.test"]), Instant::now(), &cancelled);
        assert_eq!(results[0].outcome, DnsOutcome::Cancelled);
    }

    #[test]
    fn parse_env_spec_reads_ipv4_and_ipv6() {
        let resolver = StaticDnsResolver::parse("api.example.test=192.0.2.10;v6.example.test=2001:db8::10");
        let cancelled = AtomicBool::new(false);
        let results = resolver.resolve(&hosts(&["api.example.test", "v6.example.test"]), Instant::now(), &cancelled);
        assert_eq!(results[0].a, vec!["192.0.2.10".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(results[1].aaaa, vec!["2001:db8::10".parse::<Ipv6Addr>().unwrap()]);
    }
}
