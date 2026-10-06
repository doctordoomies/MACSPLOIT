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

/// Result of a reverse (PTR) lookup for a single IP. `names` are de-duplicated,
/// order-preserving PTR hostnames (trailing dots stripped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseResolution {
    pub ip: std::net::IpAddr,
    pub names: Vec<String>,
    pub outcome: DnsOutcome,
}

impl ReverseResolution {
    pub fn empty(ip: std::net::IpAddr, outcome: DnsOutcome) -> Self {
        Self {
            ip,
            names: Vec::new(),
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
    fn resolve(
        &self,
        hosts: &[String],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Vec<HostResolution>;
    /// Bounded reverse (PTR) lookup. The default fails closed (ResolverFailure) so a
    /// resolver that does not implement reverse lookup never silently returns "no PTR".
    fn reverse(
        &self,
        ips: &[std::net::IpAddr],
        _deadline: Instant,
        _cancelled: &AtomicBool,
    ) -> Vec<ReverseResolution> {
        ips.iter()
            .map(|ip| ReverseResolution::empty(*ip, DnsOutcome::ResolverFailure))
            .collect()
    }
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
    ptr: HashMap<std::net::IpAddr, ReverseResolution>,
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

    /// Program PTR (reverse) names for an IP (outcome Resolved, or NoRecords if empty).
    pub fn with_ptr(mut self, ip: std::net::IpAddr, names: &[&str]) -> Self {
        let mut deduped: Vec<String> = Vec::new();
        for name in names {
            let name = name.trim_end_matches('.').to_owned();
            if !name.is_empty() && !deduped.contains(&name) {
                deduped.push(name);
            }
        }
        let outcome = if deduped.is_empty() {
            DnsOutcome::NoRecords
        } else {
            DnsOutcome::Resolved
        };
        self.ptr.insert(
            ip,
            ReverseResolution {
                ip,
                names: deduped,
                outcome,
            },
        );
        self
    }

    pub fn with_ptr_outcome(mut self, ip: std::net::IpAddr, outcome: DnsOutcome) -> Self {
        self.ptr.insert(ip, ReverseResolution::empty(ip, outcome));
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
            for address in addresses
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
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

    fn reverse(
        &self,
        ips: &[std::net::IpAddr],
        _deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Vec<ReverseResolution> {
        ips.iter()
            .map(|ip| {
                if cancelled.load(Ordering::SeqCst) {
                    return ReverseResolution::empty(*ip, DnsOutcome::Cancelled);
                }
                self.ptr
                    .get(ip)
                    .cloned()
                    .unwrap_or_else(|| ReverseResolution::empty(*ip, DnsOutcome::NxDomain))
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

#[derive(Clone, Copy, Default)]
pub struct SystemDnsResolver {
    pub limits: ResolveLimits,
}

impl DnsResolver for SystemDnsResolver {
    fn resolve(
        &self,
        hosts: &[String],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Vec<HostResolution> {
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
            // Respect the system resolver configuration (hickory 0.26:
            // builder_tokio() reads the host's resolv.conf). If it cannot be read
            // we fail closed rather than silently using a hardcoded public resolver.
            let resolver = match hickory_resolver::Resolver::builder_tokio()
                .and_then(|builder| builder.build())
            {
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
                    tasks.push(ready_task(HostResolution::empty(
                        host,
                        DnsOutcome::Cancelled,
                    )));
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
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return HostResolution::empty(&host, DnsOutcome::Timeout);
                    }
                    resolve_one(&resolver, &host, per_query.min(remaining)).await
                }));
            }
            collect_dns_tasks(tasks, deadline, cancelled, |index, outcome| {
                HostResolution::empty(&hosts[index], outcome)
            })
            .await
        })
    }

    fn reverse(
        &self,
        ips: &[std::net::IpAddr],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Vec<ReverseResolution> {
        let limits = self.limits;
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return ips
                .iter()
                .map(|ip| ReverseResolution::empty(*ip, DnsOutcome::ResolverFailure))
                .collect();
        };
        runtime.block_on(async move {
            let resolver = match hickory_resolver::Resolver::builder_tokio().and_then(|b| b.build())
            {
                Ok(resolver) => Arc::new(resolver),
                Err(_) => {
                    return ips
                        .iter()
                        .map(|ip| ReverseResolution::empty(*ip, DnsOutcome::ResolverFailure))
                        .collect()
                }
            };
            let semaphore = Arc::new(tokio::sync::Semaphore::new(limits.max_concurrency.max(1)));
            let mut tasks = Vec::with_capacity(ips.len());
            for ip in ips {
                let ip = *ip;
                if cancelled.load(Ordering::SeqCst) {
                    tasks.push(ready_reverse(ReverseResolution::empty(
                        ip,
                        DnsOutcome::Cancelled,
                    )));
                    continue;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    tasks.push(ready_reverse(ReverseResolution::empty(
                        ip,
                        DnsOutcome::Timeout,
                    )));
                    continue;
                }
                let per_query = limits.per_query_timeout.min(remaining);
                let resolver = resolver.clone();
                let semaphore = semaphore.clone();
                tasks.push(tokio::spawn(async move {
                    let _permit = semaphore.acquire_owned().await.ok();
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return ReverseResolution::empty(ip, DnsOutcome::Timeout);
                    }
                    reverse_one(&resolver, ip, per_query.min(remaining)).await
                }));
            }
            collect_dns_tasks(tasks, deadline, cancelled, |index, outcome| {
                ReverseResolution::empty(ips[index], outcome)
            })
            .await
        })
    }
}

// Polling here keeps the public resolver synchronous while promptly cancelling all
// in-flight/queued futures; no borrowed cancellation flag enters a spawned task.
async fn collect_dns_tasks<T>(
    mut tasks: Vec<tokio::task::JoinHandle<T>>,
    deadline: Instant,
    cancelled: &AtomicBool,
    empty: impl Fn(usize, DnsOutcome) -> T,
) -> Vec<T> {
    let mut results = Vec::with_capacity(tasks.len());
    for index in 0..tasks.len() {
        loop {
            let stopped = if cancelled.load(Ordering::SeqCst) {
                Some(DnsOutcome::Cancelled)
            } else if Instant::now() >= deadline {
                Some(DnsOutcome::Timeout)
            } else {
                None
            };
            if let Some(outcome) = stopped {
                for task in &tasks {
                    task.abort();
                }
                results.extend((index..tasks.len()).map(|i| empty(i, outcome)));
                return results;
            }
            if let Ok(result) =
                tokio::time::timeout(Duration::from_millis(20), &mut tasks[index]).await
            {
                results.push(result.unwrap_or_else(|_| empty(index, DnsOutcome::ResolverFailure)));
                break;
            }
        }
    }
    results
}

fn ready_task(resolution: HostResolution) -> tokio::task::JoinHandle<HostResolution> {
    tokio::spawn(async move { resolution })
}

fn ready_reverse(resolution: ReverseResolution) -> tokio::task::JoinHandle<ReverseResolution> {
    tokio::spawn(async move { resolution })
}

/// Build the reverse-DNS query name (`in-addr.arpa` / `ip6.arpa`) for an IP.
fn reverse_dns_name(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            let mut s = String::with_capacity(74);
            for octet in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.", octet & 0x0f));
                s.push_str(&format!("{:x}.", (octet >> 4) & 0x0f));
            }
            s.push_str("ip6.arpa.");
            s
        }
    }
}

async fn reverse_one(
    resolver: &hickory_resolver::TokioResolver,
    ip: std::net::IpAddr,
    per_query: Duration,
) -> ReverseResolution {
    use hickory_resolver::proto::rr::RData;
    use tokio::time::timeout;
    let query = reverse_dns_name(ip);
    match timeout(per_query, resolver.reverse_lookup(query.as_str())).await {
        Ok(Ok(lookup)) => {
            let mut names = Vec::new();
            for record in lookup.answers() {
                if let RData::PTR(ptr) = &record.data {
                    let text = ptr.0.to_string();
                    let text = text.trim_end_matches('.').to_owned();
                    if !text.is_empty() && !names.contains(&text) {
                        names.push(text);
                    }
                }
            }
            let outcome = if names.is_empty() {
                DnsOutcome::NoRecords
            } else {
                DnsOutcome::Resolved
            };
            ReverseResolution { ip, names, outcome }
        }
        Ok(Err(error)) => ReverseResolution::empty(ip, classify(&error)),
        Err(_) => ReverseResolution::empty(ip, DnsOutcome::Timeout),
    }
}

async fn resolve_one(
    resolver: &hickory_resolver::TokioResolver,
    host: &str,
    per_query: Duration,
) -> HostResolution {
    use std::net::IpAddr;
    use tokio::time::timeout;

    // hickory 0.26 removed the per-family ipv4_lookup/ipv6_lookup helpers; lookup_ip
    // queries both A and AAAA and returns the combined addresses, which we split by
    // family. Host-level partial success (some addresses) is still preserved.
    match timeout(per_query, resolver.lookup_ip(host)).await {
        Ok(Ok(lookup)) => {
            let mut a = Vec::new();
            let mut aaaa = Vec::new();
            for ip in lookup.iter() {
                match ip {
                    IpAddr::V4(v4) if !a.contains(&v4) => a.push(v4),
                    IpAddr::V6(v6) if !aaaa.contains(&v6) => aaaa.push(v6),
                    _ => {}
                }
            }
            let outcome = if a.is_empty() && aaaa.is_empty() {
                DnsOutcome::NoRecords
            } else {
                DnsOutcome::Resolved
            };
            HostResolution {
                host: host.to_owned(),
                a,
                aaaa,
                outcome,
            }
        }
        Ok(Err(error)) => HostResolution::empty(host, classify(&error)),
        Err(_) => HostResolution::empty(host, DnsOutcome::Timeout),
    }
}

fn classify(error: &hickory_resolver::net::NetError) -> DnsOutcome {
    use hickory_resolver::net::{DnsError, NetError};
    use hickory_resolver::proto::op::ResponseCode;
    match error {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            if no_records.response_code == ResponseCode::NXDomain {
                DnsOutcome::NxDomain
            } else {
                DnsOutcome::NoRecords
            }
        }
        NetError::Dns(DnsError::ResponseCode(code)) => {
            if *code == ResponseCode::NXDomain {
                DnsOutcome::NxDomain
            } else {
                DnsOutcome::ResolverFailure
            }
        }
        NetError::Timeout => DnsOutcome::Timeout,
        NetError::Proto(_) => DnsOutcome::TemporaryFailure,
        NetError::Io(_) => DnsOutcome::ResolverFailure,
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
            .with("v6.example.test", &[], &["2001:db8::10".parse().unwrap()]);
        let cancelled = AtomicBool::new(false);
        let results = resolver.resolve(
            &hosts(&["api.example.test", "v6.example.test"]),
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        );
        assert_eq!(
            results[0].a,
            vec!["192.0.2.10".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(results[0].outcome, DnsOutcome::Resolved);
        assert_eq!(
            results[1].aaaa,
            vec!["2001:db8::10".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn static_resolver_unknown_host_is_nxdomain() {
        let resolver = StaticDnsResolver::new();
        let cancelled = AtomicBool::new(false);
        let results = resolver.resolve(
            &hosts(&["missing.example.test"]),
            Instant::now(),
            &cancelled,
        );
        assert_eq!(results[0].outcome, DnsOutcome::NxDomain);
    }

    #[test]
    fn static_resolver_honors_cancellation() {
        let resolver =
            StaticDnsResolver::new().with("x.example.test", &["192.0.2.1".parse().unwrap()], &[]);
        let cancelled = AtomicBool::new(true);
        let results = resolver.resolve(&hosts(&["x.example.test"]), Instant::now(), &cancelled);
        assert_eq!(results[0].outcome, DnsOutcome::Cancelled);
    }

    #[test]
    fn static_reverse_returns_programmed_ptr_names() {
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let resolver = StaticDnsResolver::new().with_ptr(ip, &["localhost", "localhost."]);
        let cancelled = AtomicBool::new(false);
        let results = resolver.reverse(&[ip], Instant::now() + Duration::from_secs(5), &cancelled);
        assert_eq!(results[0].outcome, DnsOutcome::Resolved);
        assert_eq!(results[0].names, vec!["localhost".to_string()]); // trailing dot stripped, deduped
    }

    #[test]
    fn static_reverse_unknown_ip_is_nxdomain_and_honors_cancellation() {
        let ip: std::net::IpAddr = "198.51.100.9".parse().unwrap();
        let resolver = StaticDnsResolver::new();
        let ok = AtomicBool::new(false);
        assert_eq!(
            resolver.reverse(&[ip], Instant::now(), &ok)[0].outcome,
            DnsOutcome::NxDomain
        );
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            resolver.reverse(&[ip], Instant::now(), &cancelled)[0].outcome,
            DnsOutcome::Cancelled
        );
    }

    #[test]
    fn default_reverse_fails_closed() {
        // A resolver that does not override reverse must not silently return "no PTR".
        struct ForwardOnly;
        impl DnsResolver for ForwardOnly {
            fn resolve(
                &self,
                hosts: &[String],
                _d: Instant,
                _c: &AtomicBool,
            ) -> Vec<HostResolution> {
                hosts
                    .iter()
                    .map(|h| HostResolution::empty(h, DnsOutcome::NoRecords))
                    .collect()
            }
        }
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let r = ForwardOnly.reverse(&[ip], Instant::now(), &AtomicBool::new(false));
        assert_eq!(r[0].outcome, DnsOutcome::ResolverFailure);
    }

    #[test]
    fn pending_queries_are_cancelled_or_timed_out_without_network() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for cancel in [false, true] {
            let cancelled = AtomicBool::new(cancel);
            let result = runtime.block_on(async {
                let tasks = vec![tokio::spawn(std::future::pending::<DnsOutcome>())];
                collect_dns_tasks(
                    tasks,
                    Instant::now() + Duration::from_millis(30),
                    &cancelled,
                    |_, outcome| outcome,
                )
                .await
            });
            assert_eq!(
                result,
                vec![if cancel {
                    DnsOutcome::Cancelled
                } else {
                    DnsOutcome::Timeout
                }]
            );
        }
        let ip = "::1".parse().unwrap();
        assert_eq!(
            StaticDnsResolver::new().with_ptr(ip, &[]).reverse(
                &[ip],
                Instant::now(),
                &AtomicBool::new(false)
            )[0]
            .outcome,
            DnsOutcome::NoRecords
        );
    }

    #[test]
    fn reverse_dns_name_matches_arpa_format() {
        assert_eq!(
            reverse_dns_name("127.0.0.1".parse().unwrap()),
            "1.0.0.127.in-addr.arpa."
        );
        assert_eq!(
            reverse_dns_name("::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
        );
    }

    #[test]
    fn parse_env_spec_reads_ipv4_and_ipv6() {
        let resolver =
            StaticDnsResolver::parse("api.example.test=192.0.2.10;v6.example.test=2001:db8::10");
        let cancelled = AtomicBool::new(false);
        let results = resolver.resolve(
            &hosts(&["api.example.test", "v6.example.test"]),
            Instant::now(),
            &cancelled,
        );
        assert_eq!(
            results[0].a,
            vec!["192.0.2.10".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            results[1].aaaa,
            vec!["2001:db8::10".parse::<Ipv6Addr>().unwrap()]
        );
    }
}
