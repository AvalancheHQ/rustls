//! Benchmarks of whole-connection operations: full handshakes, resumed
//! handshakes, and bulk data transfer.
//!
//! These complement the fine-grained benchmarks living in the provider crates
//! (see `rustls-ring/benches` and `rustls-aws-lc-rs/benches`) and are run for
//! every pull request by CodSpeed, which reports the CPU cost of each scenario.
//!
//! Run them locally with:
//!
//! ```text
//! cargo bench -p rustls-test --bench connection
//! ```

use core::hint::black_box;
use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache};
use rustls::{
    ClientConfig, ClientConnection, Connection, HandshakeKind, ServerConfig, ServerConnection,
    SupportedCipherSuite, VecInput,
};
use rustls_test::{
    KeyType, do_handshake, make_client_config, make_pair_for_arc_configs, make_server_config,
    provider_with_one_suite, transfer,
};

/// Amount of application data sent by the server in the transfer benchmarks.
///
/// Large enough that record encryption dominates the measurement, small enough
/// that the benchmark stays fast under CPU simulation.
const TRANSFER_SIZE: usize = 256 * 1024;

/// Size of each `write()` call made by the transfer benchmarks.
///
/// This matches rustls' maximum plaintext fragment size, so each chunk becomes
/// a single TLS record.
const TRANSFER_CHUNK_SIZE: usize = 16 * 1024;

/// A crypto provider, and the subsets of it, that we benchmark.
struct Provider {
    name: &'static str,
    tls12: CryptoProvider,
    tls13: CryptoProvider,
    /// TLS1.3 cipher suites of interest, as `(short name, suite)`.
    tls13_suites: &'static [(&'static str, SupportedCipherSuite)],
}

static RING_TLS13_SUITES: &[(&str, SupportedCipherSuite)] = &[
    (
        "aes128gcm",
        SupportedCipherSuite::Tls13(rustls_ring::cipher_suite::TLS13_AES_128_GCM_SHA256),
    ),
    (
        "chacha20",
        SupportedCipherSuite::Tls13(rustls_ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
    ),
];

static AWS_LC_RS_TLS13_SUITES: &[(&str, SupportedCipherSuite)] = &[
    (
        "aes128gcm",
        SupportedCipherSuite::Tls13(rustls_aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256),
    ),
    (
        "chacha20",
        SupportedCipherSuite::Tls13(rustls_aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
    ),
];

fn providers() -> Vec<Provider> {
    vec![
        Provider {
            name: "ring",
            tls12: rustls_ring::DEFAULT_TLS12_PROVIDER,
            tls13: rustls_ring::DEFAULT_TLS13_PROVIDER,
            tls13_suites: RING_TLS13_SUITES,
        },
        Provider {
            name: "aws-lc-rs",
            tls12: rustls_aws_lc_rs::DEFAULT_TLS12_PROVIDER,
            tls13: rustls_aws_lc_rs::DEFAULT_TLS13_PROVIDER,
            tls13_suites: AWS_LC_RS_TLS13_SUITES,
        },
    ]
}

fn key_type_name(kt: KeyType) -> &'static str {
    match kt {
        KeyType::Rsa2048 => "rsa2048",
        KeyType::Rsa3072 => "rsa3072",
        KeyType::Rsa4096 => "rsa4096",
        KeyType::EcdsaP256 => "ecdsap256",
        KeyType::EcdsaP384 => "ecdsap384",
        KeyType::EcdsaP521 => "ecdsap521",
        KeyType::Ed25519 => "ed25519",
    }
}

/// What kind of session resumption the configurations should allow.
#[derive(Clone, Copy, PartialEq)]
enum Resume {
    No,
    SessionId,
    Tickets,
}

fn client_config(kt: KeyType, provider: &CryptoProvider, resume: Resume) -> Arc<ClientConfig> {
    let mut config = make_client_config(kt, provider);
    config.resumption = match resume {
        Resume::No => Resumption::disabled(),
        _ => Resumption::in_memory_sessions(128),
    };
    Arc::new(config)
}

fn server_config(kt: KeyType, provider: &CryptoProvider, resume: Resume) -> Arc<ServerConfig> {
    let mut config = make_server_config(kt, provider);
    match resume {
        Resume::No => config.session_storage = Arc::new(NoServerSessionStorage {}),
        Resume::SessionId => config.session_storage = ServerSessionMemoryCache::new(128),
        Resume::Tickets => {
            config.ticketer = Some(
                provider
                    .ticketer_factory
                    .ticketer()
                    .unwrap(),
            );
        }
    }
    Arc::new(config)
}

/// Run one handshake to completion, returning the client's view of its kind.
///
/// The final flight (which carries the TLS1.3 session tickets) is exchanged as
/// part of `do_handshake`, so a subsequent connection using the same configs
/// can resume.
fn handshake(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> Option<HandshakeKind> {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    let (mut client, mut server) =
        make_pair_for_arc_configs(client_config, server_config, &mut client_output);

    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let kind = client.handshake_kind();
    black_box((client, server));
    kind
}

fn bench_full_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake_full");
    group.throughput(Throughput::Elements(1));

    for provider in providers() {
        for (version, provider_for_version, key_types) in [
            (
                "tls13",
                &provider.tls13,
                &[KeyType::Rsa2048, KeyType::EcdsaP256, KeyType::Ed25519][..],
            ),
            (
                "tls12",
                &provider.tls12,
                &[KeyType::Rsa2048, KeyType::EcdsaP256][..],
            ),
        ] {
            for kt in key_types {
                let client_config = client_config(*kt, provider_for_version, Resume::No);
                let server_config = server_config(*kt, provider_for_version, Resume::No);

                assert_eq!(
                    handshake(&client_config, &server_config),
                    Some(HandshakeKind::Full)
                );

                group.bench_function(
                    format!("{}/{version}/{}", provider.name, key_type_name(*kt)),
                    |b| b.iter(|| handshake(&client_config, &server_config)),
                );
            }
        }
    }
}

fn bench_resumed_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake_resumed");
    group.throughput(Throughput::Elements(1));

    for provider in providers() {
        for (version, provider_for_version) in
            [("tls13", &provider.tls13), ("tls12", &provider.tls12)]
        {
            for (resume_name, resume) in [
                ("session_id", Resume::SessionId),
                ("tickets", Resume::Tickets),
            ] {
                let kt = KeyType::EcdsaP256;
                let client_config = client_config(kt, provider_for_version, resume);
                let server_config = server_config(kt, provider_for_version, resume);

                // prime the session caches, then check resumption really happens
                assert_eq!(
                    handshake(&client_config, &server_config),
                    Some(HandshakeKind::Full)
                );
                assert_eq!(
                    handshake(&client_config, &server_config),
                    Some(HandshakeKind::Resumed)
                );

                group.bench_function(format!("{}/{version}/{resume_name}", provider.name), |b| {
                    b.iter(|| handshake(&client_config, &server_config))
                });
            }
        }
    }
}

/// A handshaked connection pair, plus the buffers needed to drive it.
struct Session {
    client: ClientConnection,
    client_input: VecInput,
    client_output: Vec<u8>,
    server: ServerConnection,
    server_output: Vec<u8>,
    received: Vec<u8>,
}

impl Session {
    fn new(client_config: &Arc<ClientConfig>, server_config: &Arc<ServerConfig>) -> Self {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();

        let (mut client, mut server) =
            make_pair_for_arc_configs(client_config, server_config, &mut client_output);

        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        Self {
            client,
            client_input,
            client_output,
            server,
            server_output,
            received: Vec::new(),
        }
    }

    /// Encrypt `plaintext` server-side, then transfer and decrypt it client-side.
    ///
    /// The data is sent one record at a time and consumed as it arrives, so
    /// this uses a bounded amount of memory whatever `plaintext.len()` is.
    fn send_and_receive(&mut self, plaintext: &[u8]) {
        let mut received = 0;

        for chunk in plaintext.chunks(TRANSFER_CHUNK_SIZE) {
            self.server
                .write(chunk.into(), &mut self.server_output)
                .unwrap();
            transfer(&mut self.server_output, &mut self.client_input);
            self.client
                .read_tls(&mut self.client_input, &mut self.client_output)
                .handle_all(&mut self.received)
                .unwrap();
            received += self.received.len();
            self.received.clear();
        }

        assert_eq!(received, plaintext.len());
    }
}

fn bench_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer");
    group.throughput(Throughput::Bytes(TRANSFER_SIZE as u64));

    let plaintext = vec![0u8; TRANSFER_SIZE];
    let kt = KeyType::EcdsaP256;

    for provider in providers() {
        for (suite_name, suite) in provider.tls13_suites {
            let single = provider_with_one_suite(&provider.tls13, *suite);
            let mut session = Session::new(
                &client_config(kt, &single, Resume::No),
                &server_config(kt, &single, Resume::No),
            );

            group.bench_function(format!("{}/tls13/{suite_name}", provider.name), |b| {
                b.iter(|| session.send_and_receive(&plaintext))
            });
        }

        let mut session = Session::new(
            &client_config(kt, &provider.tls12, Resume::No),
            &server_config(kt, &provider.tls12, Resume::No),
        );
        group.bench_function(format!("{}/tls12/default", provider.name), |b| {
            b.iter(|| session.send_and_receive(&plaintext))
        });
    }
}

criterion_group!(
    benches,
    bench_full_handshake,
    bench_resumed_handshake,
    bench_transfer
);
criterion_main!(benches);
