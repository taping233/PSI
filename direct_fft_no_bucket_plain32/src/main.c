#include <flint/flint.h>
#include <flint/nmod_poly.h>
#include <arpa/inet.h>
#include <errno.h>
#include <omp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LONG long long int
#define DATA_BIT 32
#define MAX_DATASET_EXP 20
#define MAX_CLIENTS 20
#define FIXED_PROTOCOL_SEED 0x7d5a9e3779b97f4aULL
#define SYMMETRIC_KEY_BYTES 32
#define SYMMETRIC_NONCE_BYTES 12
#define SYMMETRIC_TAG_BYTES 16
#define NETWORK_CHUNK_BYTES 65536
#define NETWORK_HEADER_WORDS 8
#define NETWORK_SHUTDOWN_LEN UINT64_MAX
#define PKE_RSA_BITS 2048
#define SPDZ_MAC_BYTES 32

int FFTpolmul64s(LONG *a, LONG *b, LONG *c, LONG da, LONG db, LONG p);
int roots64s(LONG *lambda, LONG n, LONG *R, LONG p);
int roots64s_seeded(LONG *lambda, LONG n, LONG *R, LONG p,
                    unsigned long long initial_seed);
int ntl_poly_gcd_u64(const uint64_t *lhs, size_t lhs_len,
                     const uint64_t *rhs, size_t rhs_len,
                     uint64_t prime, uint64_t *out, size_t *out_len);

/* FFT-domain Beaver multiplication: primitives from fftutil8.c / int128g.c */
typedef struct {
    unsigned long long s;
    unsigned long long v;
    unsigned long long d0;
    unsigned long long d1;
} recint;
recint recip1(unsigned long long p);
unsigned long long mulrec64(unsigned long long a, unsigned long long b, recint v);
LONG getomega64s(LONG p, LONG n);
void FFT64s1(LONG n, LONG *a, LONG *W, LONG p, recint P);
void FFT64s2(LONG n, LONG *a, LONG *W, LONG p, recint P);
void MakeW64(LONG n, LONG w, LONG *W, LONG p);
void MakeWinv64(LONG n, LONG *W, LONG p);
LONG modinv64s(LONG c, LONG p);


typedef __uint128_t u128;

typedef struct {
    uint64_t *coeffs;
    size_t len;
} Poly;

typedef struct {
    uint64_t *values;
    size_t len;
} Dataset;

typedef struct {
    size_t id;
    Dataset dataset;
    Poly set_poly;
} ClientRole;

typedef struct {
    Poly aggregate_share;
} CloudRole;

typedef struct {
    Dataset dataset;
} QueryRole;

typedef struct {
    uint64_t seed;
} DealerRole;

typedef struct {
    Poly cloud;
    Poly user;
} SharedPoly;

typedef struct {
    Poly cloud;
    Poly evaluator;
} RieRoundShares;

typedef enum {
    ROLE_CLIENT,
    ROLE_CLOUD,
    ROLE_QUERY,
    ROLE_DEALER
} RoleKind;

typedef enum {
    PHASE_INPUT_SHARING,
    PHASE_BEAVER_MULTIPLY,
    PHASE_RESULT_DELIVERY,
    PHASE_RECONSTRUCTION
} ProtocolPhase;

typedef enum {
    CHANNEL_SECRET_SHARE,
    CHANNEL_BEAVER_OPEN,
    CHANNEL_SECURE_CHANNEL,
    CHANNEL_COMMON_KEY_ENCRYPTED
} ChannelKind;

typedef struct {
    RoleKind sender;
    RoleKind receiver;
    size_t round;
    uint64_t field_elements;
    ProtocolPhase phase;
    ChannelKind channel;
} ProtocolMessage;

typedef enum {
    TRANSPORT_RUNTIME_ESTIMATED,
    TRANSPORT_RUNTIME_TCP_TLS
} TransportRuntimeMode;

typedef struct {
    double set_poly_time;
    double share_time;
    double multiply_time;
    double fft_prepare_time;
    double fft_forward_time;
    double beaver_pointwise_time;
    double fft_inverse_time;
    double convolution_extract_time;
    double cloud_aggregate_time;
    double reconstruct_time;
    double common_key_encrypt_time;
    double common_key_decrypt_time;
    double pke_key_exchange_time;
    double tls_handshake_time;
    double network_time;
    double spdz_mac_time;
    double gcd_time;
    double tg_time;
    double query_filter_time;
    uint64_t triples;
    uint64_t messages;
    uint64_t field_elements;
    uint64_t beaver_checks;
    uint64_t secret_share_field_elements;
    uint64_t beaver_open_field_elements;
    uint64_t secure_channel_field_elements;
    uint64_t common_key_encrypted_field_elements;
    uint64_t common_key_encrypted_bytes;
    uint64_t common_key_encryptions;
    uint64_t pke_recipients;
    uint64_t pke_public_key_bytes;
    uint64_t pke_ciphertext_bytes;
    uint64_t pke_decryptions;
    uint64_t tls_connections;
    uint64_t network_messages;
    uint64_t network_payload_bytes;
    uint64_t network_wire_bytes;
    uint64_t network_acks;
    uint64_t spdz_mac_checks;
    uint64_t spdz_mac_failures;
    uint64_t spdz_mac_bytes;
    uint64_t reconstructed_polynomials;
} Metrics;

typedef struct {
    uint64_t state;
} DeterministicRng;

typedef struct {
    uint64_t *a_cloud;
    uint64_t *a_user;
    uint64_t *b_cloud;
    uint64_t *b_user;
    uint64_t *c_cloud;
    uint64_t *c_user;
    size_t n; /* FFT frequency bins = triple count */
    int consumed;
} TripleCache;

typedef struct {
    TripleCache *caches;
    size_t participant_count;
    size_t round;
} RieOfflineCache;

typedef struct {
    double triple_generate_time;
    uint64_t triples;
    uint64_t cached_field_elements;
    uint64_t cache_bytes;
} OfflineMetrics;

typedef enum {
    TRANSPORT_LATENCY_BANDWIDTH,
    TRANSPORT_ZHIHU_LINEAR
} TransportModel;

typedef enum {
    TRANSPORT_PROFILE_CUSTOM,
    TRANSPORT_PROFILE_LAN,
    TRANSPORT_PROFILE_WAN
} TransportProfile;

typedef struct {
    double bandwidth_mbps;
    double latency_ms;
    uint64_t message_overhead_bytes;
    TransportModel model;
    TransportProfile profile;
    double linear_intercept;
    double linear_slope_per_mb;
    double linear_valid_min_mb;
} TransportConfig;

typedef struct {
    uint64_t secret_share_bytes;
    uint64_t beaver_open_bytes;
    uint64_t secure_channel_bytes;
    uint64_t common_key_encrypted_payload_bytes;
    uint64_t payload_bytes;
    uint64_t overhead_bytes;
    uint64_t total_bytes;
    uint64_t messages;
    double communication_mb;
    double latency_time;
    double bandwidth_time;
    double transport_time;
} TransportMetrics;

typedef enum {
    MODE_PROTOCOL3,
    MODE_PROTOCOL3_METHOD2
} RunMode;

typedef enum {
    EXTRACT_ROOTS_INTERSECT,
    EXTRACT_GCD
} ExtractionMode;

typedef enum {
    ROOT_FLINT,
    ROOT_FLINT_DISTINCT,
    ROOT_TG
} RootMethod;

typedef enum {
    GCD_FLINT,
    GCD_NTL
} GcdBackend;

typedef enum {
    SCENARIO_HALF,
    SCENARIO_EMPTY,
    SCENARIO_FULL,
    SCENARIO_SINGLE,
    SCENARIO_DUPLICATES,
    SCENARIO_BOUNDS
} Scenario;

static const uint64_t FIELD_PRIME = 180143985094819841ULL;

typedef struct {
    int listen_fd;
    int server_fd;
    int client_fd;
    int port;
    SSL_CTX *server_ctx;
    SSL_CTX *client_ctx;
    SSL *server_ssl;
    SSL *client_ssl;
    X509 *server_cert;
    EVP_PKEY *server_key;
    pthread_t server_thread;
    int failed;
    int started;
} TlsRpcTransport;

static TransportRuntimeMode g_transport_runtime =
    TRANSPORT_RUNTIME_ESTIMATED;
static TlsRpcTransport g_tls_transport;
static TlsRpcTransport *g_active_transport = NULL;
static unsigned char g_common_key[SYMMETRIC_KEY_BYTES];
static int g_common_key_ready = 0;

static void die(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

static uint64_t mod_add(uint64_t a, uint64_t b)
{
    return (uint64_t)(((u128)a + b) % FIELD_PRIME);
}

static uint64_t mod_sub(uint64_t a, uint64_t b)
{
    return a >= b ? a - b : FIELD_PRIME - (b - a);
}

static uint64_t mod_mul(uint64_t a, uint64_t b)
{
    return (uint64_t)(((u128)a * b) % FIELD_PRIME);
}

static uint64_t mod_pow(uint64_t base, uint64_t exponent)
{
    uint64_t result = 1;
    while (exponent) {
        if (exponent & 1) {
            result = mod_mul(result, base);
        }
        base = mod_mul(base, base);
        exponent >>= 1;
    }
    return result;
}

static uint64_t mod_inv(uint64_t value)
{
    if (value == 0) {
        die("mod_inv: inverse of zero");
    }
    return mod_pow(value, FIELD_PRIME - 2);
}

static uint64_t splitmix64_next(DeterministicRng *rng)
{
    uint64_t z = (rng->state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t rng_field(DeterministicRng *rng)
{
    return splitmix64_next(rng) % FIELD_PRIME;
}

static uint64_t derive_seed(uint64_t base, size_t round, size_t party,
                            uint64_t domain)
{
    DeterministicRng rng = {
        base ^ ((uint64_t)round << 48) ^ ((uint64_t)party << 24) ^ domain
    };
    return splitmix64_next(&rng);
}

static Poly poly_alloc(size_t len);

static void fill_deterministic_bytes(unsigned char *out, size_t len,
                                     uint64_t seed)
{
    DeterministicRng rng = {seed};
    size_t offset = 0;
    while (offset < len) {
        uint64_t word = splitmix64_next(&rng);
        size_t chunk = len - offset < sizeof(word) ?
            len - offset : sizeof(word);
        memcpy(out + offset, &word, chunk);
        offset += chunk;
    }
}

static void die_openssl(const char *message)
{
    ERR_print_errors_fp(stderr);
    die(message);
}

static uint64_t host_to_be64(uint64_t value)
{
    return ((value & 0x00000000000000ffULL) << 56) |
           ((value & 0x000000000000ff00ULL) << 40) |
           ((value & 0x0000000000ff0000ULL) << 24) |
           ((value & 0x00000000ff000000ULL) << 8) |
           ((value & 0x000000ff00000000ULL) >> 8) |
           ((value & 0x0000ff0000000000ULL) >> 24) |
           ((value & 0x00ff000000000000ULL) >> 40) |
           ((value & 0xff00000000000000ULL) >> 56);
}

static uint64_t be64_to_host(uint64_t value)
{
    return host_to_be64(value);
}

static int ssl_write_all(SSL *ssl, const unsigned char *buf, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > NETWORK_CHUNK_BYTES) {
            chunk = NETWORK_CHUNK_BYTES;
        }
        int written = SSL_write(ssl, buf + offset, (int)chunk);
        if (written <= 0) {
            return 0;
        }
        offset += (size_t)written;
    }
    return 1;
}

static int ssl_read_all(SSL *ssl, unsigned char *buf, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > NETWORK_CHUNK_BYTES) {
            chunk = NETWORK_CHUNK_BYTES;
        }
        int received = SSL_read(ssl, buf + offset, (int)chunk);
        if (received <= 0) {
            return 0;
        }
        offset += (size_t)received;
    }
    return 1;
}

static void build_rpc_header(const ProtocolMessage *message,
                             uint64_t payload_bytes,
                             uint64_t message_id,
                             uint64_t header[NETWORK_HEADER_WORDS])
{
    header[0] = host_to_be64(payload_bytes);
    header[1] = host_to_be64(message_id);
    header[2] = host_to_be64((uint64_t)message->sender);
    header[3] = host_to_be64((uint64_t)message->receiver);
    header[4] = host_to_be64((uint64_t)message->round);
    header[5] = host_to_be64((uint64_t)message->phase);
    header[6] = host_to_be64((uint64_t)message->channel);
    header[7] = host_to_be64(message->field_elements);
}

static uint64_t rpc_payload_seed(const uint64_t header[NETWORK_HEADER_WORDS])
{
    uint64_t seed = FIXED_PROTOCOL_SEED ^ 0x5250435041594c44ULL;
    for (size_t i = 0; i < NETWORK_HEADER_WORDS; ++i) {
        DeterministicRng rng = {seed ^ be64_to_host(header[i]) ^ i};
        seed = splitmix64_next(&rng);
    }
    return seed;
}

static void hmac_init_frame(HMAC_CTX **ctx,
                            const uint64_t header[NETWORK_HEADER_WORDS])
{
    unsigned char mac_key[SYMMETRIC_KEY_BYTES];
    fill_deterministic_bytes(
        mac_key, sizeof(mac_key),
        FIXED_PROTOCOL_SEED ^ 0x5350445a4d41434bULL);
    *ctx = HMAC_CTX_new();
    if (!*ctx ||
        HMAC_Init_ex(*ctx, mac_key, (int)sizeof(mac_key),
                     EVP_sha256(), NULL) != 1 ||
        HMAC_Update(*ctx, (const unsigned char *)header,
                    sizeof(uint64_t) * NETWORK_HEADER_WORDS) != 1) {
        die_openssl("hmac_init_frame failed");
    }
}

static void hmac_final_frame(HMAC_CTX *ctx,
                             unsigned char tag[SPDZ_MAC_BYTES])
{
    unsigned int tag_len = 0;
    if (HMAC_Final(ctx, tag, &tag_len) != 1 ||
        tag_len != SPDZ_MAC_BYTES) {
        die_openssl("hmac_final_frame failed");
    }
    HMAC_CTX_free(ctx);
}

static EVP_PKEY *generate_rsa_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    if (!ctx ||
        EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, PKE_RSA_BITS) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        die_openssl("generate_rsa_key failed");
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static X509 *generate_self_signed_cert(EVP_PKEY *key)
{
    X509 *cert = X509_new();
    if (!cert) {
        die_openssl("generate_self_signed_cert: allocation failed");
    }
    if (X509_set_version(cert, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
        X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL ||
        X509_gmtime_adj(X509_get_notAfter(cert), 24 * 60 * 60) == NULL ||
        X509_set_pubkey(cert, key) != 1) {
        die_openssl("generate_self_signed_cert: base fields failed");
    }
    X509_NAME *name = X509_get_subject_name(cert);
    if (!name ||
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            (const unsigned char *)"localhost", -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert, name) != 1 ||
        X509_sign(cert, key, EVP_sha256()) <= 0) {
        die_openssl("generate_self_signed_cert: sign failed");
    }
    return cert;
}

static void *tls_rpc_server_thread(void *arg)
{
    TlsRpcTransport *transport = (TlsRpcTransport *)arg;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    transport->server_fd =
        accept(transport->listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (transport->server_fd < 0) {
        transport->failed = 1;
        return NULL;
    }

    transport->server_ssl = SSL_new(transport->server_ctx);
    if (!transport->server_ssl ||
        SSL_set_fd(transport->server_ssl, transport->server_fd) != 1 ||
        SSL_accept(transport->server_ssl) != 1) {
        transport->failed = 1;
        return NULL;
    }

    for (;;) {
        uint64_t header[NETWORK_HEADER_WORDS];
        if (!ssl_read_all(transport->server_ssl,
                          (unsigned char *)header, sizeof(header))) {
            break;
        }
        uint64_t payload_bytes = be64_to_host(header[0]);
        if (payload_bytes == NETWORK_SHUTDOWN_LEN) {
            break;
        }

        HMAC_CTX *hctx = NULL;
        hmac_init_frame(&hctx, header);
        uint64_t remaining = payload_bytes;
        unsigned char chunk[NETWORK_CHUNK_BYTES];
        while (remaining) {
            size_t take = remaining > NETWORK_CHUNK_BYTES ?
                NETWORK_CHUNK_BYTES : (size_t)remaining;
            if (!ssl_read_all(transport->server_ssl, chunk, take) ||
                HMAC_Update(hctx, chunk, take) != 1) {
                transport->failed = 1;
                HMAC_CTX_free(hctx);
                return NULL;
            }
            remaining -= take;
        }
        unsigned char expected[SPDZ_MAC_BYTES];
        unsigned char received[SPDZ_MAC_BYTES];
        hmac_final_frame(hctx, expected);
        if (!ssl_read_all(transport->server_ssl, received, sizeof(received))) {
            transport->failed = 1;
            return NULL;
        }
        unsigned char ack =
            CRYPTO_memcmp(expected, received, SPDZ_MAC_BYTES) == 0 ?
            0xac : 0x15;
        if (!ssl_write_all(transport->server_ssl, &ack, 1)) {
            transport->failed = 1;
            return NULL;
        }
    }

    SSL_shutdown(transport->server_ssl);
    return NULL;
}

static void tls_rpc_transport_start(TlsRpcTransport *transport,
                                    Metrics *metrics)
{
    memset(transport, 0, sizeof(*transport));
    transport->listen_fd = -1;
    transport->server_fd = -1;
    transport->client_fd = -1;
    OPENSSL_init_ssl(0, NULL);

    transport->server_key = generate_rsa_key();
    transport->server_cert = generate_self_signed_cert(transport->server_key);
    transport->server_ctx = SSL_CTX_new(TLS_server_method());
    transport->client_ctx = SSL_CTX_new(TLS_client_method());
    if (!transport->server_ctx || !transport->client_ctx) {
        die_openssl("tls_rpc_transport_start: ctx allocation failed");
    }
    SSL_CTX_set_min_proto_version(transport->server_ctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(transport->client_ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate(transport->server_ctx,
                                transport->server_cert) != 1 ||
        SSL_CTX_use_PrivateKey(transport->server_ctx,
                               transport->server_key) != 1 ||
        SSL_CTX_check_private_key(transport->server_ctx) != 1) {
        die_openssl("tls_rpc_transport_start: server cert failed");
    }
    X509_STORE *store = SSL_CTX_get_cert_store(transport->client_ctx);
    if (!store || X509_STORE_add_cert(store, transport->server_cert) != 1) {
        die_openssl("tls_rpc_transport_start: trust store failed");
    }
    SSL_CTX_set_verify(transport->client_ctx, SSL_VERIFY_PEER, NULL);

    transport->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (transport->listen_fd < 0) {
        die("tls_rpc_transport_start: socket failed");
    }
    int one = 1;
    setsockopt(transport->listen_fd, SOL_SOCKET, SO_REUSEADDR,
               &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(transport->listen_fd, (struct sockaddr *)&addr,
             sizeof(addr)) < 0 ||
        listen(transport->listen_fd, 1) < 0) {
        die("tls_rpc_transport_start: bind/listen failed");
    }
    socklen_t addr_len = sizeof(addr);
    if (getsockname(transport->listen_fd, (struct sockaddr *)&addr,
                    &addr_len) < 0) {
        die("tls_rpc_transport_start: getsockname failed");
    }
    transport->port = ntohs(addr.sin_port);
    if (pthread_create(&transport->server_thread, NULL,
                       tls_rpc_server_thread, transport) != 0) {
        die("tls_rpc_transport_start: pthread_create failed");
    }

    transport->client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (transport->client_fd < 0) {
        die("tls_rpc_transport_start: client socket failed");
    }
    double start = omp_get_wtime();
    if (connect(transport->client_fd, (struct sockaddr *)&addr,
                sizeof(addr)) < 0) {
        die("tls_rpc_transport_start: connect failed");
    }
    transport->client_ssl = SSL_new(transport->client_ctx);
    if (!transport->client_ssl ||
        SSL_set_fd(transport->client_ssl, transport->client_fd) != 1 ||
        SSL_connect(transport->client_ssl) != 1 ||
        SSL_get_verify_result(transport->client_ssl) != X509_V_OK) {
        die_openssl("tls_rpc_transport_start: TLS handshake failed");
    }
    metrics->tls_handshake_time += omp_get_wtime() - start;
    metrics->tls_connections++;
    transport->started = 1;
    g_active_transport = transport;
}

static void tls_rpc_transport_stop(TlsRpcTransport *transport)
{
    if (!transport || !transport->started) {
        return;
    }
    uint64_t header[NETWORK_HEADER_WORDS] = {0};
    header[0] = host_to_be64(NETWORK_SHUTDOWN_LEN);
    (void)ssl_write_all(transport->client_ssl,
                        (const unsigned char *)header, sizeof(header));
    SSL_shutdown(transport->client_ssl);
    pthread_join(transport->server_thread, NULL);
    int failed = transport->failed;

    if (transport->client_ssl) SSL_free(transport->client_ssl);
    if (transport->server_ssl) SSL_free(transport->server_ssl);
    if (transport->client_fd >= 0) close(transport->client_fd);
    if (transport->server_fd >= 0) close(transport->server_fd);
    if (transport->listen_fd >= 0) close(transport->listen_fd);
    if (transport->client_ctx) SSL_CTX_free(transport->client_ctx);
    if (transport->server_ctx) SSL_CTX_free(transport->server_ctx);
    if (transport->server_cert) X509_free(transport->server_cert);
    if (transport->server_key) EVP_PKEY_free(transport->server_key);
    memset(transport, 0, sizeof(*transport));
    transport->listen_fd = -1;
    transport->server_fd = -1;
    transport->client_fd = -1;
    g_active_transport = NULL;
    if (failed) {
        die("tls_rpc_transport_stop: server thread failed");
    }
}

static void tls_rpc_send_message(Metrics *metrics,
                                 const ProtocolMessage *message)
{
    if (g_transport_runtime != TRANSPORT_RUNTIME_TCP_TLS ||
        !g_active_transport) {
        return;
    }
    if (message->field_elements > UINT64_MAX / sizeof(uint64_t)) {
        die("tls_rpc_send_message: payload size overflow");
    }
    uint64_t payload_bytes =
        message->field_elements * (uint64_t)sizeof(uint64_t);
    uint64_t message_id = metrics->network_messages + 1;
    uint64_t header[NETWORK_HEADER_WORDS];
    build_rpc_header(message, payload_bytes, message_id, header);

    HMAC_CTX *hctx = NULL;
    double mac_start = omp_get_wtime();
    hmac_init_frame(&hctx, header);
    metrics->spdz_mac_time += omp_get_wtime() - mac_start;

    double start = omp_get_wtime();
    if (!ssl_write_all(g_active_transport->client_ssl,
                       (const unsigned char *)header, sizeof(header))) {
        die("tls_rpc_send_message: write header failed");
    }

    DeterministicRng rng = {rpc_payload_seed(header)};
    uint64_t remaining = payload_bytes;
    unsigned char chunk[NETWORK_CHUNK_BYTES];
    while (remaining) {
        size_t take = remaining > NETWORK_CHUNK_BYTES ?
            NETWORK_CHUNK_BYTES : (size_t)remaining;
        size_t offset = 0;
        while (offset < take) {
            uint64_t word = splitmix64_next(&rng);
            size_t part = take - offset < sizeof(word) ?
                take - offset : sizeof(word);
            memcpy(chunk + offset, &word, part);
            offset += part;
        }
        mac_start = omp_get_wtime();
        if (HMAC_Update(hctx, chunk, take) != 1) {
            die_openssl("tls_rpc_send_message: HMAC update failed");
        }
        metrics->spdz_mac_time += omp_get_wtime() - mac_start;
        if (!ssl_write_all(g_active_transport->client_ssl, chunk, take)) {
            HMAC_CTX_free(hctx);
            die("tls_rpc_send_message: write payload failed");
        }
        remaining -= take;
    }

    unsigned char tag[SPDZ_MAC_BYTES];
    mac_start = omp_get_wtime();
    hmac_final_frame(hctx, tag);
    metrics->spdz_mac_time += omp_get_wtime() - mac_start;
    if (!ssl_write_all(g_active_transport->client_ssl, tag, sizeof(tag))) {
        die("tls_rpc_send_message: write MAC failed");
    }
    unsigned char ack = 0;
    if (!ssl_read_all(g_active_transport->client_ssl, &ack, 1)) {
        die("tls_rpc_send_message: read ACK failed");
    }
    metrics->network_time += omp_get_wtime() - start;
    metrics->network_messages++;
    metrics->network_payload_bytes += payload_bytes;
    metrics->network_wire_bytes +=
        (uint64_t)sizeof(header) + payload_bytes + SPDZ_MAC_BYTES + 1;
    metrics->network_acks++;
    metrics->spdz_mac_checks++;
    metrics->spdz_mac_bytes += SPDZ_MAC_BYTES;
    if (ack != 0xac) {
        metrics->spdz_mac_failures++;
        die("tls_rpc_send_message: frame MAC rejected");
    }
}

static void derive_common_key_material(size_t round, size_t party,
                                       unsigned char key[SYMMETRIC_KEY_BYTES],
                                       unsigned char nonce[SYMMETRIC_NONCE_BYTES])
{
    uint64_t nonce_seed = derive_seed(
        FIXED_PROTOCOL_SEED, round, party, 0x434f4d4d4f4e4e31ULL);
    if (!g_common_key_ready) {
        die("derive_common_key_material: PKE common key not established");
    }
    memcpy(key, g_common_key, SYMMETRIC_KEY_BYTES);
    fill_deterministic_bytes(nonce, SYMMETRIC_NONCE_BYTES, nonce_seed);
}

static void perform_pke_common_key_exchange(size_t recipients,
                                            Metrics *metrics)
{
    double start = omp_get_wtime();
    fill_deterministic_bytes(
        g_common_key, sizeof(g_common_key),
        FIXED_PROTOCOL_SEED ^ 0x504b45434f4d4d4bULL);
    g_common_key_ready = 0;

    for (size_t i = 0; i < recipients; ++i) {
        EVP_PKEY *recipient_key = generate_rsa_key();
        int pub_len = i2d_PUBKEY(recipient_key, NULL);
        if (pub_len <= 0) {
            die_openssl("perform_pke_common_key_exchange: public key encode failed");
        }
        metrics->pke_public_key_bytes += (uint64_t)pub_len;

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(recipient_key, NULL);
        if (!enc_ctx ||
            EVP_PKEY_encrypt_init(enc_ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(
                enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, EVP_sha256()) <= 0) {
            die_openssl("perform_pke_common_key_exchange: encrypt init failed");
        }
        size_t ciphertext_len = 0;
        if (EVP_PKEY_encrypt(
                enc_ctx, NULL, &ciphertext_len,
                g_common_key, sizeof(g_common_key)) <= 0) {
            die_openssl("perform_pke_common_key_exchange: encrypt size failed");
        }
        unsigned char *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
            die("perform_pke_common_key_exchange: allocation failed");
        }
        if (EVP_PKEY_encrypt(
                enc_ctx, ciphertext, &ciphertext_len,
                g_common_key, sizeof(g_common_key)) <= 0) {
            die_openssl("perform_pke_common_key_exchange: encrypt failed");
        }
        EVP_PKEY_CTX_free(enc_ctx);
        metrics->pke_ciphertext_bytes += (uint64_t)ciphertext_len;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(recipient_key, NULL);
        if (!dec_ctx ||
            EVP_PKEY_decrypt_init(dec_ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(
                dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, EVP_sha256()) <= 0) {
            die_openssl("perform_pke_common_key_exchange: decrypt init failed");
        }
        unsigned char recovered[512];
        size_t plaintext_len = sizeof(recovered);
        if (EVP_PKEY_decrypt(
                dec_ctx, recovered, &plaintext_len,
                ciphertext, ciphertext_len) <= 0 ||
            plaintext_len != SYMMETRIC_KEY_BYTES ||
            CRYPTO_memcmp(recovered, g_common_key,
                          SYMMETRIC_KEY_BYTES) != 0) {
            die_openssl("perform_pke_common_key_exchange: decrypt failed");
        }
        EVP_PKEY_CTX_free(dec_ctx);
        EVP_PKEY_free(recipient_key);
        free(ciphertext);
        metrics->pke_recipients++;
        metrics->pke_decryptions++;
    }

    g_common_key_ready = 1;
    metrics->pke_key_exchange_time += omp_get_wtime() - start;
}

static Poly common_key_encrypt_decrypt_poly(const Poly *plain, size_t round,
                                            size_t party, Metrics *metrics)
{
    size_t plaintext_len = plain->len * sizeof(uint64_t);
    if (plaintext_len > (size_t)INT_MAX) {
        die("common_key_encrypt_decrypt_poly: payload too large");
    }

    unsigned char key[SYMMETRIC_KEY_BYTES];
    unsigned char nonce[SYMMETRIC_NONCE_BYTES];
    unsigned char tag[SYMMETRIC_TAG_BYTES];
    derive_common_key_material(round, party, key, nonce);

    unsigned char *ciphertext = malloc(plaintext_len ? plaintext_len : 1);
    unsigned char *decrypted = malloc(plaintext_len ? plaintext_len : 1);
    if (!ciphertext || !decrypted) {
        die("common_key_encrypt_decrypt_poly: allocation failed");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        die("common_key_encrypt_decrypt_poly: encrypt ctx failed");
    }
    int out_len = 0;
    int total_len = 0;
    double start = omp_get_wtime();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            SYMMETRIC_NONCE_BYTES, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &out_len,
                          (const unsigned char *)plain->coeffs,
                          (int)plaintext_len) != 1) {
        die("common_key_encrypt_decrypt_poly: encrypt failed");
    }
    total_len = out_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &out_len) != 1) {
        die("common_key_encrypt_decrypt_poly: encrypt final failed");
    }
    total_len += out_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            SYMMETRIC_TAG_BYTES, tag) != 1) {
        die("common_key_encrypt_decrypt_poly: get tag failed");
    }
    metrics->common_key_encrypt_time += omp_get_wtime() - start;
    EVP_CIPHER_CTX_free(ctx);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        die("common_key_encrypt_decrypt_poly: decrypt ctx failed");
    }
    int plain_len = 0;
    int recovered_len = 0;
    start = omp_get_wtime();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            SYMMETRIC_NONCE_BYTES, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &plain_len,
                          ciphertext, total_len) != 1) {
        die("common_key_encrypt_decrypt_poly: decrypt failed");
    }
    recovered_len = plain_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            SYMMETRIC_TAG_BYTES, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, decrypted + recovered_len, &plain_len) != 1) {
        die("common_key_encrypt_decrypt_poly: decrypt auth failed");
    }
    recovered_len += plain_len;
    metrics->common_key_decrypt_time += omp_get_wtime() - start;
    EVP_CIPHER_CTX_free(ctx);

    if ((size_t)recovered_len != plaintext_len) {
        die("common_key_encrypt_decrypt_poly: decrypted length mismatch");
    }

    Poly out = poly_alloc(plain->len);
    memcpy(out.coeffs, decrypted, plaintext_len);
    metrics->common_key_encrypted_bytes +=
        (uint64_t)total_len + SYMMETRIC_NONCE_BYTES + SYMMETRIC_TAG_BYTES;
    metrics->common_key_encryptions++;

    free(decrypted);
    free(ciphertext);
    return out;
}

static Poly poly_alloc(size_t len)
{
    Poly poly = {calloc(len ? len : 1, sizeof(uint64_t)), len ? len : 1};
    if (!poly.coeffs) {
        die("poly_alloc: allocation failed");
    }
    return poly;
}

static void poly_free(Poly *poly)
{
    if (!poly) {
        return;
    }
    free(poly->coeffs);
    poly->coeffs = NULL;
    poly->len = 0;
}

static void poly_trim(Poly *poly)
{
    while (poly->len > 1 && poly->coeffs[poly->len - 1] == 0) {
        poly->len--;
    }
}

static Poly poly_copy(const Poly *source)
{
    Poly copy = poly_alloc(source->len);
    memcpy(copy.coeffs, source->coeffs,
           source->len * sizeof(uint64_t));
    return copy;
}

static size_t poly_degree(const Poly *poly)
{
    return poly->len ? poly->len - 1 : 0;
}

static void poly_add_inplace(Poly *dst, const Poly *src)
{
    if (src->len > dst->len) {
        uint64_t *grown = realloc(dst->coeffs, src->len * sizeof(uint64_t));
        if (!grown) {
            die("poly_add_inplace: allocation failed");
        }
        memset(grown + dst->len, 0,
               (src->len - dst->len) * sizeof(uint64_t));
        dst->coeffs = grown;
        dst->len = src->len;
    }
    for (size_t i = 0; i < src->len; ++i) {
        dst->coeffs[i] = mod_add(dst->coeffs[i], src->coeffs[i]);
    }
    poly_trim(dst);
}

static int poly_divide_linear_inplace(Poly *poly, uint64_t root)
{
    size_t degree = poly_degree(poly);
    if (degree == 0) {
        return 0;
    }
    uint64_t *quotient = calloc(degree, sizeof(uint64_t));
    if (!quotient) {
        die("poly_divide_linear_inplace: allocation failed");
    }

    quotient[degree - 1] = poly->coeffs[degree];
    for (size_t k = degree - 1; k > 0; --k) {
        quotient[k - 1] =
            mod_add(poly->coeffs[k], mod_mul(root, quotient[k]));
    }
    uint64_t remainder =
        mod_add(poly->coeffs[0], mod_mul(root, quotient[0]));
    if (remainder != 0) {
        free(quotient);
        return 0;
    }

    memcpy(poly->coeffs, quotient, degree * sizeof(uint64_t));
    poly->len = degree;
    poly_trim(poly);
    free(quotient);
    return 1;
}

static int compare_u64(const void *lhs, const void *rhs)
{
    uint64_t a = *(const uint64_t *)lhs;
    uint64_t b = *(const uint64_t *)rhs;
    return (a > b) - (a < b);
}

static void values_sort_unique(Dataset *dataset, int enforce_32_bit)
{
    if (dataset->len == 0) {
        return;
    }
    qsort(dataset->values, dataset->len, sizeof(uint64_t), compare_u64);
    size_t out = 0;
    for (size_t i = 0; i < dataset->len; ++i) {
        if (enforce_32_bit && dataset->values[i] > UINT32_MAX) {
            die("dataset element exceeds 32-bit range");
        }
        if (out == 0 || dataset->values[i] != dataset->values[out - 1]) {
            dataset->values[out++] = dataset->values[i];
        }
    }
    dataset->len = out;
}

static void dataset_sort_unique(Dataset *dataset)
{
    values_sort_unique(dataset, 1);
}

static int dataset_contains(const Dataset *dataset, uint64_t value)
{
    size_t lo = 0;
    size_t hi = dataset->len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (dataset->values[mid] < value) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < dataset->len && dataset->values[lo] == value;
}

static void dataset_free(Dataset *dataset)
{
    free(dataset->values);
    dataset->values = NULL;
    dataset->len = 0;
}

static Dataset dataset_copy(const Dataset *source)
{
    Dataset copy = {malloc(source->len * sizeof(uint64_t)), source->len};
    if (source->len && !copy.values) {
        die("dataset_copy: allocation failed");
    }
    if (source->len) {
        memcpy(copy.values, source->values, source->len * sizeof(uint64_t));
    }
    return copy;
}

static Dataset make_dataset(size_t n, size_t party, int is_query,
                            Scenario scenario, int has_common_override,
                            size_t common_override)
{
    Dataset dataset = {malloc(n * sizeof(uint64_t)), n};
    if (!dataset.values) {
        die("make_dataset: allocation failed");
    }

    size_t common = n / 2;
    if (scenario == SCENARIO_EMPTY) {
        common = 0;
    } else if (scenario == SCENARIO_FULL) {
        common = n;
    } else if (scenario == SCENARIO_SINGLE) {
        common = 1;
    }
    if (has_common_override) {
        common = common_override;
    }
    if (common > n) {
        die("make_dataset: common count exceeds dataset size");
    }

    uint64_t unique_base = is_query
        ? (1ULL << 30)
        : (1ULL << 24) + (uint64_t)party * (1ULL << 20);

    for (size_t i = 0; i < n; ++i) {
        if (i < common) {
            if (scenario == SCENARIO_BOUNDS && i == 0) {
                dataset.values[i] = 0;
            } else if (scenario == SCENARIO_BOUNDS && i == 1) {
                dataset.values[i] = UINT32_MAX;
            } else {
                dataset.values[i] = (1ULL << 20) + i;
            }
        } else {
            dataset.values[i] = unique_base + i;
        }
    }

    if (scenario == SCENARIO_DUPLICATES && n >= 8) {
        for (size_t i = 3 * n / 4; i < n; ++i) {
            dataset.values[i] = dataset.values[i - n / 4];
        }
    }

    dataset_sort_unique(&dataset);
    return dataset;
}

static Dataset expected_intersection(const ClientRole *clients,
                                     size_t client_count,
                                     const QueryRole *query)
{
    Dataset expected = dataset_copy(&query->dataset);
    size_t out = 0;
    for (size_t i = 0; i < expected.len; ++i) {
        int present = 1;
        for (size_t c = 0; c < client_count; ++c) {
            if (!dataset_contains(&clients[c].dataset, expected.values[i])) {
                present = 0;
                break;
            }
        }
        if (present) {
            expected.values[out++] = expected.values[i];
        }
    }
    expected.len = out;
    return expected;
}

static void make_linear64(uint64_t *poly, uint64_t root)
{
    poly[0] = root == 0 ? 0 : FIELD_PRIME - root;
    poly[1] = 1;
}

static void product_tree_prime(const uint64_t *roots, size_t start, size_t end,
                               uint64_t *out)
{
    if (start == end) {
        make_linear64(out, roots[start]);
        return;
    }

    size_t mid = start + (end - start) / 2;
    size_t left_degree = mid - start + 1;
    size_t right_degree = end - mid;
    LONG *left = calloc(left_degree + 1, sizeof(LONG));
    LONG *right = calloc(right_degree + 1, sizeof(LONG));
    LONG *product = calloc(left_degree + right_degree + 1, sizeof(LONG));
    if (!left || !right || !product) {
        die("product_tree_prime: allocation failed");
    }

    product_tree_prime(roots, start, mid, (uint64_t *)left);
    product_tree_prime(roots, mid + 1, end, (uint64_t *)right);
    FFTpolmul64s(left, right, product, (LONG)left_degree,
                 (LONG)right_degree, (LONG)FIELD_PRIME);
    for (size_t i = 0; i <= left_degree + right_degree; ++i) {
        out[i] = (uint64_t)product[i];
    }

    free(product);
    free(right);
    free(left);
}

static Poly build_set_polynomial(const Dataset *dataset)
{
    if (dataset->len == 0) {
        Poly one = poly_alloc(1);
        one.coeffs[0] = 1;
        return one;
    }
    Poly poly = poly_alloc(dataset->len + 1);
    product_tree_prime(dataset->values, 0, dataset->len - 1, poly.coeffs);
    return poly;
}

static void nmod_poly_from_poly(nmod_poly_t out, const Poly *source)
{
    nmod_poly_fit_length(out, (slong)source->len);
    for (size_t i = 0; i < source->len; ++i) {
        out->coeffs[i] = (mp_limb_t)source->coeffs[i];
    }
    _nmod_poly_set_length(out, (slong)source->len);
    _nmod_poly_normalise(out);
}

static Poly polynomial_gcd(const Poly *lhs, const Poly *rhs,
                           GcdBackend backend)
{
    if (backend == GCD_NTL) {
        size_t capacity = lhs->len < rhs->len ? lhs->len : rhs->len;
        Poly result = poly_alloc(capacity ? capacity : 1);
        size_t out_len = 0;
        if (!ntl_poly_gcd_u64(lhs->coeffs, lhs->len, rhs->coeffs, rhs->len,
                              FIELD_PRIME, result.coeffs, &out_len)) {
            die("polynomial_gcd: NTL backend failed");
        }
        result.len = out_len ? out_len : 1;
        poly_trim(&result);
        return result;
    }

    nmod_poly_t a;
    nmod_poly_t b;
    nmod_poly_t gcd;

    nmod_poly_init2(a, (mp_limb_t)FIELD_PRIME, (slong)lhs->len);
    nmod_poly_init2(b, (mp_limb_t)FIELD_PRIME, (slong)rhs->len);
    nmod_poly_init(gcd, (mp_limb_t)FIELD_PRIME);

    nmod_poly_from_poly(a, lhs);
    nmod_poly_from_poly(b, rhs);

    nmod_poly_gcd(gcd, a, b);
    slong degree = nmod_poly_degree(gcd);
    if (degree >= 0 && nmod_poly_get_coeff_ui(gcd, degree) != 1) {
        nmod_poly_make_monic(gcd, gcd);
    }

    Poly result = poly_alloc(degree >= 0 ? (size_t)degree + 1 : 1);
    if (degree >= 0) {
        memcpy(result.coeffs, gcd->coeffs,
               ((size_t)degree + 1) * sizeof(uint64_t));
    }
    poly_trim(&result);

    nmod_poly_clear(gcd);
    nmod_poly_clear(b);
    nmod_poly_clear(a);
    return result;
}

static Dataset tg_roots(const Poly *poly, double *elapsed)
{
    Dataset roots = {NULL, 0};
    size_t original_degree = poly_degree(poly);
    if (original_degree == 0) {
        if (elapsed) {
            *elapsed = 0.0;
        }
        return roots;
    }

    roots.values = malloc(original_degree * sizeof(uint64_t));
    LONG *lambda = calloc(original_degree + 1, sizeof(LONG));
    LONG *raw = calloc(original_degree, sizeof(LONG));
    LONG *candidate = calloc(original_degree, sizeof(LONG));
    if (!roots.values || !lambda || !raw || !candidate) {
        die("tg_roots: allocation failed");
    }

    double start = omp_get_wtime();
    Poly residual = poly_copy(poly);
    while (poly_degree(&residual) > 0) {
        size_t degree = poly_degree(&residual);
        if (degree == 1) {
            uint64_t root = mod_mul(
                mod_sub(0, residual.coeffs[0]),
                mod_inv(residual.coeffs[1]));
            roots.values[roots.len++] = root;
            if (!poly_divide_linear_inplace(&residual, root)) {
                die("tg_roots: linear residual did not divide");
            }
            continue;
        }

        memset(lambda, 0, (original_degree + 1) * sizeof(LONG));
        for (size_t i = 0; i <= degree; ++i) {
            if (residual.coeffs[i] > INT64_MAX) {
                die("tg_roots: coefficient does not fit signed 64-bit");
            }
            lambda[i] = (LONG)residual.coeffs[i];
        }

        int count = 0;
        for (unsigned long long attempt = 1; attempt <= 8; ++attempt) {
            int this_count = roots64s_seeded(
                lambda, (LONG)degree, candidate,
                (LONG)FIELD_PRIME, attempt);
            if (this_count > count) {
                count = this_count;
                memcpy(raw, candidate,
                       (size_t)this_count * sizeof(LONG));
            }
            if ((size_t)count == degree) {
                break;
            }
        }
        if (count == 0) {
            break;
        }
        if ((size_t)count == degree) {
            for (int i = 0; i < count; ++i) {
                roots.values[roots.len++] = (uint64_t)raw[i];
            }
            break;
        }

        size_t progress = 0;
        for (int i = 0; i < count; ++i) {
            uint64_t root = (uint64_t)raw[i];
            if (poly_divide_linear_inplace(&residual, root)) {
                roots.values[roots.len++] = root;
                progress++;
            }
        }
        if (progress == 0) {
            break;
        }
    }
    if (elapsed) {
        *elapsed = omp_get_wtime() - start;
    }
    values_sort_unique(&roots, 0);

    poly_free(&residual);
    free(candidate);
    free(raw);
    free(lambda);
    return roots;
}

static Dataset flint_roots(const Poly *poly, double *elapsed)
{
    Dataset roots = {NULL, 0};
    size_t original_degree = poly_degree(poly);
    if (original_degree == 0) {
        if (elapsed) {
            *elapsed = 0.0;
        }
        return roots;
    }

    roots.values = malloc(original_degree * sizeof(uint64_t));
    if (!roots.values) {
        die("flint_roots: allocation failed");
    }

    double start = omp_get_wtime();
    nmod_poly_t f;
    nmod_poly_factor_t fac;
    nmod_poly_init2(f, (mp_limb_t)FIELD_PRIME, (slong)poly->len);
    nmod_poly_factor_init(fac);
    nmod_poly_from_poly(f, poly);
    nmod_poly_roots(fac, f, 0);

    for (slong i = 0; i < fac->num; ++i) {
        nmod_poly_struct *factor = fac->p + i;
        if (nmod_poly_degree(factor) != 1) {
            continue;
        }
        uint64_t constant =
            (uint64_t)nmod_poly_get_coeff_ui(factor, 0);
        uint64_t leading =
            (uint64_t)nmod_poly_get_coeff_ui(factor, 1);
        uint64_t root =
            mod_mul(mod_sub(0, constant), mod_inv(leading));
        roots.values[roots.len++] = root;
    }

    nmod_poly_factor_clear(fac);
    nmod_poly_clear(f);
    if (elapsed) {
        *elapsed = omp_get_wtime() - start;
    }
    values_sort_unique(&roots, 0);
    return roots;
}

static Dataset flint_distinct_roots(const Poly *poly, double *elapsed)
{
    Dataset roots = {NULL, 0};
    size_t original_degree = poly_degree(poly);
    if (original_degree == 0) {
        if (elapsed) {
            *elapsed = 0.0;
        }
        return roots;
    }

    roots.values = malloc(original_degree * sizeof(uint64_t));
    if (!roots.values) {
        die("flint_distinct_roots: allocation failed");
    }

    double start = omp_get_wtime();
    nmod_poly_t f;
    nmod_poly_init2(f, (mp_limb_t)FIELD_PRIME, (slong)poly->len);
    nmod_poly_from_poly(f, poly);

    int success = nmod_poly_find_distinct_nonzero_roots(
        (mp_limb_t *)roots.values, f);
    if (!success) {
        die("flint_distinct_roots: root finder failed");
    }
    roots.len = original_degree;

    nmod_poly_clear(f);
    if (elapsed) {
        *elapsed = omp_get_wtime() - start;
    }
    values_sort_unique(&roots, 0);
    return roots;
}

static Dataset extract_roots(const Poly *poly, RootMethod method,
                             double *elapsed)
{
    if (method == ROOT_TG) {
        return tg_roots(poly, elapsed);
    }
    if (method == ROOT_FLINT_DISTINCT) {
        return flint_distinct_roots(poly, elapsed);
    }
    return flint_roots(poly, elapsed);
}

static Dataset query_evaluate_rie(const QueryRole *query, const Poly *rie)
{
    Dataset result = {
        malloc((query->dataset.len ? query->dataset.len : 1)
               * sizeof(uint64_t)), 0
    };
    if (!result.values) {
        die("query_evaluate_rie: allocation failed");
    }

    if (query->dataset.len == 0) {
        return result;
    }

    nmod_poly_t f;
    nmod_poly_init2(f, (mp_limb_t)FIELD_PRIME, (slong)rie->len);
    nmod_poly_from_poly(f, rie);

    mp_limb_t *evaluations =
        malloc(query->dataset.len * sizeof(mp_limb_t));
    if (!evaluations) {
        die("query_evaluate_rie: allocation failed");
    }

    nmod_poly_evaluate_nmod_vec_fast(
        evaluations, f, (mp_srcptr)query->dataset.values,
        (slong)query->dataset.len);

    for (size_t i = 0; i < query->dataset.len; ++i) {
        if (evaluations[i] == 0) {
            result.values[result.len++] = query->dataset.values[i];
        }
    }

    free(evaluations);
    nmod_poly_clear(f);
    return result;
}

static int dataset_equal(const Dataset *lhs, const Dataset *rhs)
{
    return lhs->len == rhs->len &&
           (lhs->len == 0 ||
            memcmp(lhs->values, rhs->values,
                   lhs->len * sizeof(uint64_t)) == 0);
}

static void record_message(Metrics *metrics, ProtocolMessage message)
{
    metrics->messages++;
    metrics->field_elements += message.field_elements;
    switch (message.channel) {
    case CHANNEL_SECRET_SHARE:
        metrics->secret_share_field_elements += message.field_elements;
        break;
    case CHANNEL_BEAVER_OPEN:
        metrics->beaver_open_field_elements += message.field_elements;
        break;
    case CHANNEL_SECURE_CHANNEL:
        metrics->secure_channel_field_elements += message.field_elements;
        break;
    case CHANNEL_COMMON_KEY_ENCRYPTED:
        metrics->common_key_encrypted_field_elements +=
            message.field_elements;
        break;
    }
    tls_rpc_send_message(metrics, &message);
}

static void share_poly_padded(const Poly *plain, size_t len, uint64_t seed,
                              SharedPoly *shared)
{
    if (plain->len > len) {
        die("share_poly_padded: source exceeds public degree bound");
    }
    shared->cloud = poly_alloc(len);
    shared->user = poly_alloc(len);
    DeterministicRng rng = {seed};
    for (size_t i = 0; i < len; ++i) {
        uint64_t value = i < plain->len ? plain->coeffs[i] : 0;
        shared->cloud.coeffs[i] = rng_field(&rng);
        shared->user.coeffs[i] =
            mod_sub(value, shared->cloud.coeffs[i]);
    }
}

static void shared_poly_free(SharedPoly *shared)
{
    poly_free(&shared->user);
    poly_free(&shared->cloud);
}

static Poly random_polynomial(size_t degree, uint64_t seed)
{
    Poly poly = poly_alloc(degree + 1);
    DeterministicRng rng = {seed};
    for (size_t i = 0; i <= degree; ++i) {
        poly.coeffs[i] = rng_field(&rng);
    }
    if (poly.coeffs[degree] == 0) {
        poly.coeffs[degree] = 1;
    }
    return poly;
}

static TripleCache triple_cache_alloc(size_t n)
{
    size_t count = n;
    TripleCache cache = {
        malloc(count * sizeof(uint64_t)),
        malloc(count * sizeof(uint64_t)),
        malloc(count * sizeof(uint64_t)),
        malloc(count * sizeof(uint64_t)),
        malloc(count * sizeof(uint64_t)),
        malloc(count * sizeof(uint64_t)),
        n,
        0
    };
    if (!cache.a_cloud || !cache.a_user || !cache.b_cloud ||
        !cache.b_user || !cache.c_cloud || !cache.c_user) {
        die("triple_cache_alloc: allocation failed");
    }
    return cache;
}

static void triple_cache_free(TripleCache *cache)
{
    free(cache->c_user);
    free(cache->c_cloud);
    free(cache->b_user);
    free(cache->b_cloud);
    free(cache->a_user);
    free(cache->a_cloud);
    memset(cache, 0, sizeof(*cache));
}

static void dealer_precompute_cache(DealerRole *dealer, TripleCache *cache,
                                    uint64_t seed)
{
    DeterministicRng rng = {seed ^ dealer->seed};
    size_t count = cache->n;
    for (size_t index = 0; index < count; ++index) {
        uint64_t a = rng_field(&rng);
        uint64_t b = rng_field(&rng);
        uint64_t c = mod_mul(a, b);
        cache->a_cloud[index] = rng_field(&rng);
        cache->a_user[index] = mod_sub(a, cache->a_cloud[index]);
        cache->b_cloud[index] = rng_field(&rng);
        cache->b_user[index] = mod_sub(b, cache->b_cloud[index]);
        cache->c_cloud[index] = rng_field(&rng);
        cache->c_user[index] = mod_sub(c, cache->c_cloud[index]);
    }
}

static RieOfflineCache rie_offline_precompute(
    DealerRole *dealer, size_t participant_count, size_t poly_len,
    size_t round, OfflineMetrics *metrics)
{
    RieOfflineCache offline = {
        calloc(participant_count, sizeof(TripleCache)),
        participant_count,
        round
    };
    if (!offline.caches) {
        die("rie_offline_precompute: allocation failed");
    }

    for (size_t party = 0; party < participant_count; ++party) {
        double start = omp_get_wtime();
        size_t fft_n = 1; while (fft_n < 2 * poly_len - 1) fft_n <<= 1;
        offline.caches[party] = triple_cache_alloc(fft_n);
        dealer_precompute_cache(
            dealer, &offline.caches[party],
            derive_seed(FIXED_PROTOCOL_SEED, round, party, 0x545249504c45ULL));
        metrics->triple_generate_time += omp_get_wtime() - start;
        uint64_t triples = (uint64_t)fft_n;
        metrics->triples += triples;
        metrics->cached_field_elements += 6 * triples;
        metrics->cache_bytes += 6 * triples * sizeof(uint64_t);
    }
    return offline;
}

static void rie_offline_free(RieOfflineCache *offline)
{
    if (!offline || !offline->caches) {
        return;
    }
    for (size_t i = 0; i < offline->participant_count; ++i) {
        triple_cache_free(&offline->caches[i]);
    }
    free(offline->caches);
    memset(offline, 0, sizeof(*offline));
}

static SharedPoly beaver_poly_multiply(const SharedPoly *x,
                                       const SharedPoly *y,
                                       TripleCache *cache,
                                       size_t round,
                                       Metrics *metrics)
{
    if (cache->consumed) {
        die("beaver_poly_multiply: triple cache reused");
    }
    double total_start = omp_get_wtime();
    double phase_start = total_start;
    size_t len = x->cloud.len;

    /* Determine FFT size: next power of 2 >= 2*len-1 */
    size_t fft_n = 1;
    while (fft_n < 2 * len - 1) fft_n <<= 1;

    if (cache->n != fft_n) {
        die("beaver_poly_multiply: cache size does not match FFT size");
    }

    /* Allocate and pad to FFT size */
    LONG *fx_cloud = calloc(fft_n, sizeof(LONG));
    LONG *fx_user  = calloc(fft_n, sizeof(LONG));
    LONG *fy_cloud = calloc(fft_n, sizeof(LONG));
    LONG *fy_user  = calloc(fft_n, sizeof(LONG));
    if (!fx_cloud || !fx_user || !fy_cloud || !fy_user)
        die("beaver_poly_multiply: FFT alloc failed");
    for (size_t i = 0; i < len; ++i) {
        fx_cloud[i] = (LONG)x->cloud.coeffs[i];
        fx_user[i]  = (LONG)x->user.coeffs[i];
        fy_cloud[i] = (LONG)y->cloud.coeffs[i];
        fy_user[i]  = (LONG)y->user.coeffs[i];
    }

    /* FFT precomputation */
    LONG p = (LONG)FIELD_PRIME;
    LONG w = getomega64s(p, (LONG)fft_n);
    if (w == 0) die("beaver_poly_multiply: no omega for FFT size");
    recint P = recip1((unsigned long long)p);
    LONG *W = calloc(fft_n, sizeof(LONG));
    MakeW64((LONG)fft_n, w, W, p);
    metrics->fft_prepare_time += omp_get_wtime() - phase_start;

    /* Forward FFT on all four shares (purely local) */
    phase_start = omp_get_wtime();
    FFT64s1((LONG)fft_n, fx_cloud, W, p, P);
    FFT64s1((LONG)fft_n, fx_user,  W, p, P);
    FFT64s1((LONG)fft_n, fy_cloud, W, p, P);
    FFT64s1((LONG)fft_n, fy_user,  W, p, P);
    metrics->fft_forward_time += omp_get_wtime() - phase_start;

    /* Pointwise Beaver multiply in frequency domain (one triple per bin) */
    phase_start = omp_get_wtime();
    LONG *fz_cloud = calloc(fft_n, sizeof(LONG));
    LONG *fz_user  = calloc(fft_n, sizeof(LONG));
    if (!fz_cloud || !fz_user) {
        die("beaver_poly_multiply: product FFT alloc failed");
    }
    for (size_t k = 0; k < fft_n; ++k) {
        uint64_t x_c = (uint64_t)fx_cloud[k];
        uint64_t x_u = (uint64_t)fx_user[k];
        uint64_t y_c = (uint64_t)fy_cloud[k];
        uint64_t y_u = (uint64_t)fy_user[k];

        uint64_t d_c = mod_sub(x_c, cache->a_cloud[k]);
        uint64_t d_u = mod_sub(x_u, cache->a_user[k]);
        uint64_t d   = mod_add(d_c, d_u);

        uint64_t e_c = mod_sub(y_c, cache->b_cloud[k]);
        uint64_t e_u = mod_sub(y_u, cache->b_user[k]);
        uint64_t e   = mod_add(e_c, e_u);

        uint64_t z_c = cache->c_cloud[k];
        z_c = mod_add(z_c, mod_mul(d, cache->b_cloud[k]));
        z_c = mod_add(z_c, mod_mul(e, cache->a_cloud[k]));
        z_c = mod_add(z_c, mod_mul(d, e));

        uint64_t z_u = cache->c_user[k];
        z_u = mod_add(z_u, mod_mul(d, cache->b_user[k]));
        z_u = mod_add(z_u, mod_mul(e, cache->a_user[k]));

        fz_cloud[k] = (LONG)z_c;
        fz_user[k]  = (LONG)z_u;

        /* Verification */
        uint64_t x_plain = mod_add(x_c, x_u);
        uint64_t y_plain = mod_add(y_c, y_u);
        if (mod_add(z_c, z_u) != mod_mul(x_plain, y_plain))
            die("FFT Beaver multiplication invariant failed");
        metrics->beaver_checks++;
        metrics->triples++;
    }
    metrics->beaver_pointwise_time += omp_get_wtime() - phase_start;

    /* Inverse FFT */
    phase_start = omp_get_wtime();
    MakeWinv64((LONG)fft_n, W, p);
    FFT64s2((LONG)fft_n, fz_cloud, W, p, P);
    FFT64s2((LONG)fft_n, fz_user,  W, p, P);
    LONG inv_n = modinv64s((LONG)fft_n, p);
    for (size_t i = 0; i < fft_n; ++i) {
        fz_cloud[i] = (LONG)mulrec64((unsigned long long)fz_cloud[i],
                                     (unsigned long long)inv_n, P);
        fz_user[i]  = (LONG)mulrec64((unsigned long long)fz_user[i],
                                     (unsigned long long)inv_n, P);
    }
    metrics->fft_inverse_time += omp_get_wtime() - phase_start;

    /* Extract convolution result */
    phase_start = omp_get_wtime();
    SharedPoly product = {
        poly_alloc(2 * len - 1),
        poly_alloc(2 * len - 1)
    };
    for (size_t i = 0; i < 2 * len - 1; ++i) {
        product.cloud.coeffs[i] = (uint64_t)fz_cloud[i];
        product.user.coeffs[i]  = (uint64_t)fz_user[i];
    }
    metrics->convolution_extract_time += omp_get_wtime() - phase_start;
    metrics->multiply_time += omp_get_wtime() - total_start;

    /* Message accounting */
    ProtocolMessage open_to_cloud = {
        ROLE_CLIENT, ROLE_CLOUD, round, 2 * fft_n,
        PHASE_BEAVER_MULTIPLY, CHANNEL_BEAVER_OPEN
    };
    ProtocolMessage open_to_client = {
        ROLE_CLOUD, ROLE_CLIENT, round, 2 * fft_n,
        PHASE_BEAVER_MULTIPLY, CHANNEL_BEAVER_OPEN
    };
    record_message(metrics, open_to_cloud);
    record_message(metrics, open_to_client);

    free(W);
    free(fz_user);
    free(fz_cloud);
    free(fy_user);
    free(fy_cloud);
    free(fx_user);
    free(fx_cloud);

    cache->consumed = 1;
    return product;
}

static RieRoundShares run_protocol3_share_round(const Poly *participant_polys,
                                                size_t participant_count,
                                                size_t public_degree,
                                                size_t round,
                                                RieOfflineCache *offline,
                                                Metrics *metrics)
{
    if (offline->participant_count != participant_count ||
        offline->round != round) {
        die("run_protocol3_share_round: offline cache does not match round");
    }
    CloudRole cloud = {poly_alloc(1)};
    Poly evaluator_sum = poly_alloc(1);

    for (size_t party = 0; party < participant_count; ++party) {
        const Poly *set_poly = &participant_polys[party];
        Poly omega = random_polynomial(
            public_degree,
            derive_seed(FIXED_PROTOCOL_SEED, round, party, 0x4f4d454741ULL));

        double start = omp_get_wtime();
        SharedPoly p_share;
        SharedPoly omega_share;
        share_poly_padded(
            set_poly, public_degree + 1,
            derive_seed(FIXED_PROTOCOL_SEED, round, party, 0x50534852ULL),
            &p_share);
        share_poly_padded(
            &omega, public_degree + 1,
            derive_seed(FIXED_PROTOCOL_SEED, round, party, 0x57534852ULL),
            &omega_share);
        metrics->share_time += omp_get_wtime() - start;

        ProtocolMessage p_upload = {
            ROLE_CLIENT, ROLE_CLOUD, round, p_share.cloud.len,
            PHASE_INPUT_SHARING, CHANNEL_SECRET_SHARE
        };
        ProtocolMessage omega_upload = {
            ROLE_CLIENT, ROLE_CLOUD, round, omega_share.cloud.len,
            PHASE_INPUT_SHARING, CHANNEL_SECRET_SHARE
        };
        record_message(metrics, p_upload);
        record_message(metrics, omega_upload);

        SharedPoly product = beaver_poly_multiply(
            &p_share, &omega_share, &offline->caches[party],
            round, metrics);

        start = omp_get_wtime();
        poly_add_inplace(&cloud.aggregate_share, &product.cloud);
        metrics->cloud_aggregate_time += omp_get_wtime() - start;

        ProtocolMessage user_result = {
            ROLE_CLIENT, ROLE_QUERY, round, product.user.len,
            PHASE_RESULT_DELIVERY, CHANNEL_COMMON_KEY_ENCRYPTED
        };
        record_message(metrics, user_result);
        Poly decrypted_user_share = common_key_encrypt_decrypt_poly(
            &product.user, round, party, metrics);
        poly_add_inplace(&evaluator_sum, &decrypted_user_share);
        poly_free(&decrypted_user_share);

        shared_poly_free(&product);
        shared_poly_free(&omega_share);
        shared_poly_free(&p_share);
        poly_free(&omega);
    }

    ProtocolMessage cloud_result = {
        ROLE_CLOUD, ROLE_QUERY, round, cloud.aggregate_share.len,
        PHASE_RESULT_DELIVERY, CHANNEL_SECURE_CHANNEL
    };
    record_message(metrics, cloud_result);

    RieRoundShares shares = {cloud.aggregate_share, evaluator_sum};
    return shares;
}

static void rie_round_shares_free(RieRoundShares *shares)
{
    poly_free(&shares->evaluator);
    poly_free(&shares->cloud);
}

static Poly reconstruct_rie_polynomial(RieRoundShares *shares,
                                       Metrics *metrics)
{
    double start = omp_get_wtime();
    poly_add_inplace(&shares->cloud, &shares->evaluator);
    metrics->reconstruct_time += omp_get_wtime() - start;
    metrics->reconstructed_polynomials++;

    poly_trim(&shares->cloud);
    Poly reconstructed = shares->cloud;
    shares->cloud.coeffs = NULL;
    shares->cloud.len = 0;
    return reconstructed;
}

static Poly run_rie_round(const Poly *participant_polys,
                          size_t participant_count,
                          size_t public_degree,
                          size_t round,
                          RieOfflineCache *offline,
                          Metrics *metrics)
{
    RieRoundShares shares = run_protocol3_share_round(
        participant_polys, participant_count, public_degree, round,
        offline, metrics);
    Poly reconstructed = reconstruct_rie_polynomial(&shares, metrics);
    rie_round_shares_free(&shares);
    return reconstructed;
}

static Poly direct_gcd_oracle(const Poly *polys, size_t count,
                              GcdBackend gcd_backend)
{
    if (count == 0) {
        Poly one = poly_alloc(1);
        one.coeffs[0] = 1;
        return one;
    }
    Poly current = poly_alloc(polys[0].len);
    memcpy(current.coeffs, polys[0].coeffs,
           polys[0].len * sizeof(uint64_t));
    for (size_t i = 1; i < count; ++i) {
        Poly next = polynomial_gcd(&current, &polys[i], gcd_backend);
        poly_free(&current);
        current = next;
    }
    return current;
}

static Dataset delegated_intersection(const ClientRole *clients,
                                      size_t client_count)
{
    Dataset result = dataset_copy(&clients[0].dataset);
    size_t out = 0;
    for (size_t i = 0; i < result.len; ++i) {
        int present = 1;
        for (size_t c = 1; c < client_count; ++c) {
            if (!dataset_contains(&clients[c].dataset, result.values[i])) {
                present = 0;
                break;
            }
        }
        if (present) {
            result.values[out++] = result.values[i];
        }
    }
    result.len = out;
    return result;
}

static Dataset dataset_intersection_two(const Dataset *lhs,
                                        const Dataset *rhs)
{
    Dataset result = {
        malloc((lhs->len ? lhs->len : 1) * sizeof(uint64_t)), 0
    };
    if (!result.values) {
        die("dataset_intersection_two: allocation failed");
    }
    size_t i = 0;
    size_t j = 0;
    while (i < lhs->len && j < rhs->len) {
        if (lhs->values[i] == rhs->values[j]) {
            result.values[result.len++] = lhs->values[i];
            i++;
            j++;
        } else if (lhs->values[i] < rhs->values[j]) {
            i++;
        } else {
            j++;
        }
    }
    return result;
}

static void print_dataset_sample(const char *label, const Dataset *dataset)
{
    printf("%s count=%zu values=", label, dataset->len);
    size_t shown = dataset->len < 12 ? dataset->len : 12;
    for (size_t i = 0; i < shown; ++i) {
        printf("%s%llu", i ? ":" : "",
               (unsigned long long)dataset->values[i]);
    }
    if (shown < dataset->len) {
        printf(":...");
    }
    printf("\n");
}

static const char *scenario_name(Scenario scenario)
{
    switch (scenario) {
    case SCENARIO_EMPTY: return "empty";
    case SCENARIO_FULL: return "full";
    case SCENARIO_SINGLE: return "single";
    case SCENARIO_DUPLICATES: return "duplicates";
    case SCENARIO_BOUNDS: return "bounds";
    default: return "half";
    }
}

static const char *mode_name(RunMode mode)
{
    return mode == MODE_PROTOCOL3 ? "protocol3" : "protocol3-method2";
}

static int mode_uses_protocol3_method2(RunMode mode)
{
    return mode == MODE_PROTOCOL3_METHOD2;
}

static const char *extraction_name(ExtractionMode extraction)
{
    return extraction == EXTRACT_GCD ? "gcd" : "roots-intersect";
}

static const char *root_method_name(RootMethod method)
{
    if (method == ROOT_FLINT_DISTINCT) {
        return "distinct";
    }
    return method == ROOT_TG ? "tg" : "flint";
}

static const char *gcd_backend_name(GcdBackend backend)
{
    return backend == GCD_NTL ? "ntl" : "flint";
}

static uint64_t field_elements_to_bytes(uint64_t field_elements)
{
    if (field_elements > UINT64_MAX / sizeof(uint64_t)) {
        die("field_elements_to_bytes: overflow");
    }
    return field_elements * (uint64_t)sizeof(uint64_t);
}

static const char *transport_model_name(TransportModel model)
{
    return model == TRANSPORT_ZHIHU_LINEAR ?
        "zhihu-linear" : "latency-bandwidth";
}

static const char *transport_profile_name(TransportProfile profile)
{
    if (profile == TRANSPORT_PROFILE_LAN) return "lan";
    if (profile == TRANSPORT_PROFILE_WAN) return "wan";
    return "custom";
}

static void apply_transport_profile(TransportConfig *config)
{
    if (config->profile == TRANSPORT_PROFILE_LAN) {
        config->linear_intercept = 0.024;
        config->linear_slope_per_mb = 0.004;
        config->linear_valid_min_mb = 10.0;
        config->bandwidth_mbps = 10000.0;
        config->latency_ms = 5.0;
    } else if (config->profile == TRANSPORT_PROFILE_WAN) {
        config->linear_intercept = 0.538;
        config->linear_slope_per_mb = 0.116;
        config->linear_valid_min_mb = 40.0;
        config->bandwidth_mbps = 100.0;
        config->latency_ms = 100.0;
    }
}

static TransportMetrics estimate_transport_metrics(
    const Metrics *metrics, const TransportConfig *config)
{
    if (config->bandwidth_mbps <= 0.0 || config->latency_ms < 0.0 ||
        config->linear_slope_per_mb < 0.0 || config->linear_intercept < 0.0) {
        die("invalid transport model parameters");
    }

    TransportMetrics out = {0};
    out.secret_share_bytes =
        field_elements_to_bytes(metrics->secret_share_field_elements);
    out.beaver_open_bytes =
        field_elements_to_bytes(metrics->beaver_open_field_elements);
    out.secure_channel_bytes =
        field_elements_to_bytes(metrics->secure_channel_field_elements);
    out.common_key_encrypted_payload_bytes =
        metrics->common_key_encrypted_bytes ? metrics->common_key_encrypted_bytes :
        field_elements_to_bytes(metrics->common_key_encrypted_field_elements);
    out.payload_bytes =
        out.secret_share_bytes + out.beaver_open_bytes +
        out.secure_channel_bytes + out.common_key_encrypted_payload_bytes;
    out.overhead_bytes =
        metrics->messages * config->message_overhead_bytes;
    out.total_bytes = out.payload_bytes + out.overhead_bytes;
    out.messages = metrics->messages;
    out.communication_mb = (double)out.total_bytes / 1000000.0;
    if (config->model == TRANSPORT_ZHIHU_LINEAR) {
        out.latency_time = config->linear_intercept;
        out.bandwidth_time = config->linear_slope_per_mb * out.communication_mb;
    } else {
        out.latency_time =
            (double)metrics->messages * config->latency_ms / 1000.0;
        out.bandwidth_time =
            ((double)out.total_bytes * 8.0) /
            (config->bandwidth_mbps * 1000000.0);
    }
    out.transport_time = out.latency_time + out.bandwidth_time;
    return out;
}

static const char *transport_runtime_name(TransportRuntimeMode mode);

static void print_transport_metrics(const char *label,
                                    const TransportMetrics *metrics,
                                    const TransportConfig *config,
                                    double online_time,
                                    double end_to_end_time)
{
    int estimate_applied =
        g_transport_runtime != TRANSPORT_RUNTIME_TCP_TLS;
    double combined_online = estimate_applied ?
        online_time + metrics->transport_time : online_time;
    double combined_end_to_end = estimate_applied ?
        end_to_end_time + metrics->transport_time : end_to_end_time;
    printf(
        "%s model=%s,profile=%s,runtime=%s,estimate_applied=%s,"
        "bandwidth_mbps=%.6f,"
        "latency_ms=%.6f,message_overhead_bytes=%llu,"
        "linear_intercept=%.6f,linear_slope_per_mb=%.6f,"
        "linear_valid_min_mb=%.6f,field_bytes=%zu,messages=%llu,"
        "secret_share_bytes=%llu,beaver_open_bytes=%llu,"
        "secure_channel_bytes=%llu,common_key_encrypted_payload_bytes=%llu,"
        "payload_bytes=%llu,overhead_bytes=%llu,total_bytes=%llu,"
        "communication_mb=%.6f,latency_time=%.6f,bandwidth_time=%.6f,"
        "transport_time=%.6f,"
        "online_with_transport_time=%.6f,"
        "end_to_end_with_transport_time=%.6f\n",
        label, transport_model_name(config->model),
        transport_profile_name(config->profile),
        transport_runtime_name(g_transport_runtime),
        estimate_applied ? "yes" : "no",
        config->bandwidth_mbps, config->latency_ms,
        (unsigned long long)config->message_overhead_bytes,
        config->linear_intercept, config->linear_slope_per_mb,
        config->linear_valid_min_mb, sizeof(uint64_t),
        (unsigned long long)metrics->messages,
        (unsigned long long)metrics->secret_share_bytes,
        (unsigned long long)metrics->beaver_open_bytes,
        (unsigned long long)metrics->secure_channel_bytes,
        (unsigned long long)metrics->common_key_encrypted_payload_bytes,
        (unsigned long long)metrics->payload_bytes,
        (unsigned long long)metrics->overhead_bytes,
        (unsigned long long)metrics->total_bytes,
        metrics->communication_mb, metrics->latency_time,
        metrics->bandwidth_time,
        metrics->transport_time, combined_online, combined_end_to_end);
}

static void print_metrics(const char *label, const Metrics *metrics)
{
    printf(
        "%s share_time=%.6f,multiply_time=%.6f,"
        "cloud_aggregate_time=%.6f,reconstruct_time=%.6f,"
        "common_key_encrypt_time=%.6f,common_key_decrypt_time=%.6f,"
        "pke_key_exchange_time=%.6f,tls_handshake_time=%.6f,"
        "network_time=%.6f,spdz_mac_time=%.6f,"
        "common_key_encryptions=%llu,common_key_encrypted_bytes=%llu,"
        "pke_recipients=%llu,pke_ciphertext_bytes=%llu,"
        "tls_connections=%llu,network_messages=%llu,"
        "network_payload_bytes=%llu,network_wire_bytes=%llu,"
        "spdz_mac_checks=%llu,spdz_mac_failures=%llu,"
        "triples=%llu,beaver_checks=%llu,messages=%llu,"
        "field_elements=%llu\n",
        label,
        metrics->share_time,
        metrics->multiply_time,
        metrics->cloud_aggregate_time,
        metrics->reconstruct_time,
        metrics->common_key_encrypt_time,
        metrics->common_key_decrypt_time,
        metrics->pke_key_exchange_time,
        metrics->tls_handshake_time,
        metrics->network_time,
        metrics->spdz_mac_time,
        (unsigned long long)metrics->common_key_encryptions,
        (unsigned long long)metrics->common_key_encrypted_bytes,
        (unsigned long long)metrics->pke_recipients,
        (unsigned long long)metrics->pke_ciphertext_bytes,
        (unsigned long long)metrics->tls_connections,
        (unsigned long long)metrics->network_messages,
        (unsigned long long)metrics->network_payload_bytes,
        (unsigned long long)metrics->network_wire_bytes,
        (unsigned long long)metrics->spdz_mac_checks,
        (unsigned long long)metrics->spdz_mac_failures,
        (unsigned long long)metrics->triples,
        (unsigned long long)metrics->beaver_checks,
        (unsigned long long)metrics->messages,
        (unsigned long long)metrics->field_elements);
}

static const char *transport_runtime_name(TransportRuntimeMode mode)
{
    return mode == TRANSPORT_RUNTIME_TCP_TLS ? "tcp-tls" : "estimated";
}

static void print_network_metrics(const char *label, const Metrics *metrics)
{
    printf(
        "%s runtime=%s,rpc=length-prefixed-streaming,"
        "connection_model=long-lived,ack=one-byte,"
        "tls=openssl,connections=%llu,tls_handshake_time=%.6f,"
        "pke=rsa-oaep-sha256,pke_recipients=%llu,"
        "pke_public_key_bytes=%llu,pke_ciphertext_bytes=%llu,"
        "pke_decryptions=%llu,pke_key_exchange_time=%.6f,"
        "spdz_mac=hmac-sha256-frame-check,spdz_mac_checks=%llu,"
        "spdz_mac_failures=%llu,spdz_mac_bytes=%llu,"
        "spdz_mac_time=%.6f,messages=%llu,payload_bytes=%llu,"
        "wire_bytes=%llu,acks=%llu,network_time=%.6f\n",
        label, transport_runtime_name(g_transport_runtime),
        (unsigned long long)metrics->tls_connections,
        metrics->tls_handshake_time,
        (unsigned long long)metrics->pke_recipients,
        (unsigned long long)metrics->pke_public_key_bytes,
        (unsigned long long)metrics->pke_ciphertext_bytes,
        (unsigned long long)metrics->pke_decryptions,
        metrics->pke_key_exchange_time,
        (unsigned long long)metrics->spdz_mac_checks,
        (unsigned long long)metrics->spdz_mac_failures,
        (unsigned long long)metrics->spdz_mac_bytes,
        metrics->spdz_mac_time,
        (unsigned long long)metrics->network_messages,
        (unsigned long long)metrics->network_payload_bytes,
        (unsigned long long)metrics->network_wire_bytes,
        (unsigned long long)metrics->network_acks,
        metrics->network_time);
}

static void print_profile_metrics(const char *label,
                                  const Metrics *metrics)
{
    printf(
        "%s fft_prepare_time=%.6f,fft_forward_time=%.6f,"
        "beaver_pointwise_time=%.6f,fft_inverse_time=%.6f,"
        "convolution_extract_time=%.6f\n",
        label,
        metrics->fft_prepare_time,
        metrics->fft_forward_time,
        metrics->beaver_pointwise_time,
        metrics->fft_inverse_time,
        metrics->convolution_extract_time);
}

static void print_framework_metrics(const char *label,
                                    const Metrics *metrics)
{
    printf(
        "%s secret_share_field_elements=%llu,"
        "beaver_open_field_elements=%llu,"
        "secure_channel_field_elements=%llu,"
        "common_key_encrypted_field_elements=%llu,"
        "reconstructed_polynomials=%llu\n",
        label,
        (unsigned long long)metrics->secret_share_field_elements,
        (unsigned long long)metrics->beaver_open_field_elements,
        (unsigned long long)metrics->secure_channel_field_elements,
        (unsigned long long)metrics->common_key_encrypted_field_elements,
        (unsigned long long)metrics->reconstructed_polynomials);
}

typedef struct {
    uint64_t rss_kib;
    uint64_t peak_rss_kib;
} MemoryUsage;

static MemoryUsage read_memory_usage(void)
{
    MemoryUsage usage = {0, 0};
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) {
        return usage;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        unsigned long long value = 0;
        if (sscanf(line, "VmRSS: %llu kB", &value) == 1) {
            usage.rss_kib = (uint64_t)value;
        } else if (sscanf(line, "VmHWM: %llu kB", &value) == 1) {
            usage.peak_rss_kib = (uint64_t)value;
        }
    }
    fclose(file);
    return usage;
}

static void print_memory_usage(const char *label)
{
    MemoryUsage usage = read_memory_usage();
    printf("%s rss_kib=%llu,peak_rss_kib=%llu\n",
           label,
           (unsigned long long)usage.rss_kib,
           (unsigned long long)usage.peak_rss_kib);
}

static void print_protocol_trace(RunMode mode, size_t client_count,
                                 int dataset_exp, int validate)
{
    size_t n = (size_t)1 << dataset_exp;
    printf(
        "DPSI_TRACE framework=paper-aligned,security_model=semi-honest,"
        "transport_runtime=%s,clients=%zu,input_size=%zu,"
        "validate=%s\n",
        transport_runtime_name(g_transport_runtime),
        client_count, n, validate ? "yes" : "no");
    printf(
        "DPSI_TRACE phase=setup paper=Protocol3.Step1 "
        "action=direct-32bit-field-embedding hash_tag=no\n");
    printf(
        "DPSI_TRACE phase=input-sharing paper=Protocol3.Step3-4 "
        "action=additive-share pi-and-omega receiver=cloud\n");
    printf(
        "DPSI_TRACE phase=secure-multiply paper=Protocol3.Step5-6 "
        "action=fft-domain-beaver-multiply triples=offline-cache\n");
    printf(
        "DPSI_TRACE phase=delivery paper=Protocol3.Step7-8 "
        "action=cloud-share-via-secure-channel,user-share-via-common-key\n");
    printf(
        "DPSI_TRACE phase=reconstruction paper=Protocol3.Step9 "
        "action=evaluator-reconstructs-rie-polynomial\n");
    if (mode_uses_protocol3_method2(mode)) {
        printf(
            "DPSI_TRACE phase=third-party-query paper=Fig4+Section6.3.Method2 "
            "action=run-two-independent-protocol3-share-rounds,skip-query-input-filter,gcd,root-extraction\n");
    } else {
        printf(
            "DPSI_TRACE phase=query-filter paper=Protocol3.Step9 "
            "action=query-party-fast-multipoint-root-test\n");
    }
}

static void print_offline_metrics(const char *label,
                                  const OfflineMetrics *metrics)
{
    printf(
        "%s triple_generate_time=%.6f,triples=%llu,"
        "cached_field_elements=%llu,cache_bytes=%llu\n",
        label,
        metrics->triple_generate_time,
        (unsigned long long)metrics->triples,
        (unsigned long long)metrics->cached_field_elements,
        (unsigned long long)metrics->cache_bytes);
}

static int run_protocol(RunMode mode, size_t client_count, int dataset_exp,
                        Scenario scenario, int validate,
                        ExtractionMode extraction, RootMethod root_method,
                        GcdBackend gcd_backend, int trace,
                        const TransportConfig *transport_config,
                        int has_common_override, size_t common_override)
{
    size_t n = (size_t)1 << dataset_exp;
    if (trace) {
        print_protocol_trace(mode, client_count, dataset_exp, validate);
    }
    ClientRole *clients = calloc(client_count, sizeof(ClientRole));
    Poly *delegated_polys = calloc(client_count, sizeof(Poly));
    Poly *all_polys = validate ? calloc(client_count + 1, sizeof(Poly)) : NULL;
    if (!clients || !delegated_polys || (validate && !all_polys)) {
        die("run_protocol: allocation failed");
    }

    DealerRole dealer = {FIXED_PROTOCOL_SEED};
    Metrics protocol_metrics = {0};
    Metrics validation_metrics = {0};
    OfflineMetrics protocol_offline_metrics = {0};
    OfflineMetrics validation_offline_metrics = {0};

    if (g_transport_runtime == TRANSPORT_RUNTIME_TCP_TLS) {
        tls_rpc_transport_start(&g_tls_transport, &protocol_metrics);
    }
    perform_pke_common_key_exchange(client_count + 1, &protocol_metrics);

    QueryRole query = {
        make_dataset(n, 0, 1, scenario, has_common_override,
                     common_override)
    };
    double start = omp_get_wtime();
    for (size_t i = 0; i < client_count; ++i) {
        clients[i].id = i + 1;
        clients[i].dataset = make_dataset(
            n, i + 1, 0, scenario, has_common_override, common_override);
        clients[i].set_poly = build_set_polynomial(&clients[i].dataset);
        delegated_polys[i] = clients[i].set_poly;
        if (validate) {
            all_polys[i] = clients[i].set_poly;
        }
    }
    Poly query_poly = {NULL, 0};
    if (validate) {
        query_poly = build_set_polynomial(&query.dataset);
        all_polys[client_count] = query_poly;
    }
    protocol_metrics.set_poly_time = omp_get_wtime() - start;

    Dataset expected = expected_intersection(clients, client_count, &query);
    Dataset delegated_expected =
        delegated_intersection(clients, client_count);

    Poly oracle_poly = {NULL, 0};
    Dataset oracle_roots = {NULL, 0};
    if (validate) {
        start = omp_get_wtime();
        oracle_poly = direct_gcd_oracle(all_polys, client_count + 1,
                                        gcd_backend);
        validation_metrics.gcd_time += omp_get_wtime() - start;
        double oracle_tg_time = 0.0;
        oracle_roots = extract_roots(&oracle_poly, root_method,
                                     &oracle_tg_time);
        validation_metrics.tg_time += oracle_tg_time;
    }

    RieOfflineCache protocol_r1 = rie_offline_precompute(
        &dealer, client_count, n + 1, 1, &protocol_offline_metrics);
    Poly r1 = run_rie_round(delegated_polys, client_count, n, 1,
                            &protocol_r1, &protocol_metrics);
    rie_offline_free(&protocol_r1);
    Dataset paper_result = {NULL, 0};
    if (mode == MODE_PROTOCOL3 || validate) {
        start = omp_get_wtime();
        paper_result = query_evaluate_rie(&query, &r1);
        protocol_metrics.query_filter_time += omp_get_wtime() - start;
    }

    Dataset third_party_roots = {NULL, 0};
    Dataset r1_roots = {NULL, 0};
    Dataset r2_roots = {NULL, 0};
    Dataset query_included_roots = {NULL, 0};
    Poly r2 = {NULL, 0};
    Poly double_gcd = {NULL, 0};
    Poly included_gcd = {NULL, 0};
    size_t random_factor_excess = 0;
    int double_ok = 1;
    int included_ok = 1;

    if (mode_uses_protocol3_method2(mode)) {
        RieOfflineCache protocol_r2 = rie_offline_precompute(
            &dealer, client_count, n + 1, 2, &protocol_offline_metrics);
        r2 = run_rie_round(delegated_polys, client_count, n, 2,
                           &protocol_r2, &protocol_metrics);
        rie_offline_free(&protocol_r2);
        if (extraction == EXTRACT_GCD) {
            start = omp_get_wtime();
            double_gcd = polynomial_gcd(&r1, &r2, gcd_backend);
            protocol_metrics.gcd_time += omp_get_wtime() - start;
            if (poly_degree(&double_gcd) > delegated_expected.len) {
                random_factor_excess =
                    poly_degree(&double_gcd) - delegated_expected.len;
            }
            double tg_elapsed = 0.0;
            third_party_roots = extract_roots(&double_gcd, root_method,
                                              &tg_elapsed);
            protocol_metrics.tg_time += tg_elapsed;
        } else {
            double tg_elapsed = 0.0;
            r1_roots = extract_roots(&r1, root_method, &tg_elapsed);
            protocol_metrics.tg_time += tg_elapsed;
            tg_elapsed = 0.0;
            r2_roots = extract_roots(&r2, root_method, &tg_elapsed);
            protocol_metrics.tg_time += tg_elapsed;
            third_party_roots =
                dataset_intersection_two(&r1_roots, &r2_roots);
            if (third_party_roots.len > delegated_expected.len) {
                random_factor_excess =
                    third_party_roots.len - delegated_expected.len;
            }
        }
        double_ok = dataset_equal(&third_party_roots, &delegated_expected);

        if (validate) {
            RieOfflineCache validation_r1 = rie_offline_precompute(
                &dealer, client_count + 1, n + 1, 101,
                &validation_offline_metrics);
            Poly included_r1 = run_rie_round(
                all_polys, client_count + 1, n, 101,
                &validation_r1, &validation_metrics);
            rie_offline_free(&validation_r1);
            RieOfflineCache validation_r2 = rie_offline_precompute(
                &dealer, client_count + 1, n + 1, 102,
                &validation_offline_metrics);
            Poly included_r2 = run_rie_round(
                all_polys, client_count + 1, n, 102,
                &validation_r2, &validation_metrics);
            rie_offline_free(&validation_r2);
            start = omp_get_wtime();
            included_gcd = polynomial_gcd(&included_r1, &included_r2,
                                          gcd_backend);
            validation_metrics.gcd_time += omp_get_wtime() - start;
            query_included_roots =
                extract_roots(&included_gcd, root_method,
                              &validation_metrics.tg_time);
            included_ok = dataset_equal(&query_included_roots, &expected);
            poly_free(&included_r2);
            poly_free(&included_r1);
        }
    }

    if (g_transport_runtime == TRANSPORT_RUNTIME_TCP_TLS) {
        tls_rpc_transport_stop(&g_tls_transport);
    }

    int paper_ok = (mode_uses_protocol3_method2(mode) && !validate) ?
        1 : dataset_equal(&paper_result, &expected);
    int oracle_ok = validate ? dataset_equal(&oracle_roots, &expected) : 1;
    int root_count_ok =
        mode_uses_protocol3_method2(mode) ?
            (third_party_roots.len == delegated_expected.len) : 1;
    double total_time =
        protocol_metrics.set_poly_time +
        protocol_metrics.share_time +
        protocol_metrics.multiply_time +
        protocol_metrics.cloud_aggregate_time +
        protocol_metrics.reconstruct_time +
        protocol_metrics.common_key_encrypt_time +
        protocol_metrics.common_key_decrypt_time +
        protocol_metrics.pke_key_exchange_time +
        protocol_metrics.tls_handshake_time +
        protocol_metrics.network_time +
        protocol_metrics.gcd_time +
        protocol_metrics.tg_time +
        protocol_metrics.query_filter_time;
    double end_to_end_time =
        protocol_offline_metrics.triple_generate_time + total_time;
    TransportMetrics transport_metrics =
        estimate_transport_metrics(&protocol_metrics, transport_config);
    double online_with_transport_time =
        g_transport_runtime == TRANSPORT_RUNTIME_TCP_TLS ?
            total_time : total_time + transport_metrics.transport_time;
    double end_to_end_with_transport_time =
        g_transport_runtime == TRANSPORT_RUNTIME_TCP_TLS ?
            end_to_end_time : end_to_end_time + transport_metrics.transport_time;

    printf(
        "RIE_RESULT mode=%s,scenario=%s,clients=%zu,dataset_exp=%d,"
        "input_size=%zu,configured_common=%zu,validate=%s,"
        "hash_tag=no,rie_rounds=%zu,third_party_query=%s,"
        "transport_runtime=%s,common_key_exchange=rsa-oaep-sha256,"
        "common_key_cipher=aes-256-gcm,"
        "extract=%s,gcd_backend=%s,root=%s,expected=%zu,"
        "delegated_expected=%zu,"
        "paper_result=%zu,paper_match=%s,"
        "double_result=%zu,root_count_match=%s,double_match=%s,"
        "query_included_result=%zu,"
        "query_included_match=%s,oracle_result=%zu,oracle_match=%s,"
        "deg_r1=%zu,deg_r2=%zu,deg_double_gcd=%zu,"
        "random_factor_degree_excess=%zu,set_poly_time=%.6f,"
        "common_key_encrypt_time=%.6f,common_key_decrypt_time=%.6f,"
        "common_key_encrypted_bytes=%llu,pke_key_exchange_time=%.6f,"
        "tls_handshake_time=%.6f,network_time=%.6f,"
        "spdz_mac_checks=%llu,spdz_mac_failures=%llu,gcd_time=%.6f,"
        "tg_time=%.6f,query_filter_time=%.6f,online_time=%.6f,"
        "transport_time=%.6f,online_with_transport_time=%.6f,"
        "total_time=%.6f,end_to_end_time=%.6f,"
        "end_to_end_with_transport_time=%.6f\n",
        mode_name(mode), scenario_name(scenario), client_count, dataset_exp,
        n, has_common_override ? common_override : delegated_expected.len,
        validate ? "yes" : "no",
        mode_uses_protocol3_method2(mode) ? (size_t)2 : (size_t)1,
        mode_uses_protocol3_method2(mode) ? "yes" : "no",
        transport_runtime_name(g_transport_runtime),
        extraction_name(extraction),
        gcd_backend_name(gcd_backend), root_method_name(root_method),
        expected.len,
        delegated_expected.len,
        paper_result.len,
        (mode_uses_protocol3_method2(mode) && !validate) ?
            "n/a" : (paper_ok ? "yes" : "no"),
        third_party_roots.len,
        mode_uses_protocol3_method2(mode) ?
            (root_count_ok ? "yes" : "no") : "n/a",
        mode_uses_protocol3_method2(mode) ?
            (double_ok ? "yes" : "no") : "n/a",
        query_included_roots.len,
        (mode_uses_protocol3_method2(mode) && validate) ?
            (included_ok ? "yes" : "no") : "n/a",
        oracle_roots.len, validate ? (oracle_ok ? "yes" : "no") : "n/a",
        poly_degree(&r1), r2.coeffs ? poly_degree(&r2) : 0,
        double_gcd.coeffs ? poly_degree(&double_gcd) : 0,
        random_factor_excess, protocol_metrics.set_poly_time,
        protocol_metrics.common_key_encrypt_time,
        protocol_metrics.common_key_decrypt_time,
        (unsigned long long)protocol_metrics.common_key_encrypted_bytes,
        protocol_metrics.pke_key_exchange_time,
        protocol_metrics.tls_handshake_time,
        protocol_metrics.network_time,
        (unsigned long long)protocol_metrics.spdz_mac_checks,
        (unsigned long long)protocol_metrics.spdz_mac_failures,
        protocol_metrics.gcd_time, protocol_metrics.tg_time,
        protocol_metrics.query_filter_time, total_time,
        transport_metrics.transport_time, online_with_transport_time,
        total_time, end_to_end_time, end_to_end_with_transport_time);
    print_offline_metrics("RIE_OFFLINE protocol",
                          &protocol_offline_metrics);
    if (validate && mode_uses_protocol3_method2(mode)) {
        print_offline_metrics("RIE_OFFLINE validation",
                               &validation_offline_metrics);
    }
    print_metrics("RIE_METRICS protocol", &protocol_metrics);
    print_network_metrics("RIE_NETWORK protocol", &protocol_metrics);
    print_profile_metrics("RIE_PROFILE protocol", &protocol_metrics);
    print_framework_metrics("RIE_FRAMEWORK protocol", &protocol_metrics);
    print_transport_metrics("RIE_TRANSPORT protocol", &transport_metrics,
                            transport_config, total_time, end_to_end_time);
    if (validate && mode_uses_protocol3_method2(mode)) {
        print_metrics("RIE_METRICS validation", &validation_metrics);
        print_network_metrics("RIE_NETWORK validation", &validation_metrics);
        print_profile_metrics("RIE_PROFILE validation",
                               &validation_metrics);
        print_framework_metrics("RIE_FRAMEWORK validation",
                                &validation_metrics);
    }
    print_memory_usage("RIE_MEMORY");
    print_dataset_sample("EXPECTED", &expected);
    print_dataset_sample("DELEGATED_EXPECTED", &delegated_expected);
    if (mode == MODE_PROTOCOL3 || validate) {
        print_dataset_sample("PAPER", &paper_result);
    }
    if (mode_uses_protocol3_method2(mode)) {
        print_dataset_sample("THIRD_PARTY", &third_party_roots);
    }
    if (validate && mode_uses_protocol3_method2(mode)) {
        print_dataset_sample("QUERY_INCLUDED", &query_included_roots);
    }

    int success = paper_ok && oracle_ok && double_ok && included_ok;

    poly_free(&included_gcd);
    poly_free(&double_gcd);
    poly_free(&r2);
    poly_free(&r1);
    dataset_free(&query_included_roots);
    dataset_free(&r2_roots);
    dataset_free(&r1_roots);
    dataset_free(&third_party_roots);
    dataset_free(&oracle_roots);
    dataset_free(&paper_result);
    dataset_free(&delegated_expected);
    dataset_free(&expected);
    poly_free(&oracle_poly);
    poly_free(&query_poly);
    dataset_free(&query.dataset);
    for (size_t i = 0; i < client_count; ++i) {
        poly_free(&clients[i].set_poly);
        dataset_free(&clients[i].dataset);
    }
    free(all_polys);
    free(delegated_polys);
    free(clients);
    return success ? 0 : 1;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --mode protocol3|protocol3-method2|third-party-method2 "
            "--clients 2..%d "
            "--exp 1..%d [--scenario half|empty|full|single|duplicates|bounds] "
            "[--intersection-rate 0.0..1.0] [--validate] [--trace] "
            "[--transport simulated|tcp-tls] "
            "[--extract gcd] [--gcd flint|ntl] "
            "[--root flint|distinct|tg] "
            "[--transport-model latency-bandwidth|zhihu-linear] "
            "[--transport-profile lan|wan|custom] "
            "[--transport-bandwidth-mbps M] [--transport-latency-ms L] "
            "[--transport-message-overhead-bytes B] "
            "[--transport-linear-intercept S] "
            "[--transport-linear-slope-per-mb S] "
            "[--transport-linear-valid-min-mb M]\n",
            program, MAX_CLIENTS, MAX_DATASET_EXP);
}

static Scenario parse_scenario(const char *value)
{
    if (strcmp(value, "empty") == 0) return SCENARIO_EMPTY;
    if (strcmp(value, "full") == 0) return SCENARIO_FULL;
    if (strcmp(value, "single") == 0) return SCENARIO_SINGLE;
    if (strcmp(value, "duplicates") == 0) return SCENARIO_DUPLICATES;
    if (strcmp(value, "bounds") == 0) return SCENARIO_BOUNDS;
    if (strcmp(value, "half") == 0) return SCENARIO_HALF;
    die("unknown scenario");
    return SCENARIO_HALF;
}

int main(int argc, char **argv)
{
    RunMode mode = MODE_PROTOCOL3;
    Scenario scenario = SCENARIO_HALF;
    size_t clients = 0;
    int dataset_exp = -1;
    int validate = 0;
    int trace = 0;
    int has_intersection_rate = 0;
    double intersection_rate = 0.0;
    ExtractionMode extraction = EXTRACT_GCD;
    RootMethod root_method = ROOT_TG;
    GcdBackend gcd_backend = GCD_NTL;
    TransportConfig transport_config = {
        100.0, 100.0, 64, TRANSPORT_ZHIHU_LINEAR,
        TRANSPORT_PROFILE_WAN, 0.538, 0.116, 40.0
    };

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "protocol3") == 0) {
                mode = MODE_PROTOCOL3;
            } else if (strcmp(value, "protocol3-method2") == 0 ||
                       strcmp(value, "third-party-method2") == 0) {
                mode = MODE_PROTOCOL3_METHOD2;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--clients") == 0 && i + 1 < argc) {
            clients = (size_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--exp") == 0 && i + 1 < argc) {
            dataset_exp = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            scenario = parse_scenario(argv[++i]);
        } else if (strcmp(argv[i], "--validate") == 0) {
            validate = 1;
        } else if (strcmp(argv[i], "--trace") == 0) {
            trace = 1;
        } else if (strcmp(argv[i], "--transport") == 0 &&
                   i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "simulated") == 0) {
                g_transport_runtime = TRANSPORT_RUNTIME_ESTIMATED;
            } else if (strcmp(value, "tcp-tls") == 0) {
                g_transport_runtime = TRANSPORT_RUNTIME_TCP_TLS;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--real-network") == 0) {
            g_transport_runtime = TRANSPORT_RUNTIME_TCP_TLS;
        } else if (strcmp(argv[i], "--intersection-rate") == 0 &&
                   i + 1 < argc) {
            intersection_rate = atof(argv[++i]);
            has_intersection_rate = 1;
        } else if (strcmp(argv[i], "--extract") == 0 && i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "gcd") == 0) {
                extraction = EXTRACT_GCD;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--gcd") == 0 && i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "flint") == 0) {
                gcd_backend = GCD_FLINT;
            } else if (strcmp(value, "ntl") == 0) {
                gcd_backend = GCD_NTL;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "flint") == 0) {
                root_method = ROOT_FLINT;
            } else if (strcmp(value, "distinct") == 0) {
                root_method = ROOT_FLINT_DISTINCT;
            } else if (strcmp(value, "tg") == 0) {
                root_method = ROOT_TG;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--transport-model") == 0 &&
                   i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "latency-bandwidth") == 0) {
                transport_config.model = TRANSPORT_LATENCY_BANDWIDTH;
            } else if (strcmp(value, "zhihu-linear") == 0) {
                transport_config.model = TRANSPORT_ZHIHU_LINEAR;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--transport-profile") == 0 &&
                   i + 1 < argc) {
            const char *value = argv[++i];
            if (strcmp(value, "lan") == 0) {
                transport_config.profile = TRANSPORT_PROFILE_LAN;
                apply_transport_profile(&transport_config);
            } else if (strcmp(value, "wan") == 0) {
                transport_config.profile = TRANSPORT_PROFILE_WAN;
                apply_transport_profile(&transport_config);
            } else if (strcmp(value, "custom") == 0) {
                transport_config.profile = TRANSPORT_PROFILE_CUSTOM;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--transport-bandwidth-mbps") == 0 &&
                   i + 1 < argc) {
            transport_config.bandwidth_mbps = atof(argv[++i]);
            transport_config.profile = TRANSPORT_PROFILE_CUSTOM;
        } else if (strcmp(argv[i], "--transport-latency-ms") == 0 &&
                   i + 1 < argc) {
            transport_config.latency_ms = atof(argv[++i]);
            transport_config.profile = TRANSPORT_PROFILE_CUSTOM;
        } else if (strcmp(argv[i], "--transport-message-overhead-bytes") == 0 &&
                   i + 1 < argc) {
            transport_config.message_overhead_bytes =
                (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--transport-linear-intercept") == 0 &&
                   i + 1 < argc) {
            transport_config.linear_intercept = atof(argv[++i]);
            transport_config.profile = TRANSPORT_PROFILE_CUSTOM;
        } else if (strcmp(argv[i], "--transport-linear-slope-per-mb") == 0 &&
                   i + 1 < argc) {
            transport_config.linear_slope_per_mb = atof(argv[++i]);
            transport_config.profile = TRANSPORT_PROFILE_CUSTOM;
        } else if (strcmp(argv[i], "--transport-linear-valid-min-mb") == 0 &&
                   i + 1 < argc) {
            transport_config.linear_valid_min_mb = atof(argv[++i]);
            transport_config.profile = TRANSPORT_PROFILE_CUSTOM;
        } else if (strcmp(argv[i], "--seed") == 0) {
            die("runtime seed is intentionally unsupported; fixed seed required");
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (clients < 2 || clients > MAX_CLIENTS ||
        dataset_exp < 1 || dataset_exp > MAX_DATASET_EXP) {
        usage(argv[0]);
        return 2;
    }
    if (FIELD_PRIME <= UINT32_MAX) {
        die("active field prime must exceed the 32-bit element range");
    }
    if (has_intersection_rate &&
        (intersection_rate < 0.0 || intersection_rate > 1.0)) {
        die("intersection rate must be between 0.0 and 1.0");
    }
    if (transport_config.bandwidth_mbps <= 0.0 ||
        transport_config.latency_ms < 0.0 ||
        transport_config.linear_intercept < 0.0 ||
        transport_config.linear_slope_per_mb < 0.0 ||
        transport_config.linear_valid_min_mb < 0.0) {
        die("invalid transport model parameters");
    }
    size_t common_override = 0;
    if (has_intersection_rate) {
        common_override =
            (size_t)(intersection_rate * (double)((size_t)1 << dataset_exp));
    }
    int worker_threads = omp_get_max_threads();
    if (dataset_exp <= 15 && worker_threads > 32) {
        worker_threads = 32;
        omp_set_num_threads(worker_threads);
    }
    flint_set_num_threads(worker_threads);
    printf("RIE_HEADER fixed_seed=%llu,field_prime=%llu,data_bits=%d\n",
           (unsigned long long)FIXED_PROTOCOL_SEED,
           (unsigned long long)FIELD_PRIME, DATA_BIT);
    return run_protocol(mode, clients, dataset_exp, scenario, validate,
                        extraction, root_method, gcd_backend, trace,
                        &transport_config, has_intersection_rate,
                        common_override);
}
