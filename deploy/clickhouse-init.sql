CREATE DATABASE IF NOT EXISTS traffic;

CREATE TABLE IF NOT EXISTS traffic.flows (
    timestamp       DateTime64(6),
    first_seen      Int64,
    last_seen       Int64,
    src_ip          String,
    dst_ip          String,
    src_port        UInt16,
    dst_port        UInt16,
    protocol        String,
    sni             String,
    ja3             String,
    ja3s            String,
    tls_version     String,
    server_cipher_suite UInt16,
    tls_signature_hash  String,
    dns_domain      String,
    http_host       String,
    http_method     String,
    http_ua         String,
    packets_up      UInt32,
    packets_down    UInt32,
    bytes_up        Int64,
    bytes_down      Int64,
    duration_ms     Int64,
    pkt_size_hist   String,
    pkt_iat_mean_us Float64,
    app_id          UInt32,
    app_name        String,
    app_category    String,
    confidence      Float32,
    src_mac         String,
    device_manufacturer String,
    device_hostname String,
    engines         String
) ENGINE = ReplacingMergeTree(last_seen)
  PARTITION BY toYYYYMM(timestamp)
  ORDER BY (timestamp, src_ip, first_seen)
  TTL toDateTime(timestamp) + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS traffic.flow_stats_daily (
    date            Date,
    app_id          UInt32,
    app_name        String,
    app_category    String,
    flow_count      UInt64,
    total_bytes     Int64,
    unique_devices  UInt64
) ENGINE = SummingMergeTree
  PARTITION BY toYYYYMM(date)
  ORDER BY (date, app_id);

CREATE TABLE IF NOT EXISTS traffic.device_info (
    ip           String,
    mac          String,
    hostname     String,
    vendor_class String,
    manufacturer String,
    first_seen   Int64
) ENGINE = MergeTree
  ORDER BY ip;
