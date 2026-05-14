ATTACH TABLE _ UUID 'b61dbfad-f13c-4e2d-9149-d3bfc316ba6a'
(
    `timestamp` DateTime64(6),
    `first_seen` Int64,
    `last_seen` Int64,
    `src_ip` String,
    `dst_ip` String,
    `src_port` UInt16,
    `dst_port` UInt16,
    `protocol` String,
    `sni` String,
    `ja3` String,
    `dns_domain` String,
    `http_host` String,
    `http_method` String,
    `http_ua` String,
    `packets_up` UInt32,
    `packets_down` UInt32,
    `bytes_up` Int64,
    `bytes_down` Int64,
    `duration_ms` Int64,
    `pkt_size_hist` String,
    `pkt_iat_mean_us` Float64,
    `app_id` UInt32,
    `app_name` String,
    `app_category` String,
    `confidence` Float32,
    `src_mac` String,
    `device_manufacturer` String,
    `device_hostname` String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip)
TTL toDateTime(timestamp) + toIntervalDay(90)
SETTINGS index_granularity = 8192
