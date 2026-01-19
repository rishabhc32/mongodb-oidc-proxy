-- ClickHouse Schema for MongoDB Proxy Logs with Bandwidth Tracking

-- Main events table (all events)
CREATE TABLE IF NOT EXISTS mongo_logs (
    ts DateTime64(3, 'UTC'),
    ev LowCardinality(String),
    connId Int32,

    -- Common fields (extracted for fast queries)
    user String DEFAULT '',
    tags Array(String) DEFAULT [],
    db String DEFAULT '',
    cmd String DEFAULT '',
    error String DEFAULT '',
    source String DEFAULT '',

    -- Bandwidth fields (cumulative totals per connection)
    bytesInTotal UInt64 DEFAULT 0,
    bytesOutTotal UInt64 DEFAULT 0,

    -- Full log as native JSON (for flexible querying)
    log JSON,

    INDEX idxTags tags TYPE bloom_filter(0.01) GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (user, ev, ts)
SETTINGS index_granularity = 8192;
