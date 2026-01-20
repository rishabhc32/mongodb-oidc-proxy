local function shallow_copy(t)
  local copy = {}
  for k, v in pairs(t) do copy[k] = v end
  return copy
end

local function empty_if_missing(v)
  return v ~= nil and v or ""
end

function normalize(tag, ts, record)
  -- Skip records with empty or missing event type
  if record["ev"] == nil or record["ev"] == "" then
    return -1, 0, 0
  end

  -- Provide Elasticsearch-compatible @timestamp
  local millis = math.floor((ts % 1) * 1000)
  record["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S", ts) .. string.format(".%03dZ", millis)

  -- Drop tags when missing/empty to avoid placeholder values
  if record["tags"] ~= nil and #record["tags"] == 0 then
    record["tags"] = nil
  end

  record["connId"] = empty_if_missing(record["connId"])
  record["user"] = empty_if_missing(record["user"])
  record["db"] = empty_if_missing(record["db"])
  record["cmd"] = empty_if_missing(record["cmd"])
  record["error"] = empty_if_missing(record["error"])
  record["source"] = empty_if_missing(record["source"])

  record["requestBytes"] = record["requestBytes"] or 0
  record["responseBytes"] = record["responseBytes"] or 0
  record["bytesInTotal"] = record["bytesInTotal"] or 0
  record["bytesOutTotal"] = record["bytesOutTotal"] or 0

  return 1, ts, record
end
