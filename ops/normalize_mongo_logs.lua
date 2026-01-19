function normalize(tag, ts, record)
  local function empty_if_missing(v)
    if v == nil then
      return ""
    end
    return v
  end

  -- Build tags array from either "tags" or "tag" field
  if record["tags"] ~= nil then
    if type(record["tags"]) == "string" then
      record["tags"] = { record["tags"] }
    end
  elseif record["tag"] ~= nil then
    record["tags"] = { record["tag"] }
    record["tag"] = nil
  else
    record["tags"] = { "" }  -- Empty array serializes as {}, use placeholder instead
  end

  record["user"] = empty_if_missing(record["user"])
  record["db"] = empty_if_missing(record["db"])
  record["cmd"] = empty_if_missing(record["cmd"])
  record["error"] = empty_if_missing(record["error"])
  record["source"] = empty_if_missing(record["source"])

  record["bytesInTotal"] = record["bytesInTotal"] or 0
  record["bytesOutTotal"] = record["bytesOutTotal"] or 0

  return 1, ts, record
end
