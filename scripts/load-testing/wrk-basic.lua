-- wrk load testing script for Prism
-- Run: wrk -t4 -c100 -d30s -s scripts/load-testing/wrk-basic.lua http://localhost:8080

-- Thread-local counter
local counter = 0
local threads = {}

-- Called once per thread
function setup(thread)
    thread:set("id", counter)
    table.insert(threads, thread)
    counter = counter + 1
end

-- Called once per thread
function init(args)
    -- Request paths to test
    requests = {
        { path = "/", method = "GET" },
        { path = "/api/health", method = "GET" },
        { path = "/api/users", method = "GET" },
        { path = "/api/status", method = "GET" },
    }

    -- POST request body
    post_body = '{"timestamp":"' .. os.date("!%Y-%m-%dT%H:%M:%SZ") .. '","data":"test"}'

    -- Thread-local request counter
    req_count = 0
end

-- Generate request
function request()
    req_count = req_count + 1

    -- Rotate through endpoints
    local idx = (req_count % #requests) + 1
    local req = requests[idx]

    -- Build headers
    local headers = {
        ["Content-Type"] = "application/json",
        ["X-Request-ID"] = string.format("wrk-%d-%d", id, req_count),
    }

    if req.method == "POST" then
        return wrk.format("POST", req.path, headers, post_body)
    else
        return wrk.format("GET", req.path, headers)
    end
end

-- Process response
function response(status, headers, body)
    if status >= 400 then
        -- Track errors (optional)
    end
end

-- Called at end of test
function done(summary, latency, requests)
    io.write("\n========================================\n")
    io.write("         PRISM LOAD TEST RESULTS        \n")
    io.write("========================================\n\n")

    io.write(string.format("Requests:     %d\n", summary.requests))
    io.write(string.format("Duration:     %.2fs\n", summary.duration / 1000000))
    io.write(string.format("Req/sec:      %.2f\n", summary.requests / (summary.duration / 1000000)))
    io.write(string.format("Transfer/sec: %.2f MB\n", (summary.bytes / (summary.duration / 1000000)) / 1024 / 1024))
    io.write("\n")

    io.write("Latency:\n")
    io.write(string.format("  Avg:   %.2fms\n", latency.mean / 1000))
    io.write(string.format("  Stdev: %.2fms\n", latency.stdev / 1000))
    io.write(string.format("  Max:   %.2fms\n", latency.max / 1000))
    io.write(string.format("  P50:   %.2fms\n", latency:percentile(50) / 1000))
    io.write(string.format("  P90:   %.2fms\n", latency:percentile(90) / 1000))
    io.write(string.format("  P99:   %.2fms\n", latency:percentile(99) / 1000))
    io.write("\n")

    if summary.errors.connect > 0 or summary.errors.read > 0 or
       summary.errors.write > 0 or summary.errors.timeout > 0 then
        io.write("Errors:\n")
        io.write(string.format("  Connect: %d\n", summary.errors.connect))
        io.write(string.format("  Read:    %d\n", summary.errors.read))
        io.write(string.format("  Write:   %d\n", summary.errors.write))
        io.write(string.format("  Timeout: %d\n", summary.errors.timeout))
    else
        io.write("Errors: None\n")
    end

    io.write("\n========================================\n")
end
