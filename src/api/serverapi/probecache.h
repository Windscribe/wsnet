#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <string>

#include "failover/failoverdata.h"

namespace wsnet {

// Remembers, per failover UID, that a failover was validated (won a probe or
// served a successful user-request) together with an independent freshness TTL.
// This lets ServerAPI_impl skip the full parallel myIP fan-out when only the
// FailoverData TTL (ECH config / dynamic domain) has elapsed while the route
// itself is still known to be reachable -- in that case we just refresh the
// single failover's discovery (fast path) instead of probing everything again.
//
// Not thread safe: all methods must be invoked from the io_context's thread.
class ProbeCache
{
public:
    void put(const std::string &failoverUid, FailoverData failoverData, std::chrono::seconds ttl)
    {
        Entry entry;
        entry.data = std::move(failoverData);
        entry.expiry = std::chrono::steady_clock::now() + ttl;
        entries_[failoverUid] = std::move(entry);
    }

    // Returns the cached FailoverData if the entry exists and has not expired.
    // Prunes the entry on a stale hit.
    std::optional<FailoverData> getFresh(const std::string &failoverUid)
    {
        auto it = entries_.find(failoverUid);
        if (it == entries_.end())
            return std::nullopt;
        if (std::chrono::steady_clock::now() >= it->second.expiry) {
            entries_.erase(it);
            return std::nullopt;
        }
        return it->second.data;
    }

    void invalidate(const std::string &failoverUid)
    {
        entries_.erase(failoverUid);
    }

    void clear()
    {
        entries_.clear();
    }

private:
    struct Entry {
        FailoverData data;
        std::chrono::steady_clock::time_point expiry;
    };
    std::map<std::string, Entry> entries_;
};

} // namespace wsnet
