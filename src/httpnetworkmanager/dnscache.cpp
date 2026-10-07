#include "dnscache.h"
#include <assert.h>
#include "utils/wsnet_logger.h"
#include "utils/requesterror.h"

namespace wsnet {

DnsCache::DnsCache(WSNetDnsResolver *dnsResolver, DnsCacheCallback callback) :
    dnsResolver_(dnsResolver), callback_(callback)
{
}

DnsCache::~DnsCache()
{
    std::lock_guard locker(mutex_);
    for (auto &it : activeRequests_) {
        it.second->cancel();
    }
}

DnsCacheResult DnsCache::resolve(std::uint64_t id, const std::string &hostname, IpFamily ipFamily, bool bypassCache)
{
    std::lock_guard locker(mutex_);
    assert(activeRequests_.find(id) == activeRequests_.end());

    if (!bypassCache) {
        auto it = cache_.find({hostname, ipFamily});
        if (it != cache_.end()) {
            return DnsCacheResult { id, true, it->second, 0, RequestError::createCaresSuccess() };
        }
    }
    auto asyncRequest = dnsResolver_->lookup(hostname, id, ipFamily, std::bind(&DnsCache::onDnsResolved, this, std::placeholders::_1, std::placeholders::_2, ipFamily, std::placeholders::_3));
    activeRequests_[id] = asyncRequest;
    return DnsCacheResult { id, false, std::vector<std::string>(), 0, RequestError::createCaresSuccess() };
}

void DnsCache::clear()
{
    std::lock_guard locker(mutex_);
    cache_.clear();
    g_logger->info("Clear DNS cache");
}

void DnsCache::onDnsResolved(std::uint64_t id, const std::string &hostname, IpFamily ipFamily, std::shared_ptr<WSNetDnsRequestResult> result)
{
    std::lock_guard locker(mutex_);
    auto it = activeRequests_.find(id);
    assert(it != activeRequests_.end());

    if (result->error()->isSuccess()) {
        cache_[{hostname, ipFamily}] = result->ips();
    } else {
        cache_.erase({hostname, ipFamily});
    }
    callback_(DnsCacheResult { id, false, result->ips(), result->elapsedMs(), result->error() } );

    activeRequests_.erase(it);
}

} // namespace wsnet

