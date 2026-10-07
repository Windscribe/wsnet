#pragma once

#include <chrono>
#include <map>
#include "WSNetHttpNetworkManager.h"
#include "api/baserequest.h"

namespace wsnet {

// This request is different from all the others, so it's placed in a separate class.
// A probe tries the tunnel test domains in turn within its own timeout: a domain that answers with
// something unexpected hands what is left of the timeout to the next. A transport error ends the
// probe, since it says the tunnel rather than the domain is failing. A probe whose time ran out before
// it got to every domain leaves the next probe of that family to start from the one it did not reach.
// The domain that answered last is where the next probe starts.
// Both domains are dual-stack, so the family a probe is pinned to is the family of the exit IP it reports.
// This request is intended for connectivity tests only and it does not use a failover mechanism.
class ExitIpProbe
{
public:
    explicit ExitIpProbe(WSNetHttpNetworkManager *httpNetworkManager);
    virtual ~ExitIpProbe();

    // On success the callback's string is the exit IP; on failure it is the reason, for the log.
    void probe(IpFamily ipFamily, std::uint32_t timeoutMs, RequestFinishedCallback callback);

private:
    WSNetHttpNetworkManager *httpNetworkManager_;
    std::uint64_t curUniqueId_ = 0;

    // Forward declare instead of including skyr/url.hpp which brings conflicts to Windows
    struct EndpointsImpl;
    std::unique_ptr<EndpointsImpl> endpointsImpl_;

    // Per family: an IPv6 probe failing on a network without IPv6 says nothing about the IPv4 endpoints.
    std::map<IpFamily, std::size_t> startEndpointInd_;

    struct RequestInfo {
        RequestFinishedCallback callback;
        std::size_t curEndpointInd;
        std::size_t triedEndpoints;
        std::chrono::steady_clock::time_point deadline;
        IpFamily ipFamily;
    };
    std::map<std::uint64_t, RequestInfo> activeRequests_;

    void execute(std::uint64_t requestId, const RequestInfo &requestInfo, std::uint32_t timeoutMs);

    void onHttpNetworkRequestFinished(std::uint64_t requestId, std::uint32_t elapsedMs, std::shared_ptr<WSNetRequestError> error, const std::string &data);
};

} // namespace wsnet
