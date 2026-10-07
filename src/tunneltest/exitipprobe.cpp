#include "exitipprobe.h"
#include <skyr/url.hpp>
#include "utils/wsnet_logger.h"
#include "utils/urlquery_utils.h"
#include "utils/utils.h"

namespace wsnet {

struct ExitIpProbe::EndpointsImpl {
    std::vector<skyr::url> endpoints;
};

ExitIpProbe::~ExitIpProbe() = default;

ExitIpProbe::ExitIpProbe(WSNetHttpNetworkManager *httpNetworkManager) : httpNetworkManager_(httpNetworkManager),
    endpointsImpl_(std::make_unique<EndpointsImpl>())
{
    auto tunnelTestEndpoints = Settings::instance().tunnelTestEndpoints();
    for (const std::string &it : tunnelTestEndpoints) {
        skyr::url url("https://" + it);
        auto &sp = url.search_parameters();
        urlquery_utils::addPlatformQueryItems(sp);
        endpointsImpl_->endpoints.push_back(url);
    }
}

void ExitIpProbe::probe(IpFamily ipFamily, std::uint32_t timeoutMs, RequestFinishedCallback callback)
{
    assert(!endpointsImpl_->endpoints.empty());
    assert(callback != nullptr);
    std::uint64_t requestId = curUniqueId_++;
    RequestInfo ri { callback, startEndpointInd_[ipFamily], 0, std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs), ipFamily };
    activeRequests_[requestId] = ri;
    execute(requestId, ri, timeoutMs);
}

void ExitIpProbe::execute(std::uint64_t requestId, const RequestInfo &requestInfo, std::uint32_t timeoutMs)
{
    auto httpRequest = httpNetworkManager_->createGetRequest(endpointsImpl_->endpoints[requestInfo.curEndpointInd].c_str(), timeoutMs, false);
    // We do not use DNS cache, as we need to verify the functionality of the connected VPN's DNS.
    httpRequest->setUseDnsCache(false);
    httpRequest->setIsWhiteListIps(false);
    httpRequest->setIpFamily(requestInfo.ipFamily);

    using namespace std::placeholders;
    httpNetworkManager_->executeRequestEx(httpRequest, requestId, std::bind(&ExitIpProbe::onHttpNetworkRequestFinished, this, _1, _2, _3, _4));
}

void ExitIpProbe::onHttpNetworkRequestFinished(std::uint64_t requestId, std::uint32_t elapsedMs, std::shared_ptr<WSNetRequestError> error, const std::string &data)
{
    // DNS and a TLS handshake through a tunnel do not fit in less, so a shorter remainder is not worth a request.
    constexpr std::int64_t kMinNextEndpointTimeoutMs = 500;

    auto it = activeRequests_.find(requestId);
    assert(it != activeRequests_.end());

    if (it->second.callback->isCanceled()) {
        activeRequests_.erase(it);
        return;
    }

    RequestInfo &info = it->second;
    const auto endpointCount = endpointsImpl_->endpoints.size();
    const bool isIpv6 = info.ipFamily == IpFamily::kIpv6;
    const std::string domain = endpointsImpl_->endpoints[info.curEndpointInd].domain()->c_str();
    if (!error->isSuccess()) {
        info.callback->call(ApiRetCode::kNetworkError, domain + ": " + error->toString());
        activeRequests_.erase(it);
        return;
    }

    auto trimmedData = utils::trim(data);
    // Extract HTTP response code from the error object. It must be 200 and returned data must be a valid IP address
    // of the family the request was pinned to.
    const bool isIpOfFamily = isIpv6 ? utils::isIpv6Address(trimmedData) : utils::isIpAddress(trimmedData);
    if (error->httpResponseCode() == 200 && isIpOfFamily) {
        startEndpointInd_[info.ipFamily] = info.curEndpointInd;
        info.callback->call(ApiRetCode::kSuccess, trimmedData);
        activeRequests_.erase(it);
        return;
    }
    const std::string failure = error->httpResponseCode() != 200 ? domain + ": HTTP " + std::to_string(error->httpResponseCode())
                                                                 : domain + ": body is not an " + (isIpv6 ? "ipv6" : "ipv4") + " address";

    ++info.triedEndpoints;
    const std::size_t nextEndpointInd = (info.curEndpointInd + 1) % endpointCount;
    const std::int64_t remainingMs = std::chrono::duration_cast<std::chrono::milliseconds>(info.deadline - std::chrono::steady_clock::now()).count();
    if (info.triedEndpoints < endpointCount && remainingMs >= kMinNextEndpointTimeoutMs) {
        info.curEndpointInd = nextEndpointInd;
        g_logger->info("Tunnel test probe {}: {}, trying next endpoint {} with {} ms left", isIpv6 ? "ipv6" : "ipv4", failure,
                       endpointsImpl_->endpoints[nextEndpointInd].domain()->c_str(), remainingMs);
        execute(requestId, info, static_cast<std::uint32_t>(remainingMs));
        return;
    }
    // After a full round this wraps back to where the probe started; after a probe cut short it is
    // the endpoint it never reached.
    startEndpointInd_[info.ipFamily] = nextEndpointInd;
    info.callback->call(ApiRetCode::kNetworkError, failure);
    activeRequests_.erase(it);
}


} // namespace wsnet

