#include "serverapi_utils.h"

namespace wsnet {

std::shared_ptr<WSNetHttpRequest> serverapi_utils::createHttpRequestWithFailoverParameters(WSNetHttpNetworkManager *httpNetworkManager, const FailoverData &failoverData, BaseRequest *request,
                                                                                           bool bIgnoreSslErrors, bool isAPIExtraTLSPadding)
{
    // Make sure the network return code is reset
    request->setRetCode(ServerApiRetCode::kSuccess);

    std::shared_ptr<WSNetHttpRequest> httpRequest;
    switch (request->requestType()) {
    case HttpMethod::kGet:
        httpRequest = httpNetworkManager->createGetRequest(request->url(failoverData.domain()), request->timeout(), bIgnoreSslErrors);
        break;
    case HttpMethod::kPost:
        httpRequest = httpNetworkManager->createPostRequest(request->url(failoverData.domain()), request->timeout(), request->postData(), bIgnoreSslErrors);
        break;
    case HttpMethod::kDelete:
        httpRequest = httpNetworkManager->createDeleteRequest(request->url(failoverData.domain()), request->timeout(), bIgnoreSslErrors);
        break;
    case HttpMethod::kPut:
        httpRequest = httpNetworkManager->createPutRequest(request->url(failoverData.domain()), request->timeout(), request->postData(), bIgnoreSslErrors);
        break;
    default:
        assert(false);
    }

    if (!request->isUseDnsCache())
        httpRequest->setUseDnsCache(false);

    if (!failoverData.echConfig().empty())
        httpRequest->setEchConfig(failoverData.echConfig());

    if (isAPIExtraTLSPadding)
        httpRequest->setExtraTLSPadding(true);

    if (!failoverData.sniDomain().empty()) {
        httpRequest->setSniDomain(failoverData.sniDomain());
        // Force-disable Extra Padding for CDN domains
        httpRequest->setExtraTLSPadding(false);
    }

    // Add Authorization header if bearer token is present
    if (!request->bearerToken().empty()) {
        httpRequest->addHttpHeader("Authorization: Bearer " + request->bearerToken());
    }
    return httpRequest;
}

serverapi_utils::HttpStatusVerdict serverapi_utils::verdictForHttpStatus(int httpStatusCode)
{
    // The whole 2xx range, not a strict 200: assets and non-JSON endpoints may legitimately
    // answer 204/206, and treating those as an error would break requests that work today.
    if (httpStatusCode >= 200 && httpStatusCode < 300)
        return HttpStatusVerdict::kUsable;

    // The only statuses a retry can plausibly fix. Everything else (a redirect we do not
    // follow, 400/401/403/404, or a response with no status line at all) will answer exactly
    // the same on the next attempt, so retrying the same route is pointless -- and 403/404 is
    // the usual signature of a fronting CDN or middlebox rather than of our API.
    if (httpStatusCode == 429 || (httpStatusCode >= 500 && httpStatusCode < 600))
        return HttpStatusVerdict::kApiUnavailable;

    return HttpStatusVerdict::kRouteBroken;
}


} // namespace wsnet
