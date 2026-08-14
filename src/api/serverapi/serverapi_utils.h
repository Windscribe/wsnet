#pragma once

#include <chrono>
#include <optional>
#include "WSNetHttpNetworkManager.h"
#include "failover/failoverdata.h"
#include "../baserequest.h"

namespace wsnet {

namespace serverapi_utils {
    std::shared_ptr<WSNetHttpRequest> createHttpRequestWithFailoverParameters(WSNetHttpNetworkManager *httpNetworkManager, const FailoverData &failoverData, BaseRequest *request,
                                                                          bool bIgnoreSslErrors, bool isAPIExtraTLSPadding);

    // How a response that completed at the transport level must be treated.
    // WSNetRequestError::isSuccess() only reports the curl code, i.e. that the bytes arrived;
    // the HTTP status is what says whether those bytes are an answer from our API.
    enum class HttpStatusVerdict {
        // 2xx: the body is the API's answer, hand it to BaseRequest::handle().
        kUsable,
        // 429 or 5xx: our API was reached over this route but will not serve the request right
        // now. Retriable on the same route, paced by the caller's exponential backoff.
        kApiUnavailable,
        // Anything else -- 3xx (we deliberately do not follow redirects), 4xx, or no status at
        // all: whatever answered is not serving our API here. Typical sources are a fronting
        // CDN that does not know our Host, a captive portal or a censoring middlebox, so the
        // route has to be replaced rather than retried.
        kRouteBroken
    };

    HttpStatusVerdict verdictForHttpStatus(int httpStatusCode);

    // 502/503/504 can come just as well from an overloaded backend of ours as from a fronting
    // CDN whose backend mapping broke, and nothing in the response tells the two apart. We
    // start out believing the first reading -- kApiUnavailable keeps the current route, which
    // is what stops an outage from turning into a re-probe storm -- and give it up once the
    // route has produced nothing but such answers for a whole doubt window.
    class ApiUnavailableWindow
    {
    public:
        explicit ApiUnavailableWindow(std::chrono::steady_clock::duration doubtWindow) :
            doubtWindow_(doubtWindow) {}

        // Records an "API unavailable" answer. Returns true once the doubt window has elapsed
        // without a single usable answer in between, i.e. the caller should stop retrying this
        // route and re-probe instead. The window restarts on escalation, so a route that stays
        // broken costs one re-probe per window rather than one per answer.
        bool addAndCheckElapsed(std::chrono::steady_clock::time_point now)
        {
            if (!since_.has_value()) {
                since_ = now;
                return false;
            }
            if (now - *since_ <= doubtWindow_)
                return false;
            since_ = now;
            return true;
        }

        // Call when the route produced a usable answer, or when the route itself is replaced.
        void reset() { since_.reset(); }

    private:
        std::chrono::steady_clock::duration doubtWindow_;
        std::optional<std::chrono::steady_clock::time_point> since_;
    };
}

} // namespace wsnet
