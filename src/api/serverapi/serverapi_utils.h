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

    // The one thing the HTTP status alone can decide about a response that arrived: a 5xx means
    // our API (or whatever fronts it) is there but will not serve this request right now, which
    // is retriable on the same route and must not be handed to BaseRequest::handle() as an answer.
    //
    // Every other status is passed on to handle(), where the JSON envelope decides. A non-2xx is
    // not a failure by itself -- a failed captcha comes back as 403 and a throttled caller as 429,
    // both with a perfectly valid body -- while a middlebox error page fails the envelope check on
    // any status and ends up as kIncorrectJson, which is what replaces the route.
    bool isApiUnavailableStatus(int httpStatusCode);

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
