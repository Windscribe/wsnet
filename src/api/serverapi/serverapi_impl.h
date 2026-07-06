#pragma once

#include "WSNetServerAPI.h"
#include <boost/asio.hpp>
#include <chrono>
#include <mutex>
#include <queue>
#include <map>
#include <optional>
#include <atomic>
#include "WSNetHttpNetworkManager.h"
#include "WSNetAdvancedParameters.h"
#include "../baserequest.h"
#include "connectstate.h"
#include "failover/ifailovercontainer.h"
#include "failover/failoverdata.h"
#include "failoverprobeexecutor.h"
#include "probecache.h"
#include "utils/cancelablecallback.h"
#include "utils/persistentsettings.h"
#include "connectstate.h"
#include "failedfailovers.h"

namespace wsnet {

class ServerAPI_impl
{
public:
    explicit ServerAPI_impl(boost::asio::io_context &io_context,
                            WSNetHttpNetworkManager *httpNetworkManager, IFailoverContainer *failoverContainer,
                            PersistentSettings &persistentSettings, WSNetAdvancedParameters *advancedParameters, std::shared_ptr<ConnectState> connectState);
    virtual ~ServerAPI_impl();

    void setApiResolutionsSettings(const std::string &apiRoot, const std::string &assetsRoot);
    void setIgnoreSslErrors(bool bIgnore);
    void resetFailover();
    void setIsConnectedToVpnState(bool isConnected);

    // Registers a callback fired once when the parallel backup-domain search starts
    // (i.e. when the fast path is exhausted and startProbe() begins). It is a plain status
    // signal (no arguments) so the client can show "searching for backup domains"
    void setTryingBackupEndpointCallback(std::shared_ptr<CancelableCallback<WSNetTryingBackupEndpointCallback>> tryingBackupEndpointCallback);

    void executeRequest(std::unique_ptr<BaseRequest> request);

private:
    // NOTE: fields are ordered to minimize struct padding (clang-analyzer-optin.performance.Padding).
    // Keep large/aligned members first and group the small bool/enum flags at the end.
    // The constructor initializer list must follow this same order to avoid -Wreorder.
    boost::asio::io_context &io_context_;
    WSNetHttpNetworkManager *httpNetworkManager_;
    WSNetAdvancedParameters *advancedParameters_;
    IFailoverContainer *failoverContainer_;

    std::uint64_t curUniqueId_ = 0;     // for generate unique identifiers for HTTP-requests

    PersistentSettings &persistentSettings_;    // The ServerAPISettings class is protected by mutex, so it's thread-safe

    // Fast path discovery state (resolving the persisted failover before running user requests).
    std::unique_ptr<BaseFailover> fastPathFailover_;
    // Probe executor (parallel myIP search) used when the fast path is unavailable or has failed.
    std::unique_ptr<FailoverProbeExecutor> probeExecutor_;

    std::shared_ptr<ConnectState> connectState_;
    std::shared_ptr<CancelableCallback<WSNetTryingBackupEndpointCallback>> tryingBackupEndpointCallback_ = nullptr;

    struct HttpRequestInfo {
        std::unique_ptr<BaseRequest> request;
        std::shared_ptr<WSNetCancelableCallback> asyncCallback_;
        bool bFromDisconnectedVPNState_;
        bool bDiscard;
        // Captured at send time: the failover this request was sent to was selected via the
        // fast path and not yet confirmed by a successful request. A failure (even a DNS
        // error) on such a request must fall back to the probe rather than return an error.
        bool bFastPathUnconfirmed_;
        // The FailoverData this request was actually sent with. Recorded into
        // failedFailovers_ on failure so the subsequent probe does not immediately
        // reselect a failover that answers myIP but keeps failing real requests.
        FailoverData failoverData_;
    };
    std::map<std::uint64_t, HttpRequestInfo> activeHttpRequests_;

    // Stage 2: remembers recently-validated failovers so that an expired FailoverData
    // (ECH config / dynamic domain TTL) can be refreshed via the single-failover fast
    // path instead of a full parallel probe fan-out.
    ProbeCache probeCache_;
    // Time window during which a validated failover is trusted for the expiry fast-path.
    static constexpr std::chrono::seconds kProbeCacheTtl{15 * 60};
    // Set in executeRequest() when an expired-but-cache-fresh failover should be refreshed
    // through the fast path on this turn; consumed by the discovery dispatch below.
    std::string pendingExpiredRefreshUid_;

    FailedFailovers failedFailovers_;

    std::deque<std::unique_ptr<BaseRequest>> queueRequests_;    // a queue of requests waiting for failover detection (probe / fast path)

    ApiOverrideSettings apiOverrideSettings_;

    std::optional<FailoverData> failoverData_;      // valid only in kReady state

    // Current failover state.
    enum class FailoverState { kUnknown, kReady, kFailed } failoverState_;

    bool bIgnoreSslErrors_ = false;
    bool isConnectedToVpn_ = false;

    // Fast path: per-session flag preventing the persisted UID from being re-attempted
    // after the first try (success or failure) -- subsequent unknowns go through probe.
    bool triedPersistedThisSession_ = false;

    // True when the current kReady failover was selected via the fast path (persisted or
    // primary) but has not yet been confirmed by a successful user-request. Unlike a
    // probe-selected failover, a fast-path domain is used without first validating it with
    // a myIP probe, so while it is unconfirmed ANY user-request failure (including a DNS
    // resolution error) must fall back to the parallel probe instead of being treated as a
    // transient local network problem.
    bool currentFailoverUnconfirmed_ = false;

    bool fastPathInProgress_ = false;
    bool fastPathConnectStateAtStart_ = false;

    bool isFailoverFailedLogAlreadyDone_ = false;   // log "failover failed: API not ready" only once to avoid spam
    bool bWasSuccesfullRequest_ = false;    // was at least one successful request?

    void executeRequest(std::uint64_t requestId);
    void executeRequestImpl(std::unique_ptr<BaseRequest> request, const FailoverData &failoverData);
    void executeWaitingInQueueRequests();
    std::string hostnameForConnectedState() const;
    void setErrorCodeAndEmitRequestFinished(BaseRequest *request, ServerApiRetCode retCode);

    void startFastPath(const std::string &failoverUid);
    void onFastPathDiscovery(FailoverResult result, const std::vector<FailoverData> &data);
    void startProbe();
    void onProbeFinished(FailoverProbeResult result, FailoverProbeWinner winner);

    void onHttpNetworkRequestFinished(std::uint64_t requestId, std::uint32_t elapsedMs, std::shared_ptr<WSNetRequestError> error, const std::string &data);
    // This callback function is necessary to cancel the request as quickly as possible if it was canceled on the calling side
    void onHttpNetworkRequestProgressCallback(std::uint64_t requestId, std::uint64_t bytesReceived, std::uint64_t bytesTotal);

    // fullReset == true for externally requested resets (clears triedPersistedThisSession_);
    // fullReset == false for internal recovery after a user-request failure on the
    // currently selected failover (the session is allowed to fall back to probe directly).
    void resetFailoverImpl(bool fullReset);

    void logAllFailoversFailed(BaseRequest *request);
    void failAllQueuedRequests(ServerApiRetCode retCode);
};

} // namespace wsnet
