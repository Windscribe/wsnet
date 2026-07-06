#include "serverapi_impl.h"
#include "utils/wsnet_logger.h"
#include "settings.h"
#include "serverapi_utils.h"

namespace wsnet {

namespace {

// Structured log prefix used for failover/probe metrics.
constexpr const char *kFoMetricTag = "[fo-metric]";

} // namespace

ServerAPI_impl::ServerAPI_impl(boost::asio::io_context &io_context,
                               WSNetHttpNetworkManager *httpNetworkManager, IFailoverContainer *failoverContainer, PersistentSettings &persistentSettings,
                               WSNetAdvancedParameters *advancedParameters, std::shared_ptr<ConnectState> connectState) :
    io_context_(io_context),
    httpNetworkManager_(httpNetworkManager),
    advancedParameters_(advancedParameters),
    failoverContainer_(failoverContainer),
    persistentSettings_(persistentSettings),
    connectState_(connectState),
    failoverState_(FailoverState::kUnknown)
{
    // If we have a persisted failover UID, the first user-request will use it directly
    // (fast path, no probe). Otherwise, default to the primary (first) failover so the
    // first request tries it alone via the fast path before falling back to the parallel
    // probe. If the primary fails, resetFailoverImpl() clears the UID and the next attempt
    // runs the full probe.
    if (persistentSettings_.failoverId().empty()) {
        auto primary = failoverContainer_->first();
        g_logger->info("ServerAPI_impl::ServerAPI_impl, no persisted failover, primary failover will be tried first uid={}",
                       primary->uniqueId());
        persistentSettings_.setFailoverId(primary->uniqueId());
    } else {
        g_logger->info("ServerAPI_impl::ServerAPI_impl, fast-path will be tried for persisted failover uid={}",
                       persistentSettings_.failoverId());
    }
}

ServerAPI_impl::~ServerAPI_impl()
{
    if (probeExecutor_) {
        probeExecutor_->cancel();
        probeExecutor_.reset();
    }
    for (auto &it : activeHttpRequests_) {
        it.second.asyncCallback_->cancel();
    }
}

void ServerAPI_impl::setApiResolutionsSettings(const std::string &apiRoot, const std::string &assetsRoot)
{
    apiOverrideSettings_.apiRoot = apiRoot;
    apiOverrideSettings_.assetsRoot = assetsRoot;
    if (!apiOverrideSettings_.isOverriden()) {
        g_logger->info("ServerAPI_impl::setApiResolutionsSettings, default behavior, no overridden domains");
    } else {
        g_logger->info("ServerAPI_impl::setApiResolutionsSettings, overridden domains are set, apiRoot = {}, assetsRoot = {}", apiRoot, assetsRoot);
    }
}

void ServerAPI_impl::setIgnoreSslErrors(bool bIgnore)
{
    if (!bIgnoreSslErrors_ && bIgnore && failoverState_ != FailoverState::kReady) {
        // User turned on ignore SSL errors.  If the API is currently not ready, reset failover
        resetFailover();
    }
    bIgnoreSslErrors_ = bIgnore;
    g_logger->info("ServerAPI_impl::setIgnoreSslErrors, {}", bIgnore);
}

void ServerAPI_impl::resetFailover()
{
    g_logger->info("ServerAPI_impl::resetFailover");
    resetFailoverImpl(true);
    // Drain the queue so any waiting requests get re-evaluated after the reset
    // (will re-trigger a probe).
    executeWaitingInQueueRequests();
}

void ServerAPI_impl::setIsConnectedToVpnState(bool isConnected)
{
    isConnectedToVpn_ = isConnected;
    if (probeExecutor_)
        probeExecutor_->setIsConnectedToVpnState(isConnected);
}

void ServerAPI_impl::setTryingBackupEndpointCallback(std::shared_ptr<CancelableCallback<WSNetTryingBackupEndpointCallback> > tryingBackupEndpointCallback)
{
    tryingBackupEndpointCallback_ = tryingBackupEndpointCallback;
}

void ServerAPI_impl::executeRequest(std::unique_ptr<BaseRequest> request)
{
    //if request already canceled do nothing
    if (request->isCanceled()) {
        return;
    }
    request->setApiOverrideSettings(apiOverrideSettings_);

    // check if we are online
    if (!connectState_->isOnline()) {
        request->setRetCode(ServerApiRetCode::kNoNetworkConnection);
        request->callCallback();
        executeWaitingInQueueRequests();
        return;
    }

    // if API resolution settings overrides the domain of the current request then we use that domain immediately
    if (request->isApiDomainOverriden()) {
        // In this case FailoverData will be empty, because the domain itself is already contained in the request
        executeRequestImpl(std::move(request), FailoverData());
        executeWaitingInQueueRequests();
        return;
    }

    if (isConnectedToVpn_) {
        // in the connected mode always use the primary domain
        executeRequestImpl(std::move(request), FailoverData(hostnameForConnectedState()));
        executeWaitingInQueueRequests();
        return;
    }

    // Expire the cached failover if its TTL has elapsed (ECH config, dynamic domain).
    if (failoverState_ == FailoverState::kReady && failoverData_.has_value() && failoverData_->isExpired()) {
        g_logger->info("The current failover domain is expired. Reset the failover state.");
        const std::string expiredUid = persistentSettings_.failoverId();
        failoverState_ = FailoverState::kUnknown;
        failoverData_.reset();

        // Only the FailoverData TTL (ECH config / dynamic domain)
        // has elapsed. If the probe cache still considers this failover fresh, the route
        // itself is believed reachable, so refresh just this one failover via the fast
        // path instead of re-probing every candidate.
        if (!expiredUid.empty() && probeCache_.getFresh(expiredUid).has_value()) {
            g_logger->debug("{} event=expired_refresh uid={} (probe cache fresh, skipping full probe)",
                            kFoMetricTag, expiredUid);
            pendingExpiredRefreshUid_ = expiredUid;
        }
    }

    if (failoverState_ == FailoverState::kReady) {
        assert(failoverData_.has_value());
        executeRequestImpl(std::move(request), *failoverData_);
        return;
    }

    if (failoverState_ == FailoverState::kFailed) {
        logAllFailoversFailed(request.get());
        request->setRetCode(ServerApiRetCode::kFailoverFailed);
        request->callCallback();
        return;
    }

    // failoverState_ == kUnknown: queue the request and start discovery (fast path or probe).
    // Take priority into account so that wgConfigsInit/wgConfigsConnect/pingTest get drained first.
    if (request->priority() == RequestPriority::kHigh)
        queueRequests_.push_front(std::move(request));
    else
        queueRequests_.push_back(std::move(request));

    if (fastPathInProgress_ || probeExecutor_) {
        return;  // discovery already in progress; the queued request will be processed when it completes.
    }

    if (!pendingExpiredRefreshUid_.empty()) {
        // The current failover's TTL expired but its probe cache is still fresh.
        // Refresh only that failover (single getData) rather than re-probing everything.
        const std::string uid = pendingExpiredRefreshUid_;
        pendingExpiredRefreshUid_.clear();
        startFastPath(uid);
    } else if (!persistentSettings_.failoverId().empty() && !triedPersistedThisSession_) {
        triedPersistedThisSession_ = true;
        startFastPath(persistentSettings_.failoverId());
    } else {
        startProbe();
    }
}

void ServerAPI_impl::executeRequestImpl(std::unique_ptr<BaseRequest> request, const FailoverData &failoverData)
{
    using namespace std::placeholders;
    auto httpRequest = serverapi_utils::createHttpRequestWithFailoverParameters(httpNetworkManager_, failoverData, request.get(), bIgnoreSslErrors_, advancedParameters_->isAPIExtraTLSPadding());
    httpRequest->setIsDebugLogCurlError(true);
    std::uint64_t requestId = curUniqueId_++;
    auto asyncCallback_ = httpNetworkManager_->executeRequestEx(httpRequest, requestId, std::bind(&ServerAPI_impl::onHttpNetworkRequestFinished, this, _1, _2, _3, _4),
                                                           std::bind(&ServerAPI_impl::onHttpNetworkRequestProgressCallback, this, _1, _2, _3));
    HttpRequestInfo hti { std::move(request), asyncCallback_, !isConnectedToVpn_, false, currentFailoverUnconfirmed_, failoverData};
    activeHttpRequests_[requestId] = std::move(hti);
}

void ServerAPI_impl::executeWaitingInQueueRequests()
{
    // We need a copy here because executeRequest can add requests to queueRequests_ to avoid an infinite loop
    std::deque<std::unique_ptr<BaseRequest>> copyQueueRequests = std::move(queueRequests_);
    queueRequests_.clear();
    while (!copyQueueRequests.empty()) {
        std::unique_ptr<BaseRequest> req = std::move(copyQueueRequests.front());
        copyQueueRequests.pop_front();
        executeRequest(std::move(req));
    }
}

std::string ServerAPI_impl::hostnameForConnectedState() const
{
    return Settings::instance().primaryServerDomain();
}

void ServerAPI_impl::setErrorCodeAndEmitRequestFinished(BaseRequest *request, ServerApiRetCode retCode)
{
    request->setRetCode(retCode);
    request->callCallback();
}

void ServerAPI_impl::startFastPath(const std::string &failoverUid)
{
    using namespace std::placeholders;

    auto failover = failoverContainer_->failoverById(failoverUid);
    if (!failover) {
        g_logger->info("ServerAPI_impl::startFastPath, persisted UID {} not found, falling back to probe", failoverUid);
        probeCache_.invalidate(failoverUid);
        persistentSettings_.setFailoverId("");
        startProbe();
        return;
    }

    g_logger->debug("{} event=fastpath_start uid={} name={}",
                    kFoMetricTag, failover->uniqueId(), failover->name());

    fastPathFailover_ = std::move(failover);
    fastPathInProgress_ = true;
    fastPathConnectStateAtStart_ = isConnectedToVpn_;

    std::vector<FailoverData> data;
    const bool syncResult = fastPathFailover_->getData(
        bIgnoreSslErrors_, data,
        std::bind(&ServerAPI_impl::onFastPathDiscovery, this, _1, _2));

    if (syncResult) {
        onFastPathDiscovery(FailoverResult::kSuccess, data);
    }
}

void ServerAPI_impl::onFastPathDiscovery(FailoverResult result, const std::vector<FailoverData> &data)
{
    if (!fastPathInProgress_) return;  // we got canceled (e.g. via resetFailover)
    fastPathInProgress_ = false;
    auto failoverUid = fastPathFailover_ ? fastPathFailover_->uniqueId() : std::string();
    auto failoverName = fastPathFailover_ ? fastPathFailover_->name() : std::string();
    fastPathFailover_.reset();

    if (fastPathConnectStateAtStart_ != isConnectedToVpn_) {
        g_logger->debug("{} event=fastpath_end uid={} result=connect_state_changed",
                        kFoMetricTag, failoverUid);
        // VPN state changed while resolving; re-process queue so requests pick the new branch.
        executeWaitingInQueueRequests();
        return;
    }

    if (result != FailoverResult::kSuccess || data.empty()) {
        g_logger->debug("{} event=fastpath_end uid={} result=failed",
                        kFoMetricTag, failoverUid);
        // Persisted failover did not resolve; clear it and fall back to probe.
        probeCache_.invalidate(failoverUid);
        persistentSettings_.setFailoverId("");
        startProbe();
        return;
    }

    FailoverData winnerData;
    bool found = false;
    for (const auto &candidate : data) {
        if (!failedFailovers_.isContains(candidate)) {
            winnerData = candidate;
            found = true;
            break;
        }
    }
    if (!found) {
        g_logger->debug("{} event=fastpath_end uid={} result=all_candidates_already_failed",
                        kFoMetricTag, failoverUid);
        probeCache_.invalidate(failoverUid);
        persistentSettings_.setFailoverId("");
        startProbe();
        return;
    }

    g_logger->info("Fast path selected persisted failover: {}", failoverName);
    g_logger->debug("{} event=fastpath_end uid={} result=ok domain={}",
                    kFoMetricTag, failoverUid, winnerData.domain());

    failoverState_ = FailoverState::kReady;
    failoverData_ = winnerData;
    // The fast path uses this domain without a validating myIP probe, so it stays
    // unconfirmed until a real user-request succeeds on it. If the very first request
    // fails (even with a DNS error), onHttpNetworkRequestFinished() falls back to the probe.
    currentFailoverUnconfirmed_ = true;
    // Refresh the probe cache so a later TTL expiry can reuse the fast path.
    probeCache_.put(failoverUid, winnerData, kProbeCacheTtl);
    // persistentSettings_.failoverId() stays as the same UID (no change needed).
    executeWaitingInQueueRequests();
}

void ServerAPI_impl::startProbe()
{
    using namespace std::placeholders;

    std::vector<std::unique_ptr<BaseFailover>> failovers;
    for (const auto &uid : failoverContainer_->allUids()) {
        auto fo = failoverContainer_->failoverById(uid);
        if (fo) failovers.push_back(std::move(fo));
    }

    g_logger->debug("{} event=probe_executor_start failovers={}", kFoMetricTag, failovers.size());

    // Notify the client that the backup-domain search has started. This is a plain status
    // signal (no progress counters): the parallel probe tries domains concurrently and
    // stops at the first working one, so a meaningful "N of M" cannot be reported.
    if (tryingBackupEndpointCallback_)
        tryingBackupEndpointCallback_->call();

    probeExecutor_ = std::make_unique<FailoverProbeExecutor>(
        io_context_, httpNetworkManager_, std::move(failovers),
        bIgnoreSslErrors_, isConnectedToVpn_, advancedParameters_, failedFailovers_,
        std::bind(&ServerAPI_impl::onProbeFinished, this, _1, _2));
    probeExecutor_->start();
}

void ServerAPI_impl::onProbeFinished(FailoverProbeResult result, FailoverProbeWinner winner)
{
    // Move the executor out so it gets destroyed at the end of this function (or later
    // if a re-entrant call captures it). This avoids destroying the executor while we
    // are still inside one of its callbacks.
    auto executorCopy = std::move(probeExecutor_);
    probeExecutor_.reset();

    switch (result) {
    case FailoverProbeResult::kSuccess: {
        g_logger->info("Probe selected failover uid={} domain={} elapsed_ms={}", winner.failoverUid, winner.failoverData.domain(), winner.elapsedMs);
        failoverState_ = FailoverState::kReady;
        failoverData_ = winner.failoverData;
        // The probe validated this failover with a real myIP request, so it is confirmed.
        currentFailoverUnconfirmed_ = false;
        persistentSettings_.setFailoverId(winner.failoverUid);
        // Remember this validated failover so an expired FailoverData can later be
        // refreshed via the fast path instead of a full probe.
        probeCache_.put(winner.failoverUid, winner.failoverData, kProbeCacheTtl);
        executeWaitingInQueueRequests();
        break;
    }
    case FailoverProbeResult::kAllFailed: {
        if (bWasSuccesfullRequest_) {
            // Same recovery semantics as the previous sequential failover: we know the
            // backend can be reached (we've succeeded before), so do not enter kFailed.
            // Just clear state, fail current queue with kNetworkError, and let the client retry.
            g_logger->info("Probe: all failovers failed but session had prior success, resetting");
            resetFailoverImpl(false);
            // Every failover was just tried and failed; start the next attempt from a clean
            // slate so previously-failed routes can be retried (the backend is reachable).
            failedFailovers_.clear();
            failAllQueuedRequests(ServerApiRetCode::kNetworkError);
        } else {
            failoverState_ = FailoverState::kFailed;
            if (!isFailoverFailedLogAlreadyDone_) {
                g_logger->info("Probe: all failovers failed, API not ready");
                isFailoverFailedLogAlreadyDone_ = true;
            }
            failAllQueuedRequests(ServerApiRetCode::kFailoverFailed);
        }
        break;
    }
    case FailoverProbeResult::kConnectStateChanged: {
        // VPN state flipped while probing. Re-evaluate every queued request so it
        // takes the appropriate branch (primary domain in connected state).
        executeWaitingInQueueRequests();
        break;
    }
    case FailoverProbeResult::kNoNetwork: {
        // Connectivity was lost during discovery/probing (e.g. connectState reported online
        // but the network actually dropped). This is a retriable condition, not a failover
        // failure: keep failoverState_ == kUnknown so the next request re-probes, and report
        // kNoNetworkConnection rather than kFailoverFailed ("API not ready").
        failAllQueuedRequests(ServerApiRetCode::kNoNetworkConnection);
        break;
    }
    }
}

void ServerAPI_impl::onHttpNetworkRequestFinished(std::uint64_t requestId, std::uint32_t elapsedMs, std::shared_ptr<WSNetRequestError> error, const std::string &data)
{
    auto it = activeHttpRequests_.find(requestId);
    assert(it != activeHttpRequests_.end());

    if (it->second.request->isCanceled()) {
        activeHttpRequests_.erase(it);
        return;
    }

    if (error->isSuccess()) {
        if (advancedParameters_->isLogApiResponce()) {
            g_logger->info("API request {} finished", it->second.request->name());
            g_logger->info("{}", data);
        }
        it->second.request->handle(data);
        // handle() may cause the retcode to change.  Only call callback here if it's still successful.
        if (it->second.request->retCode() == ServerApiRetCode::kSuccess) {
            bWasSuccesfullRequest_ = true;
            // The failover served a successful request; it is now confirmed and a later
            // transient DNS error on it should no longer force a full re-probe.
            currentFailoverUnconfirmed_ = false;
            // Propagate the confirmation to sibling requests already in flight on this same
            // fast-path failover. Each HttpRequestInfo captured bFastPathUnconfirmed_ at send
            // time; without clearing it here, a transient DNS error on one of those siblings
            // would still see its stale snapshot==true and tear down a now-confirmed working
            // failover, triggering a spurious full re-probe.
            for (auto &req : activeHttpRequests_) {
                req.second.bFastPathUnconfirmed_ = false;
            }
            // A successful user-request is the strongest signal that the current failover
            // works; extend its probe-cache freshness so a later TTL expiry stays on the
            // fast path.
            if (failoverState_ == FailoverState::kReady && failoverData_.has_value()
                && !persistentSettings_.failoverId().empty()) {
                probeCache_.put(persistentSettings_.failoverId(), *failoverData_, kProbeCacheTtl);
            }
            it->second.request->callCallback();
            activeHttpRequests_.erase(it);
            return;
        }
    } else if (error->isNoNetworkError()) {
        g_logger->info("API request {} failed with error = {}", it->second.request->name(), error->toString());
        setErrorCodeAndEmitRequestFinished(it->second.request.get(), ServerApiRetCode::kNoNetworkConnection);
        activeHttpRequests_.erase(it);
        return;
    }

    // Either error->isSuccess() is false or the retcode was changed to kIncorrectJson by handle().
    g_logger->info("API request {} failed with error = {}", it->second.request->name(), error->toString());

    // We need to start going through the backup domains again (via the parallel probe).
    // A DNS resolve error normally does NOT trigger this -- on an already-confirmed failover
    // it is treated as a transient local network problem. The exception is a failover that
    // was selected via the fast path and has not yet been confirmed by a successful request:
    // in that case a DNS error means the fast-path domain is unusable and we must fall back
    // to the probe instead of returning kNetworkError (otherwise a blocked/bad primary or
    // persisted domain would never fail over).
    const bool shouldReprobe = !error->isDnsError()
                               || it->second.request->retCode() == ServerApiRetCode::kIncorrectJson
                               || it->second.bFastPathUnconfirmed_;
    if (it->second.bFromDisconnectedVPNState_ && shouldReprobe) {

        if (!it->second.bDiscard) {
            // Record the failover that just failed BEFORE resetting. A failover may keep
            // answering the myIP probe while consistently failing real requests (e.g.
            // kIncorrectJson on a specific endpoint); without this it would win the next
            // probe again and we would loop on it forever, never trying lower-priority
            // working failovers. resetFailoverImpl(false) preserves failedFailovers_, so
            // the recorded failure carries into the upcoming probe and accumulates across
            // failover generations within this session.
            failedFailovers_.add(it->second.failoverData_);
            resetFailoverImpl(false);
            g_logger->info("ServerAPI_impl::onHttpNetworkRequestFinished, reset failover");

            // mark all pending requests for discard
            for (auto &req : activeHttpRequests_) {
                req.second.bDiscard = true;
            }
        }

        // Repeat the execution of the request via failover
        executeRequest(std::move(it->second.request));

    } else {
        setErrorCodeAndEmitRequestFinished(it->second.request.get(), ServerApiRetCode::kNetworkError);
    }
    activeHttpRequests_.erase(it);
}

void ServerAPI_impl::onHttpNetworkRequestProgressCallback(std::uint64_t requestId, std::uint64_t bytesReceived, std::uint64_t bytesTotal)
{
    auto it = activeHttpRequests_.find(requestId);
    assert(it != activeHttpRequests_.end());
    if (it->second.request->isCanceled()) {
        it->second.asyncCallback_->cancel();
        activeHttpRequests_.erase(it);
    }
}

void ServerAPI_impl::resetFailoverImpl(bool fullReset)
{
    if (probeExecutor_) {
        probeExecutor_->cancel();
        probeExecutor_.reset();
    }
    // fastPathInProgress_ may be set: the async callback will see fastPathInProgress_==false
    // and bail out. Drop the failover object too so we don't keep it alive past reset.
    fastPathInProgress_ = false;
    fastPathFailover_.reset();

    failoverState_ = FailoverState::kUnknown;
    failoverData_.reset();
    currentFailoverUnconfirmed_ = false;
    persistentSettings_.setFailoverId("");

    // Drop any stale probe-cache state and pending expiry refresh; after a reset we no
    // longer trust previously-validated failovers.
    probeCache_.clear();
    pendingExpiredRefreshUid_.clear();

    // NOTE: failedFailovers_ is intentionally NOT cleared on a partial (single-failover)
    // reset. It must accumulate across reprobe generations so that a failover which keeps
    // failing real requests is not reselected on every probe. It is only cleared on a full
    // reset (external resetFailover, connectivity/VPN-state change) or explicitly by the
    // "all failed after prior success" recovery path in onProbeFinished().
    if (fullReset) {
        failedFailovers_.clear();
        triedPersistedThisSession_ = false;
        isFailoverFailedLogAlreadyDone_ = false;
    }
}

void ServerAPI_impl::logAllFailoversFailed(BaseRequest *request)
{
    if (!isFailoverFailedLogAlreadyDone_) {
        g_logger->info("API request {} failed: API not ready", request->name());
        isFailoverFailedLogAlreadyDone_ = true;
    }
}

void ServerAPI_impl::failAllQueuedRequests(ServerApiRetCode retCode)
{
    std::deque<std::unique_ptr<BaseRequest>> copy = std::move(queueRequests_);
    queueRequests_.clear();
    while (!copy.empty()) {
        auto req = std::move(copy.front());
        copy.pop_front();
        setErrorCodeAndEmitRequestFinished(req.get(), retCode);
    }
}

} // namespace wsnet
