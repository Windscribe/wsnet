#include "failoverprobeexecutor.h"

#include <algorithm>

#include "serverapi_requestsfactory.h"
#include "serverapi_utils.h"
#include "utils/cancelablecallback.h"
#include "utils/utils.h"
#include "utils/wsnet_logger.h"

namespace wsnet {

namespace {

// Structured log prefix used for failover/probe metrics.
constexpr const char *kFoMetricTag = "[fo-metric]";

} // namespace

FailoverProbeExecutor::FailoverProbeExecutor(boost::asio::io_context &io_context,
                                             WSNetHttpNetworkManager *httpNetworkManager,
                                             std::vector<std::unique_ptr<BaseFailover>> failovers,
                                             bool ignoreSslErrors,
                                             bool isConnectedToVpn,
                                             WSNetAdvancedParameters *advancedParameters,
                                             FailedFailovers &failedFailovers,
                                             FailoverProbeCallback callback) :
    io_context_(io_context),
    httpNetworkManager_(httpNetworkManager),
    advancedParameters_(advancedParameters),
    failedFailovers_(failedFailovers),
    callback_(std::move(callback)),
    ignoreSslErrors_(ignoreSslErrors),
    isConnectedToVpn_(isConnectedToVpn),
    hedgeTimer_(io_context)
{
    discovery_.reserve(failovers.size());
    for (int i = 0; i < static_cast<int>(failovers.size()); ++i) {
        auto entry = std::make_unique<DiscoveryEntry>();
        entry->failover = std::move(failovers[i]);
        entry->priorityIndex = i;
        discovery_.push_back(std::move(entry));
    }
}

FailoverProbeExecutor::~FailoverProbeExecutor()
{
    cancelAllInFlight();
    hedgeTimer_.cancel();
}

void FailoverProbeExecutor::start()
{
    startTime_ = std::chrono::steady_clock::now();
    g_logger->debug("{} event=probe_search_start failovers={}", kFoMetricTag, discovery_.size());

    if (discovery_.empty()) {
        finishWith(FailoverProbeResult::kAllFailed, {});
        return;
    }

    // Launch discovery for every failover in parallel.
    // Note: synchronous failovers (hardcoded) invoke the callback re-entrantly,
    // which may already trigger a probe before this loop ends. That's fine -- the
    // hedge timer logic gates subsequent launches. The launchingDiscoveries_ flag
    // prevents onDiscoveryCallback() from concluding "all exhausted" mid-loop when an
    // early synchronous discovery produces no usable candidate (it would otherwise
    // finish the search before the remaining failovers are launched).
    launchingDiscoveries_ = true;
    for (auto &entry : discovery_) {
        if (finished_) {
            launchingDiscoveries_ = false;
            return;
        }
        startDiscovery(entry.get());
    }
    launchingDiscoveries_ = false;

    // After kicking discovery off, check if everything was synchronous and exhausted.
    if (!finished_) {
        tryLaunchProbe();
        if (!finished_ && isAllExhausted()) {
            finishWith(exhaustedResult(), {});
        }
    }
}

void FailoverProbeExecutor::cancel()
{
    if (finished_) return;
    finished_ = true;
    cancelAllInFlight();
    hedgeTimer_.cancel();
    // Drop the callback so it is never invoked. Caller initiated cancel and owns
    // the responsibility of draining any pending state externally.
    callback_ = nullptr;
}

void FailoverProbeExecutor::setIsConnectedToVpnState(bool isConnected)
{
    if (isConnectedToVpn_ != isConnected) {
        isConnectedToVpn_ = isConnected;
        isConnectStateChanged_ = true;
    }
}

void FailoverProbeExecutor::startDiscovery(DiscoveryEntry *entry)
{
    discoveryInFlight_++;
    g_logger->debug("{} event=discovery_start uid={} name={}",
                    kFoMetricTag, entry->failover->uniqueId(), entry->failover->name());

    const int idx = entry->priorityIndex;
    std::vector<FailoverData> data;
    const bool syncResult = entry->failover->getData(
        ignoreSslErrors_, data,
        [this, idx](FailoverResult result, const std::vector<FailoverData> &data) {
            onDiscoveryCallback(idx, result, data);
        });

    if (syncResult) {
        onDiscoveryCallback(idx, FailoverResult::kSuccess, data);
    }
}

void FailoverProbeExecutor::onDiscoveryCallback(int discoveryIndex, FailoverResult result, const std::vector<FailoverData> &data)
{
    if (finished_) return;

    auto &entry = discovery_[discoveryIndex];
    if (entry->finished) return;
    entry->finished = true;
    discoveryInFlight_--;

    if (isConnectStateChanged_) {
        g_logger->debug("{} event=discovery_end uid={} result=connect_state_changed",
                        kFoMetricTag, entry->failover->uniqueId());
        finishWith(FailoverProbeResult::kConnectStateChanged, {});
        return;
    }

    if (result == FailoverResult::kSuccess) {
        g_logger->debug("{} event=discovery_end uid={} result=ok domains={}",
                        kFoMetricTag, entry->failover->uniqueId(), data.size());
        for (int sub = 0; sub < static_cast<int>(data.size()); ++sub) {
            if (failedFailovers_.isContains(data[sub])) {
                g_logger->debug("Probe: skipping already-failed candidate domain={} uid={}",
                                data[sub].domain(), entry->failover->uniqueId());
                continue;
            }
            insertPendingCandidate(discoveryIndex, sub, data[sub]);
        }
    } else if (result == FailoverResult::kNoNetwork) {
        g_logger->debug("{} event=discovery_end uid={} result=no_network",
                        kFoMetricTag, entry->failover->uniqueId());
        sawNoNetwork_ = true;
    } else {
        g_logger->debug("{} event=discovery_end uid={} result=failed",
                        kFoMetricTag, entry->failover->uniqueId());
    }

    tryLaunchProbe();
    // While start() is still launching discoveries, defer the exhausted-check: not every
    // failover has been kicked off yet, so isAllExhausted() could falsely report "all failed".
    // start() runs the authoritative check once the launch loop completes.
    if (!finished_ && !launchingDiscoveries_ && isAllExhausted()) {
        finishWith(exhaustedResult(), {});
    }
}

void FailoverProbeExecutor::insertPendingCandidate(int priorityIndex, int subIndex, const FailoverData &data)
{
    PendingCandidate c;
    c.priorityIndex = priorityIndex;
    c.subIndex = subIndex;
    c.data = data;

    auto it = std::lower_bound(pendingCandidates_.begin(), pendingCandidates_.end(), c,
                               [](const PendingCandidate &a, const PendingCandidate &b) {
                                   if (a.priorityIndex != b.priorityIndex) return a.priorityIndex < b.priorityIndex;
                                   return a.subIndex < b.subIndex;
                               });
    pendingCandidates_.insert(it, std::move(c));
}

void FailoverProbeExecutor::tryLaunchProbe()
{
    if (finished_) return;
    if (pendingCandidates_.empty()) return;
    if (static_cast<int>(inFlightProbes_.size()) >= kMaxParallelProbes) return;

    launchProbe();

    // If there is still capacity AND more candidates AND discoveries running,
    // schedule the hedge timer to fire the next probe shortly. We deliberately
    // delay the next probe rather than firing them all at once to limit the
    // amount of concurrent traffic on a healthy primary.
    if (!finished_
        && static_cast<int>(inFlightProbes_.size()) < kMaxParallelProbes
        && (!pendingCandidates_.empty() || discoveryInFlight_ > 0)) {
        scheduleHedgeTimer();
    }
}

void FailoverProbeExecutor::scheduleHedgeTimer()
{
    if (hedgeTimerScheduled_ || finished_) return;
    hedgeTimerScheduled_ = true;
    hedgeTimer_.expires_after(std::chrono::milliseconds(kHedgeDelayMs));
    std::weak_ptr<bool> weakAlive = aliveToken_;
    hedgeTimer_.async_wait([this, weakAlive](const boost::system::error_code &ec) {
        // The executor may have been destroyed while this wait was pending: cancel()
        // posts the handler with operation_aborted rather than running it inline. Guard
        // against use-after-free before touching any member (including hedgeTimerScheduled_).
        auto alive = weakAlive.lock();
        if (!alive) return;
        hedgeTimerScheduled_ = false;
        if (ec) return;  // canceled or aborted
        onHedgeTimer(ec);
    });
}

void FailoverProbeExecutor::onHedgeTimer(const boost::system::error_code &ec)
{
    if (finished_) return;
    tryLaunchProbe();
}

void FailoverProbeExecutor::launchProbe()
{
    using namespace std::placeholders;

    auto candidate = std::move(pendingCandidates_.front());
    pendingCandidates_.pop_front();

    const auto probeId = nextProbeId_++;
    auto probe = std::make_unique<InFlightProbe>();
    probe->priorityIndex = candidate.priorityIndex;
    probe->data = candidate.data;
    probe->startTime = std::chrono::steady_clock::now();

    // The probe BaseRequest carries a no-op callback: we never invoke callCallback()
    // since the probe result is consumed by the FailoverProbeExecutor itself.
    auto noop = std::make_shared<CancelableCallback<WSNetRequestFinishedCallback>>(
        [](ApiRetCode, const std::string &) {});
    probe->probeRequest = std::unique_ptr<BaseRequest>(serverapi_requests_factory::myIP(noop));

    const auto *failover = failoverAt(probe->priorityIndex);
    g_logger->debug("{} event=probe_start uid={} name={} domain={} sni={} ech={}",
                    kFoMetricTag, failover->uniqueId(), failover->name(),
                    probe->data.domain(), probe->data.sniDomain(),
                    probe->data.echConfig().empty() ? "0" : "1");

    auto httpRequest = serverapi_utils::createHttpRequestWithFailoverParameters(
        httpNetworkManager_, probe->data, probe->probeRequest.get(),
        ignoreSslErrors_, advancedParameters_->isAPIExtraTLSPadding());
    httpRequest->setIsDebugLogCurlError(true);
    // Probes resolve many failover domains in parallel; without this the IPs of
    // every probed (mostly losing) domain would accumulate in the firewall whitelist
    // for the whole session. Drop them when the probe finishes or is canceled. The
    // winner's IPs are re-whitelisted by the subsequent real ServerAPI requests.
    httpRequest->setRemoveFromWhitelistIpsAfterFinish(true);

    probe->httpAsyncCallback = httpNetworkManager_->executeRequestEx(
        httpRequest, probeId,
        std::bind(&FailoverProbeExecutor::onProbeFinished, this, _1, _2, _3, _4),
        nullptr, nullptr);

    inFlightProbes_[probeId] = std::move(probe);
}

void FailoverProbeExecutor::onProbeFinished(std::uint64_t probeId, std::uint32_t elapsedMs,
                                            std::shared_ptr<WSNetRequestError> error, const std::string &data)
{
    if (finished_) return;
    auto it = inFlightProbes_.find(probeId);
    if (it == inFlightProbes_.end()) return;

    auto probe = std::move(it->second);
    inFlightProbes_.erase(it);

    const auto probeMs = utils::since(probe->startTime).count();
    const auto &failoverUid = failoverAt(probe->priorityIndex)->uniqueId();

    if (isConnectStateChanged_) {
        g_logger->debug("{} event=probe_end uid={} domain={} duration_ms={} result=connect_state_changed",
                        kFoMetricTag, failoverUid, probe->data.domain(), probeMs);
        finishWith(FailoverProbeResult::kConnectStateChanged, {});
        return;
    }

    bool success = false;
    if (error->isSuccess()) {
        probe->probeRequest->handle(data);
        if (probe->probeRequest->retCode() == ApiRetCode::kSuccess) {
            success = true;
        }
    }

    if (success) {
        const auto totalMs = utils::since(startTime_).count();
        g_logger->debug("{} event=probe_end uid={} domain={} duration_ms={} http_elapsed_ms={} result=ok total_ms={} failed_before_winner={}",
                        kFoMetricTag, failoverUid, probe->data.domain(), probeMs, elapsedMs, totalMs, failedProbeCount_);
        FailoverProbeWinner winner;
        winner.failoverUid = failoverUid;
        winner.failoverData = probe->data;
        winner.elapsedMs = totalMs;
        finishWith(FailoverProbeResult::kSuccess, std::move(winner));
        return;
    }

    // ret_code is only meaningful when the HTTP layer succeeded and handle() ran (e.g. the
    // response was received but was invalid JSON). On a pure transport error handle() is
    // skipped, so retCode() is still the BaseRequest default and would be misleading; log it
    // only when it actually reflects the parsed response.
    if (error->isSuccess()) {
        g_logger->debug("{} event=probe_end uid={} domain={} duration_ms={} http_elapsed_ms={} result=fail error={} ret_code={}",
                        kFoMetricTag, failoverUid, probe->data.domain(), probeMs, elapsedMs,
                        error->toString(), static_cast<int>(probe->probeRequest->retCode()));
    } else {
        g_logger->debug("{} event=probe_end uid={} domain={} duration_ms={} http_elapsed_ms={} result=fail error={}",
                        kFoMetricTag, failoverUid, probe->data.domain(), probeMs, elapsedMs,
                        error->toString());
    }
    if (error->isNoNetworkError()) {
        // A no-network error is not the failover's fault, so do NOT blacklist this domain
        // (per WSNetRequestError: we must not switch failovers for connectivity errors).
        // Just remember that connectivity was lost so the search reports kNoNetwork.
        sawNoNetwork_ = true;
    } else {
        failedFailovers_.add(probe->data);
    }
    ++failedProbeCount_;

    tryLaunchProbe();
    if (!finished_ && isAllExhausted()) {
        finishWith(exhaustedResult(), {});
    }
}

void FailoverProbeExecutor::cancelAllInFlight()
{
    for (auto &kv : inFlightProbes_) {
        if (kv.second->httpAsyncCallback) {
            kv.second->httpAsyncCallback->cancel();
        }
    }
    inFlightProbes_.clear();
}

void FailoverProbeExecutor::finishWith(FailoverProbeResult result, FailoverProbeWinner winner)
{
    if (finished_) return;
    finished_ = true;
    cancelAllInFlight();
    hedgeTimer_.cancel();

    // Terminal summary metric of the search (time-to-finish, winner,
    // number of failed probes before the search ended). Calibrates hedge tuning.
    const auto totalMs = utils::since(startTime_).count();
    g_logger->debug("{} event=probe_search_end result={} winner_uid={} total_ms={} failed_before_winner={}",
                    kFoMetricTag, static_cast<int>(result), winner.failoverUid, totalMs, failedProbeCount_);

    // Move callback out so re-entrancy from the callback (e.g., the caller
    // destroying *this) does not crash. Do not touch members after invoking cb.
    auto cb = std::move(callback_);
    if (cb) cb(result, std::move(winner));
}

bool FailoverProbeExecutor::isAllExhausted() const
{
    return discoveryInFlight_ == 0 && pendingCandidates_.empty() && inFlightProbes_.empty();
}

FailoverProbeResult FailoverProbeExecutor::exhaustedResult() const
{
    return sawNoNetwork_ ? FailoverProbeResult::kNoNetwork : FailoverProbeResult::kAllFailed;
}

} // namespace wsnet
