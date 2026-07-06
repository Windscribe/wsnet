#pragma once

#include <boost/asio.hpp>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "WSNetAdvancedParameters.h"
#include "WSNetHttpNetworkManager.h"
#include "../baserequest.h"
#include "failedfailovers.h"
#include "failover/basefailover.h"
#include "failover/failoverdata.h"

namespace wsnet {

enum class FailoverProbeResult {
    kSuccess,
    kAllFailed,
    kNoNetwork,
    kConnectStateChanged
};

struct FailoverProbeWinner {
    std::string failoverUid;
    FailoverData failoverData;
    // Time elapsed from the start of the probe search until this winning failover
    // was found.
    std::int64_t elapsedMs = 0;
};

using FailoverProbeCallback = std::function<void(FailoverProbeResult, FailoverProbeWinner)>;

// Parallel probe-based search for a working API failover.
//
// Discovery (BaseFailover::getData) for every failover is launched in parallel.
// As candidates arrive they are placed in a priority queue ordered by the failover's
// position in the original list. Probes (myIP) are launched one at a time, up to a
// concurrency cap, with a hedge delay between consecutive launches (Tail-at-Scale).
// The first probe that returns a valid JSON response wins; all in-flight HTTP requests
// and discoveries are cancelled and the winner is returned via the result callback.
//
// Not thread safe: all methods must be invoked from the supplied io_context's thread.
// cancel() guarantees that the result callback will NOT be invoked.
class FailoverProbeExecutor
{
public:
    FailoverProbeExecutor(boost::asio::io_context &io_context,
                          WSNetHttpNetworkManager *httpNetworkManager,
                          std::vector<std::unique_ptr<BaseFailover>> failovers,
                          bool ignoreSslErrors,
                          bool isConnectedToVpn,
                          WSNetAdvancedParameters *advancedParameters,
                          FailedFailovers &failedFailovers,
                          FailoverProbeCallback callback);
    ~FailoverProbeExecutor();

    void start();

    // Aborts everything in flight and discards the result callback. Safe to call multiple times.
    void cancel();

    void setIsConnectedToVpnState(bool isConnected);

private:
    // Hedge tuning (Tail-at-Scale). Defaults are conservative for production.
    static constexpr int kMaxParallelProbes = 4;
    static constexpr int kHedgeDelayMs = 250;

    struct DiscoveryEntry {
        std::unique_ptr<BaseFailover> failover;
        int priorityIndex = 0;
        bool finished = false;
    };

    struct PendingCandidate {
        int priorityIndex = 0;   // position of failover in the original list; indexes discovery_
        int subIndex = 0;        // index within failover's data vector
        FailoverData data;
    };

    struct InFlightProbe {
        // Index into discovery_. The failover's uid/name are read from there on demand rather
        // than copied into every candidate/probe (they are stable per failover).
        int priorityIndex = 0;
        FailoverData data;
        std::unique_ptr<BaseRequest> probeRequest;
        std::shared_ptr<WSNetCancelableCallback> httpAsyncCallback;
        std::chrono::steady_clock::time_point startTime;
    };

    boost::asio::io_context &io_context_;
    WSNetHttpNetworkManager *httpNetworkManager_;
    WSNetAdvancedParameters *advancedParameters_;
    FailedFailovers &failedFailovers_;
    FailoverProbeCallback callback_;
    bool ignoreSslErrors_;
    bool isConnectedToVpn_;
    bool isConnectStateChanged_ = false;
    bool finished_ = false;
    // True only while start() is still launching the initial discovery for every failover.
    // Synchronous failovers (e.g. hardcoded) invoke onDiscoveryCallback() re-entrantly from
    // within that launch loop. If the very first such discovery yields no usable candidate
    // (e.g. its only domain is already in failedFailovers_), discoveryInFlight_ briefly drops
    // to 0 and isAllExhausted() would report "all failed" before the remaining failovers have
    // even been launched. This flag defers the exhausted-check until start() has kicked off
    // every discovery; start() performs the single authoritative check at the end.
    bool launchingDiscoveries_ = false;
    // Set when a discovery or a probe reports a genuine lack of network connectivity
    // (WSNetRequestError::isNoNetworkError / FailoverResult::kNoNetwork). If the search
    // exhausts every candidate without a winner and this flag is set, the search reports
    // kNoNetwork instead of kAllFailed so the caller returns kNoNetworkConnection (a
    // retriable condition) rather than kFailoverFailed ("API not ready").
    bool sawNoNetwork_ = false;

    std::vector<std::unique_ptr<DiscoveryEntry>> discovery_;
    int discoveryInFlight_ = 0;

    // Candidates sorted by (priorityIndex, subIndex). Pop from front for next probe.
    std::deque<PendingCandidate> pendingCandidates_;

    std::map<std::uint64_t, std::unique_ptr<InFlightProbe>> inFlightProbes_;
    std::uint64_t nextProbeId_ = 0;

    // Metrics: number of probes that failed before a winner was found
    // (or before all candidates were exhausted). Logged at finish time so the
    // hedge tuning (delay / concurrency) can be calibrated against real networks.
    int failedProbeCount_ = 0;

    boost::asio::steady_timer hedgeTimer_;
    bool hedgeTimerScheduled_ = false;
    // Lifetime guard for the hedge-timer async handler. boost::asio cancel() (and the
    // steady_timer destructor) do NOT run a pending async_wait handler inline -- they
    // post it with operation_aborted, so it runs later on the io_context. If the executor
    // is destroyed in the meantime (e.g. finishWith() -> result callback destroys *this
    // synchronously while a hedge wait is outstanding), that posted handler would touch
    // freed memory. The handler captures a weak_ptr to this token and bails out if it
    // can no longer be locked, instead of dereferencing a dead this.
    std::shared_ptr<bool> aliveToken_ = std::make_shared<bool>(true);

    std::chrono::steady_clock::time_point startTime_;

    void startDiscovery(DiscoveryEntry *entry);
    void onDiscoveryCallback(int discoveryIndex, FailoverResult result, const std::vector<FailoverData> &data);

    void insertPendingCandidate(int priorityIndex, int subIndex, const FailoverData &data);

    // The failover for a given priorityIndex. discovery_ owns the BaseFailover for the whole
    // executor lifetime, so uid()/name() can be read on demand instead of being copied around.
    BaseFailover *failoverAt(int priorityIndex) const { return discovery_[priorityIndex]->failover.get(); }

    void tryLaunchProbe();
    void scheduleHedgeTimer();
    void onHedgeTimer(const boost::system::error_code &ec);
    void launchProbe();
    void onProbeFinished(std::uint64_t probeId, std::uint32_t elapsedMs,
                         std::shared_ptr<WSNetRequestError> error, const std::string &data);

    void cancelAllInFlight();
    void finishWith(FailoverProbeResult result, FailoverProbeWinner winner);
    bool isAllExhausted() const;
    // Result to report when all candidates are exhausted without a winner: kNoNetwork if a
    // genuine connectivity loss was observed during the search, otherwise kAllFailed.
    FailoverProbeResult exhaustedResult() const;
};

} // namespace wsnet
