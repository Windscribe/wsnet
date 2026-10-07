#pragma once

#include <boost/asio.hpp>
#include <chrono>
#include <memory>
#include <functional>
#include "WSNetDnsRequestResult.h"
#include "WSNetDnsResolver.h"
#include "WSNetTunnelTest.h"
#include "api/baserequest.h"

namespace wsnet {

using TunnelTestCallback = std::shared_ptr<CancelableCallback<WSNetTunnelTestCallback>>;
// Issues one probe pinned to ipFamily. In production this is ExitIpProbe::probe(); tests substitute their own.
using TunnelTestExitIpProbeFn = std::function<void(IpFamily ipFamily, std::uint32_t timeoutMs, RequestFinishedCallback callback)>;

// Invoked on the io_context thread. The production binding posts the resolver callback there:
// c-ares completes on its own thread, and State is io_context-thread-only.
using ResolveCallback = std::function<void(std::shared_ptr<WSNetDnsRequestResult> result)>;
using TunnelTestResolveFn = std::function<void(const std::string &hostname, ResolveCallback callback)>;

// Issues one bridge checkIp. In production this is BridgeAPI::checkIp(). The callback runs on the
// io_context thread, same as the resolver seam above. The returned handle cancels the request, so
// one given up on does not keep waiting in BridgeAPI for a token.
using TunnelTestCheckIpFn = std::function<std::shared_ptr<WSNetCancelableCallback>(RequestFinishedCallback callback)>;

// Three phases inside one overall deadline. DNS comes first and is required: a node that answers
// while the system resolver does not is a tunnel the user cannot browse through. Then the bridge
// checkIp, retried on transport errors until its own budget runs out, and abandoned at once on an
// answer from the node that carries no address. The exit IP probe is the fallback for whatever time is left:
// IPv4 decides the result, and an IPv6 probe runs beside it only to fill in the IPv6 exit IP.
// See WSNetTunnelTest::start().
// Must be used on the io_context thread.
class TunnelTest_impl
{
public:
    TunnelTest_impl(boost::asio::io_context &io_context, TunnelTestExitIpProbeFn exitIpProbeFn, TunnelTestResolveFn resolveFn,
                    TunnelTestCheckIpFn checkIpFn = {});

    void run(TunnelTestCallback callback, bool isBridgeAllowed = true);

private:
    // One test run. Kept alive by the handlers that still have work to do, so a run the caller
    // cancelled is released as soon as its outstanding probe or timer reports back.
    struct State
    {
        explicit State(boost::asio::io_context &io_context) : timer(io_context) {}

        // Index into the exit IP probe timeouts; the last one repeats.
        std::size_t exitIpProbeIndex = 0;
        bool isBridgeEnabled = false;
        bool isDnsProven = false;
        bool isCompleted = false;

        // Identifies the in-flight resolve or checkIp. A late answer from an earlier step compares
        // against it and is ignored; the deadline handler and the step callback both advance it.
        std::uint64_t stepId = 0;
        std::shared_ptr<WSNetCancelableCallback> step;
        std::shared_ptr<WSNetCancelableCallback> stepRequest;
        std::chrono::steady_clock::time_point stepStart;
        std::chrono::steady_clock::time_point overallStart;
        std::chrono::steady_clock::time_point bridgeDeadline;
        std::chrono::steady_clock::time_point exitIpProbeStart;

        // At most one IPv6 probe is in flight, and none is issued once ipv6 is known.
        std::shared_ptr<CancelableCallback<WSNetRequestFinishedCallback>> ipv6Probe;
        std::chrono::steady_clock::time_point ipv6ProbeStart;
        std::string ipv6;
        // The IPv4 exit IP, held while the run waits out the IPv6 grace period.
        std::string ipv4;
        std::chrono::steady_clock::time_point ipv4At;

        // One timer, uses that do not overlap: the in-flight step's deadline, the delay before the
        // next try, and the IPv6 grace period. expires_after cancels whichever wait is pending.
        boost::asio::steady_timer timer;
        TunnelTestCallback callback;
    };

    using Step = void (TunnelTest_impl::*)(std::shared_ptr<State>);

    boost::asio::io_context &io_context_;
    TunnelTestExitIpProbeFn exitIpProbeFn_;
    TunnelTestResolveFn resolveFn_;
    TunnelTestCheckIpFn checkIpFn_;

    void resolve(std::shared_ptr<State> state);
    void onResolved(std::shared_ptr<State> state, std::uint64_t stepId, std::shared_ptr<WSNetDnsRequestResult> result);
    void startBridge(std::shared_ptr<State> state);
    void checkIp(std::shared_ptr<State> state);
    void onCheckIp(std::shared_ptr<State> state, std::uint64_t stepId, ApiRetCode retCode, const std::string &body);
    void retryBridge(std::shared_ptr<State> state, const char *reason);
    void probeExitIp(std::shared_ptr<State> state);
    void onExitIpProbeFinished(std::shared_ptr<State> state, ApiRetCode retCode, const std::string &ipAddress);
    void probeIpv6(std::shared_ptr<State> state, std::uint32_t timeoutMs);
    void onIpv6ProbeFinished(std::shared_ptr<State> state, ApiRetCode retCode, const std::string &ipAddress);
    void waitForIpv6(std::shared_ptr<State> state, const std::string &ipv4);
    // A resolve or exit IP probe failed: try `next` again after the retry delay, or end the run.
    void retry(std::shared_ptr<State> state, Step next);
    void complete(const std::shared_ptr<State> &state, bool isSuccess, const std::string &ipv4, const std::string &ipv6, const char *source);
    // Retires the in-flight step. False when this completion is stale or the run was cancelled.
    bool takeStep(const std::shared_ptr<State> &state, std::uint64_t stepId);
    // Time since the run started. Every log line carries it, so interleaved steps read as one timeline.
    std::int64_t elapsedMs(const State &state) const;
    std::int64_t totalRemainingMs(const State &state) const;
    std::int64_t bridgeRemainingMs(const State &state) const;
    static bool isDnsSuccess(const std::shared_ptr<WSNetDnsRequestResult> &result);
};

} // namespace wsnet
