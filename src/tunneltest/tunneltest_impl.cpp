#include "tunneltest_impl.h"
#include <algorithm>
#include <vector>
#include <rapidjson/document.h>
#include "settings.h"
#include "utils/utils.h"
#include "utils/wsnet_logger.h"

namespace wsnet {

namespace {
constexpr std::uint32_t kDnsRetryDelayMs = 100;
// Once DNS is proven a fast failure is a real failure, and probing ten times a second buys nothing.
constexpr std::uint32_t kExitIpProbeRetryDelayMs = 500;
constexpr std::uint32_t kBridgeRetryDelayMs = 250;
// A step with less time left than this cannot resolve and connect, so it is given a floor instead
// of being issued to fail on arrival.
constexpr std::int64_t kMinProbeTimeoutMs = 100;

// One schedule for every protocol: a protocol that needs time to settle after connecting is the
// caller's to wait out before start(), not something this test guesses at.
constexpr std::int64_t kTotalMs = 14000;
constexpr std::int64_t kBridgeBudgetMs = 6000;
constexpr std::uint32_t kDnsTimeoutMs = 2000;
const std::vector<std::uint32_t> kExitIpProbeTimeouts{2000, 4000, 8000};
// How long a successful IPv4 probe waits for the IPv6 one. Both start together over the same tunnel,
// so a working IPv6 path answers close behind IPv4, and a missing one fails fast. Only an IPv6 path
// that drops packets runs into this, and it must not hold back the tunnel's verdict for long.
constexpr std::int64_t kIpv6GraceMs = 500;

// Transport failures and a BridgeAPI that has not seen the connection yet are the tunnel still
// coming up. Anything else is the node's answer, and asking again gets the same one.
bool isBridgeRetryable(ApiRetCode retCode)
{
    return retCode == ApiRetCode::kNetworkError || retCode == ApiRetCode::kNoNetworkConnection;
}

const char *bridgeFallthroughReason(ApiRetCode retCode)
{
    switch (retCode) {
    case ApiRetCode::kSuccess: return "unexpected payload";
    case ApiRetCode::kNoToken: return "no token";
    case ApiRetCode::kBridgeApiError: return "bridge API error";
    case ApiRetCode::kIncorrectJson: return "incorrect json";
    default: return "request failed";
    }
}

struct CheckIpAddresses
{
    std::string ipv4;
    std::string ipv6;
};

std::string stringMember(const rapidjson::Document &doc, const char *name)
{
    const auto it = doc.FindMember(name);
    if (it == doc.MemberEnd() || !it->value.IsString())
        return {};
    return std::string(it->value.GetString(), it->value.GetStringLength());
}

// kSuccess is an answer only when the body carries a non-empty ipv4 or ipv6. Anything else, including
// the empty body a suppressed bridge request completes with, is not an answer.
CheckIpAddresses addressesFromCheckIp(const std::string &body)
{
    rapidjson::Document doc;
    doc.Parse(body.c_str());
    if (doc.HasParseError() || !doc.IsObject())
        return {};
    return {stringMember(doc, "ipv4"), stringMember(doc, "ipv6")};
}

std::uint32_t clampTimeout(std::int64_t timeoutMs)
{
    return static_cast<std::uint32_t>(std::max(timeoutMs, kMinProbeTimeoutMs));
}
}

TunnelTest_impl::TunnelTest_impl(boost::asio::io_context &io_context, TunnelTestExitIpProbeFn exitIpProbeFn, TunnelTestResolveFn resolveFn,
                                 TunnelTestCheckIpFn checkIpFn) :
    io_context_(io_context),
    exitIpProbeFn_(std::move(exitIpProbeFn)),
    resolveFn_(std::move(resolveFn)),
    checkIpFn_(std::move(checkIpFn))
{
}

void TunnelTest_impl::run(TunnelTestCallback callback, bool isBridgeAllowed)
{
    auto state = std::make_shared<State>(io_context_);
    state->callback = callback;
    state->isBridgeEnabled = isBridgeAllowed && checkIpFn_;
    g_logger->info("Tunnel test: start, total {} ms, bridge budget {} ms{}", kTotalMs, kBridgeBudgetMs,
                   state->isBridgeEnabled ? "" : " (bridge disabled)");
    state->overallStart = std::chrono::steady_clock::now();
    resolve(state);
}

void TunnelTest_impl::resolve(std::shared_ptr<State> state)
{
    if (state->callback->isCanceled())
        return;

    // c-ares gives a lookup 2000 ms and two tries. The deadline keeps a lookup that never answers
    // inside the run's own budget.
    const auto stepId = ++state->stepId;
    const auto deadlineMs = clampTimeout(std::min<std::int64_t>(kDnsTimeoutMs, totalRemainingMs(*state)));
    state->timer.expires_after(std::chrono::milliseconds(deadlineMs));
    state->timer.async_wait([this, state, stepId](const boost::system::error_code &ec) {
        if (ec || !takeStep(state, stepId))
            return;
        g_logger->info("Tunnel test +{} ms dns: failed: deadline exceeded", elapsedMs(*state));
        retry(state, &TunnelTest_impl::resolve);
    });

    auto gate = std::make_shared<CancelableCallback<ResolveCallback>>(
        [this, state, stepId](std::shared_ptr<WSNetDnsRequestResult> result) {
            onResolved(state, stepId, result);
        });
    state->step = gate;
    // The primary name the exit IP probe requests, so a failure here is the failure it would usually have hit.
    const std::string hostname = Settings::instance().tunnelTestEndpoints().front();
    resolveFn_(hostname, [gate](std::shared_ptr<WSNetDnsRequestResult> result) { gate->call(result); });
}

void TunnelTest_impl::onResolved(std::shared_ptr<State> state, std::uint64_t stepId, std::shared_ptr<WSNetDnsRequestResult> result)
{
    if (!takeStep(state, stepId))
        return;

    if (isDnsSuccess(result)) {
        state->isDnsProven = true;
        g_logger->info("Tunnel test +{} ms dns: resolved to {}", elapsedMs(*state), utils::join(result->ips(), ","));
        startBridge(state);
        return;
    }
    if (result && result->error() && !result->error()->isSuccess())
        g_logger->info("Tunnel test +{} ms dns: failed: {}", elapsedMs(*state), result->error()->toString());
    else
        g_logger->info("Tunnel test +{} ms dns: failed: empty answer", elapsedMs(*state));
    retry(state, &TunnelTest_impl::resolve);
}

void TunnelTest_impl::startBridge(std::shared_ptr<State> state)
{
    if (!state->isBridgeEnabled) {
        probeExitIp(state);
        return;
    }
    // The budget starts once DNS is proven, so a slow resolver does not eat the bridge's share.
    const std::int64_t budgetMs = std::min(kBridgeBudgetMs, totalRemainingMs(*state));
    state->bridgeDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budgetMs);
    checkIp(state);
}

void TunnelTest_impl::checkIp(std::shared_ptr<State> state)
{
    if (state->callback->isCanceled())
        return;

    const std::int64_t remaining = bridgeRemainingMs(*state);
    if (remaining < kMinProbeTimeoutMs) {
        g_logger->info("Tunnel test +{} ms bridge: budget exhausted, falling back to exit IP probe", elapsedMs(*state));
        probeExitIp(state);
        return;
    }

    // No per-request cap here: response times across clients vary too widely for one number to
    // separate a slow node from a dead one. BridgeAPI's own request timeout bounds the request, and
    // this deadline only stops a token wait or a request from outliving the bridge budget.
    const auto stepId = ++state->stepId;
    state->stepStart = std::chrono::steady_clock::now();
    state->timer.expires_after(std::chrono::milliseconds(remaining));
    state->timer.async_wait([this, state, stepId](const boost::system::error_code &ec) {
        if (ec || !takeStep(state, stepId))
            return;
        g_logger->info("Tunnel test +{} ms bridge: no answer in {} ms, budget exhausted, falling back to exit IP probe",
                       elapsedMs(*state), utils::since(state->stepStart).count());
        probeExitIp(state);
    });

    auto gate = std::make_shared<CancelableCallback<WSNetRequestFinishedCallback>>(
        [this, state, stepId](ApiRetCode retCode, const std::string &body) {
            onCheckIp(state, stepId, retCode, body);
        });
    state->step = gate;
    state->stepRequest = checkIpFn_(gate);
}

void TunnelTest_impl::onCheckIp(std::shared_ptr<State> state, std::uint64_t stepId, ApiRetCode retCode, const std::string &body)
{
    if (!takeStep(state, stepId))
        return;

    const auto stepMs = utils::since(state->stepStart).count();
    if (retCode == ApiRetCode::kSuccess) {
        const auto addresses = addressesFromCheckIp(body);
        if (!addresses.ipv4.empty() || !addresses.ipv6.empty()) {
            g_logger->info("Tunnel test +{} ms bridge: ipv4={} ipv6={} in {} ms", elapsedMs(*state), addresses.ipv4, addresses.ipv6, stepMs);
            complete(state, true, addresses.ipv4, addresses.ipv6, "bridge");
            return;
        }
    }
    if (isBridgeRetryable(retCode)) {
        retryBridge(state, retCode == ApiRetCode::kNetworkError ? "network error" : "no network");
        return;
    }
    g_logger->info("Tunnel test +{} ms bridge: {} ({}) in {} ms, falling back to exit IP probe", elapsedMs(*state),
                   bridgeFallthroughReason(retCode), static_cast<int>(retCode), stepMs);
    probeExitIp(state);
}

void TunnelTest_impl::retryBridge(std::shared_ptr<State> state, const char *reason)
{
    if (bridgeRemainingMs(*state) - kBridgeRetryDelayMs < kMinProbeTimeoutMs) {
        g_logger->info("Tunnel test +{} ms bridge: {} in {} ms, budget exhausted, falling back to exit IP probe", elapsedMs(*state), reason,
                       utils::since(state->stepStart).count());
        probeExitIp(state);
        return;
    }
    g_logger->info("Tunnel test +{} ms bridge: {} in {} ms, retrying", elapsedMs(*state), reason, utils::since(state->stepStart).count());
    state->timer.expires_after(std::chrono::milliseconds(kBridgeRetryDelayMs));
    state->timer.async_wait([this, state](const boost::system::error_code &ec) {
        if (ec || state->callback->isCanceled())
            return;
        checkIp(state);
    });
}

void TunnelTest_impl::probeExitIp(std::shared_ptr<State> state)
{
    if (state->callback->isCanceled())
        return;

    const std::size_t index = std::min(state->exitIpProbeIndex, kExitIpProbeTimeouts.size() - 1);
    ++state->exitIpProbeIndex;
    // Once the bridge has had its share, the exit IP probe gets only what is left of the run.
    const std::uint32_t timeoutMs = clampTimeout(std::min<std::int64_t>(kExitIpProbeTimeouts[index], totalRemainingMs(*state)));

    const bool isProbingIpv6 = state->ipv6.empty() && !state->ipv6Probe;
    g_logger->info("Tunnel test +{} ms probe: attempt {}, timeout {} ms, {}", elapsedMs(*state), state->exitIpProbeIndex, timeoutMs,
                   isProbingIpv6 ? "ipv4 + ipv6" : "ipv4");
    // Issued first so that an IPv6 answer already in hand when IPv4 succeeds costs no grace wait.
    if (isProbingIpv6)
        probeIpv6(state, timeoutMs);

    state->exitIpProbeStart = std::chrono::steady_clock::now();
    auto probeCallback = std::make_shared<CancelableCallback<WSNetRequestFinishedCallback>>(
        [this, state](ApiRetCode retCode, const std::string &ipAddress) {
            onExitIpProbeFinished(state, retCode, ipAddress);
        });
    exitIpProbeFn_(IpFamily::kIpv4, timeoutMs, probeCallback);
}

void TunnelTest_impl::onExitIpProbeFinished(std::shared_ptr<State> state, ApiRetCode retCode, const std::string &ipAddress)
{
    if (state->callback->isCanceled())
        return;

    // ExitIpProbe reports kSuccess only for an HTTP 200 whose body is an IP address of the probed
    // family, so a successful answer needs no further validation here.
    const auto probeMs = utils::since(state->exitIpProbeStart).count();
    if (retCode == ApiRetCode::kSuccess) {
        g_logger->info("Tunnel test +{} ms probe ipv4: {} in {} ms", elapsedMs(*state), ipAddress, probeMs);
        if (state->ipv6Probe)
            waitForIpv6(state, ipAddress);
        else
            complete(state, true, ipAddress, state->ipv6, "exitIpProbe");
        return;
    }
    g_logger->info("Tunnel test +{} ms probe ipv4: failed in {} ms: {}", elapsedMs(*state), probeMs, ipAddress);
    retry(state, &TunnelTest_impl::probeExitIp);
}

void TunnelTest_impl::probeIpv6(std::shared_ptr<State> state, std::uint32_t timeoutMs)
{
    auto probeCallback = std::make_shared<CancelableCallback<WSNetRequestFinishedCallback>>(
        [this, state](ApiRetCode retCode, const std::string &ipAddress) {
            onIpv6ProbeFinished(state, retCode, ipAddress);
        });
    state->ipv6Probe = probeCallback;
    state->ipv6ProbeStart = std::chrono::steady_clock::now();
    exitIpProbeFn_(IpFamily::kIpv6, timeoutMs, probeCallback);
}

void TunnelTest_impl::onIpv6ProbeFinished(std::shared_ptr<State> state, ApiRetCode retCode, const std::string &ipAddress)
{
    // Before the cancel check: the probe's callback holds State, so keeping it would leak a cancelled run.
    state->ipv6Probe.reset();
    if (state->callback->isCanceled())
        return;

    const auto probeMs = utils::since(state->ipv6ProbeStart).count();
    if (retCode == ApiRetCode::kSuccess) {
        state->ipv6 = ipAddress;
        g_logger->info("Tunnel test +{} ms probe ipv6: {} in {} ms", elapsedMs(*state), ipAddress, probeMs);
    } else {
        g_logger->info("Tunnel test +{} ms probe ipv6: failed in {} ms: {}", elapsedMs(*state), probeMs, ipAddress);
    }
    if (!state->ipv4.empty())
        complete(state, true, state->ipv4, state->ipv6, "exitIpProbe");
}

void TunnelTest_impl::waitForIpv6(std::shared_ptr<State> state, const std::string &ipv4)
{
    state->ipv4 = ipv4;
    state->ipv4At = std::chrono::steady_clock::now();
    const std::int64_t graceMs = std::clamp<std::int64_t>(totalRemainingMs(*state), 0, kIpv6GraceMs);
    state->timer.expires_after(std::chrono::milliseconds(graceMs));
    state->timer.async_wait([this, state, graceMs](const boost::system::error_code &ec) {
        if (ec || state->callback->isCanceled())
            return;
        g_logger->info("Tunnel test +{} ms probe ipv6: no answer within {} ms of ipv4, giving up", elapsedMs(*state), graceMs);
        complete(state, true, state->ipv4, std::string(), "exitIpProbe");
    });
}

void TunnelTest_impl::retry(std::shared_ptr<State> state, Step next)
{
    if (state->callback->isCanceled())
        return;

    const std::uint32_t delayMs = state->isDnsProven ? kExitIpProbeRetryDelayMs : kDnsRetryDelayMs;
    if (totalRemainingMs(*state) - delayMs < kMinProbeTimeoutMs) {
        complete(state, false, std::string(), std::string(), state->isDnsProven ? "no exit IP" : "DNS never resolved");
        return;
    }

    state->timer.expires_after(std::chrono::milliseconds(delayMs));
    state->timer.async_wait([this, state, next](const boost::system::error_code &ec) {
        if (ec || state->callback->isCanceled())
            return;
        (this->*next)(state);
    });
}

void TunnelTest_impl::complete(const std::shared_ptr<State> &state, bool isSuccess, const std::string &ipv4, const std::string &ipv6,
                               const char *source)
{
    // A timer whose handler is already queued cannot be cancelled, so the IPv6 answer and the
    // expired grace timer can both get here.
    if (state->isCompleted)
        return;
    state->isCompleted = true;
    if (state->ipv6Probe)
        state->ipv6Probe->cancel();
    state->ipv6Probe.reset();
    state->timer.cancel();
    if (!isSuccess)
        g_logger->info("Tunnel test +{} ms result: failed, {}", elapsedMs(*state), source);
    else if (!state->ipv4.empty())
        g_logger->info("Tunnel test +{} ms result: success via {}, ipv4={} ipv6={} (waited {} ms for ipv6)", elapsedMs(*state), source, ipv4, ipv6,
                       utils::since(state->ipv4At).count());
    else
        g_logger->info("Tunnel test +{} ms result: success via {}, ipv4={} ipv6={}", elapsedMs(*state), source, ipv4, ipv6);
    state->callback->call(isSuccess, ipv4, ipv6);
}

bool TunnelTest_impl::takeStep(const std::shared_ptr<State> &state, std::uint64_t stepId)
{
    if (stepId != state->stepId)
        return false;
    ++state->stepId;
    if (state->step)
        state->step->cancel();
    state->step.reset();
    if (state->stepRequest)
        state->stepRequest->cancel();
    state->stepRequest.reset();
    state->timer.cancel();
    // The step is retired even for a cancelled run: its callbacks hold State, and keeping them would leak it.
    return !state->callback->isCanceled();
}

std::int64_t TunnelTest_impl::elapsedMs(const State &state) const
{
    return utils::since(state.overallStart).count();
}

std::int64_t TunnelTest_impl::totalRemainingMs(const State &state) const
{
    return kTotalMs - elapsedMs(state);
}

std::int64_t TunnelTest_impl::bridgeRemainingMs(const State &state) const
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(state.bridgeDeadline - std::chrono::steady_clock::now()).count();
}

bool TunnelTest_impl::isDnsSuccess(const std::shared_ptr<WSNetDnsRequestResult> &result)
{
    return result && result->error() && result->error()->isSuccess() && !result->ips().empty();
}

} // namespace wsnet
