#pragma once

#include "WSNetApiResourcesManager.h"
#include <boost/asio.hpp>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include "WSNetServerAPI.h"
#include "connectstate.h"
#include "inventoryparser.h"
#include "sessionstatus.h"
#include "utils/persistentsettings.h"
#include "utils/cancelablecallback.h"

namespace wsnet {

enum class RequestType {
    kSessionStatus,
    kAuthToken,
    kInventoryLocations,
    kInventoryServers,
    kServerCredentialsOpenVPN,
    kServerCredentialsIkev2,
    kServerConfigs,
    kPortMap,
    kStaticIps,
    kNotifications,
    kCheckUpdate,
    kAmneziawgUnblockParams
};

class ApiResourcesManager : public WSNetApiResourcesManager
{
public:
    explicit ApiResourcesManager(boost::asio::io_context &io_context, WSNetServerAPI *serverAPI, PersistentSettings &persistentSettings, std::shared_ptr<ConnectState> connectState);
    virtual ~ApiResourcesManager();

    std::shared_ptr<WSNetCancelableCallback> setCallback(WSNetApiResourcesManagerCallback callback) override;

    void setAuthHash(const std::string &authHash) override;

    bool isExist() const override;

    bool loginWithAuthHash() override;
    void authTokenLogin(const std::string &username, bool useAsciiCaptcha) override;
    void login(const std::string &username, const std::string &password, const std::string &code2fa, const std::string &secureToken,
               const std::string &captchaSolution = std::string(),
               const std::vector<float> &captchaTrailX = std::vector<float>(),
               const std::vector<float> &captchaTrailY = std::vector<float>()) override;
    void authTokenSignup(const std::string &username, bool useAsciiCaptcha) override;
    void signup(const std::string &username, const std::string &password, const std::string &referringUsername,
                const std::string &email, const std::string &voucherCode,
                const std::string &secureToken,
                const std::string &captchaSolution = std::string(),
                const std::vector<float> &captchaTrailX = std::vector<float>(),
                const std::vector<float> &captchaTrailY = std::vector<float>()) override;
    void logout() override;

    void fetchSession() override;

    void fetchServerCredentials() override;

    std::string authHash() override;

    void removeFromPersistentSettings() override;

    void checkUpdate(UpdateChannel channel, const std::string &appVersion, const std::string &appBuild,
                               const std::string &osVersion, const std::string &osBuild) override;

    void setNotificationPcpid(const std::string &pcpid) override;
    void setMobileDeviceId(const std::string &appleId, const std::string &gpDeviceId) override;
    void setBackup(std::int32_t backup) override;

    std::string sessionStatus() const override;
    std::string portMap() const override;
    std::shared_ptr<WSNetServerLocations> serverLocations() const override;
    std::string staticIps() const override;
    std::string serverCredentialsOvpn() const override;
    std::string serverCredentialsIkev2() const override;
    std::string serverConfigs() const override;
    std::string notifications() const override;
    std::string checkUpdate() const override;
    std::string authTokenResult() const override;
    std::string amneziawgUnblockParams() const override;
    std::string amneziawgConfigId() const override;

    void setUpdateIntervals(int sessionInDisconnectedStateMs, int sessionInConnectedStateMs,
                            int locationsMs, int staticIpsMs, int serverConfigsAndCredentialsMs,
                            int portMapMs, int notificationsMs, int checkUpdateMs, int amneziawgUnblockParamsMs) override;

private:
    mutable std::mutex mutex_;
    std::shared_ptr<CancelableCallback<WSNetApiResourcesManagerCallback>> callback_ = nullptr;

    // Bumped by logout() and removeFromPersistentSettings(). Requests cannot be recalled once issued, so
    // completions are tagged with the epoch current when scheduled and dropped if that session has ended --
    // otherwise a login answer outliving a logout restores the auth hash and the client logs back in.
    std::uint64_t sessionEpoch_ = 0;

    // Takes mutex_ (so completion bodies no longer do) and drops the answer if its session has ended; tag
    // and test are both under the lock. Every completion must go through here or it opts out of the rule.
    // Public API methods keep locking themselves -- they are inbound calls, not completions.
    template <class F>
    auto guarded(F f)
    {
        return [this, f = std::move(f), epoch = sessionEpoch_](auto &&...args) {
            std::lock_guard locker(mutex_);
            if (epoch != sessionEpoch_)
                return;
            f(std::forward<decltype(args)>(args)...);
        };
    }

    // guarded() without the epoch test, for a completion that neither persists nor notifies session data.
    // onDeleteSessionAnswer is the only one: it is issued by the session end itself, so testing the epoch
    // would strand its kLogoutFinished as soon as a second end-of-session call bumped it.
    template <class F>
    auto locked(F f)
    {
        return [this, f = std::move(f)](auto &&...args) {
            std::lock_guard locker(mutex_);
            f(std::forward<decltype(args)>(args)...);
        };
    }

    boost::asio::io_context &io_context_;
    boost::asio::steady_timer fetchTimer_;
    WSNetServerAPI *serverAPI_;
    PersistentSettings &persistentSettings_;
    std::shared_ptr<ConnectState> connectState_;

    std::unique_ptr<SessionStatus> sessionStatus_;
    std::unique_ptr<SessionStatus> prevSessionStatus_;

    // Built from inventoryLocations_ + inventoryServers_; returned to the client.
    std::shared_ptr<WSNetServerLocations> serverLocations_;

    // Inventory v2 state — kept in sync with persistent settings.
    std::vector<InventoryLocation> inventoryLocations_;
    std::map<int, InventoryServer> inventoryServers_;
    std::int64_t invRevision_ = 0;

    std::string checkUpdate_;

    std::string pcpidNotifications_;
    std::string appleId_;
    std::string gpDeviceId_;
    std::string authTokenResult_;
    std::int32_t backup_ = -1;

    static constexpr int kMinute  = 60 * 1000;
    static constexpr int kHour    = 60 * 60 * 1000;
    static constexpr int k24Hours = 24 * 60 * 60 * 1000;

    // Failed requests are retried with bounded exponential backoff plus jitter instead of a
    // fixed delay. With a fixed delay every client degraded into a 1 Hz retry loop during an
    // API outage (resource fetches through the 1-second fetch timer, login/session/auth-token
    // through their own retry timers), and the large Inventory payloads amplified server load
    // and delayed recovery. Backoff state is tracked per resource / per flow, and a new
    // user-initiated login attempt always goes out immediately (the counters reset).
    //
    // The login/session/signup and auth-token loops use a smaller cap: their retries are silent
    // (no notification until an answer other than kNetworkError arrives), so the user is watching
    // a spinner the whole time, and with the 5-minute cap a client could sit out most of that
    // after the API had already recovered. These flows are a small share of outage traffic next
    // to the resource fetches, so the smaller cap keeps nearly all of the server-load win. The
    // initial auth-hash session on app start is included: the client shows "logging in" until it
    // completes, which makes it interactive in effect.
    static constexpr int kFailedRequestInitialDelayMs  = 1000;
    static constexpr int kFailedRequestMaxDelayMs      = 5 * kMinute;
    static constexpr int kInteractiveRetryMaxDelayMs   = kMinute;

    // Update intervals (milliseconds)
    int sessionInDisconnectedStateMs_  = kHour;
    int sessionInConnectedStateMs_     = kMinute;
    int locationsMs_                   = k24Hours;
    int staticIpsMs_                   = k24Hours;
    int serverConfigsAndCredentialsMs_ = k24Hours;
    int portMapMs_                     = k24Hours;
    int notificationsMs_               = kHour;
    int checkUpdateMs_                 = k24Hours;
    int amneziawgUnblockParamsMs_      = k24Hours;

    struct UpdateInfo {
        std::chrono::time_point<std::chrono::steady_clock> updateTime;
        bool isRequestSuccess;
        // Consecutive failures that reached the API (offline answers do not count).
        int consecutiveFailures = 0;
        // Delay before the next attempt after a failure; recomputed with jitter on every failure.
        int retryDelayMs = kFailedRequestInitialDelayMs;
    };
    std::map<RequestType, UpdateInfo> lastUpdateTimeMs_;
    std::map<RequestType, std::shared_ptr<wsnet::WSNetCancelableCallback>> requestsInProgress_;

    // Jitter source for retry backoff, so clients do not retry in lockstep after an outage.
    std::mt19937 backoffRndGen_{std::random_device{}()};

    // Consecutive kNetworkError answers in the login/session and auth-token retry loops.
    // Reset on any other answer and by the user-facing entry points, so an explicit retry
    // (user pressed "login" again) is never delayed.
    int loginRetryFailures_ = 0;
    int authTokenRetryFailures_ = 0;

    // Pending network-error retry timers for those loops. A new user-initiated attempt cancels the
    // scheduled retry of the previous one; otherwise the stale retry fires later (up to the backoff
    // cap) and issues a duplicate request on top of the new attempt -- re-submitting credentials
    // over an already established session in the worst case. The retry handlers also compare their
    // captured timer against the member, so a handler that was already dequeued when the timer was
    // replaced drops itself instead of re-issuing.
    std::shared_ptr<boost::asio::steady_timer> loginRetryTimer_;
    std::shared_ptr<boost::asio::steady_timer> authTokenRetryTimer_;

    bool isLoginOkEmitted_ = false;

    bool isFetchingServerCredentials_ = false;
    bool isOpenVpnCredentialsReceived_;
    bool isIkev2CredentialsReceived_;
    bool isServerConfigsReceived_;

    struct {
        UpdateChannel channel;
        std::string appVersion;
        std::string appBuild;
        std::string osVersion;
        std::string osBuild;
    } checkUpdateData_;
    bool isCheckUpdateDataSet_ = false;

    bool forceRefetchSessionStatus_ = false;
    bool forceRefetchInventoryServers_ = false;

    // Assume mutex_ is held. The public overloads lock and delegate; the network-error retries reach them
    // through guarded(), which holds the lock across the epoch test and the re-issue.
    bool loginWithAuthHashImpl();
    void authTokenLoginImpl(const std::string &username, bool useAsciiCaptcha);
    void authTokenSignupImpl(const std::string &username, bool useAsciiCaptcha);
    void loginImpl(const std::string &username, const std::string &password, const std::string &code2fa,
                   const std::string &secureToken, const std::string &captchaSolution,
                   const std::vector<float> &captchaTrailX, const std::vector<float> &captchaTrailY);
    void signupImpl(const std::string &username, const std::string &password, const std::string &referringUsername,
                    const std::string &email, const std::string &voucherCode, const std::string &secureToken,
                    const std::string &captchaSolution, const std::vector<float> &captchaTrailX,
                    const std::vector<float> &captchaTrailY);

    void handleLoginOrSessionAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);

    void checkForReadyLogin();
    void checkForServerCredentialsFetchFinished();

    // Rebuild serverLocations_ from current inventoryLocations_ + inventoryServers_.
    // Returns true if the rebuild produced a non-null result.
    bool rebuildServerLocations();

    // Apply a server_inventory delta embedded in a session JSON response.
    // Returns true if the server list actually changed (enables/disables applied).
    bool applyInventoryDelta(const std::string &sessionJson);

    void fetchAll();
    bool fetchSession(const std::string &authHash);
    void fetchInventoryLocations();
    bool fetchInventoryServers();
    void fetchStaticIps(const std::string &authHash);
    void fetchServerConfigs(const std::string &authHash);
    void fetchServerCredentialsOpenVpn(const std::string &authHash);
    void fetchServerCredentialsIkev2(const std::string &authHash);
    void fetchPortMap(const std::string &authHash);
    void fetchNotifications(const std::string &authHash);
    void fetchCheckUpdate();
    void fetchAmneziawgUnblockParams(const std::string &authHash);

    void updateSessionStatus();

    void onFetchTimer(boost::system::error_code const &err);

    void onAuthTokenAnswer(const std::string &username, bool useAsciiCaptcha, wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData, bool isLoginCall);
    void onInitialSessionAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onLoginAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData,
                       const std::string &username, const std::string &password, const std::string &code2fa,
                       const std::string &secureToken,
                       const std::string &captchaSolution, const std::vector<float> &captchaTrailX, const std::vector<float> &captchaTrailY);
    void onSignupAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData,
                        const std::string &username, const std::string &password, const std::string &referringUsername,
                        const std::string &email, const std::string &voucherCode, const std::string &secureToken,
                        const std::string &captchaSolution, const std::vector<float> &captchaTrailX, const std::vector<float> &captchaTrailY);
    void onSessionAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onInventoryLocationsAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onInventoryServersAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onStaticIpsAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onServerConfigsAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onServerCredentialsOpenVpnAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onServerCredentialsIkev2Answer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onPortMapAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onNotificationsAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onCheckUpdateAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onAmneziawgUnblockParamsAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);
    void onDeleteSessionAnswer(wsnet::ServerApiRetCode serverApiRetCode, const std::string &jsonData);

    bool isTimeoutForRequest(RequestType requestType, int timeout);

    // Record the outcome of a finished resource request and update its backoff state.
    void recordRequestResult(RequestType requestType, wsnet::ServerApiRetCode serverApiRetCode);
    int nextRetryDelayMs(int consecutiveFailures, int maxDelayMs = kFailedRequestMaxDelayMs);

    // Schedule a delayed re-issue after a kNetworkError answer in one of the interactive flows
    // (login/session/signup share loginRetryTimer_, the auth-token loop has its own). Bumps the
    // flow's failure counter, arms the flow's timer with the interactive backoff delay and runs
    // reissue() when it fires; the handler drops itself if the timer was superseded or canceled.
    // Assume mutex_ is held.
    void scheduleInteractiveRetry(std::shared_ptr<boost::asio::steady_timer> &retryTimer, int &retryFailures,
                                  const char *logTag, std::function<void()> reissue);

    // Cancel a scheduled network-error retry because a newer attempt supersedes it. Assume mutex_ is held.
    void cancelPendingLoginRetry();
    void cancelPendingAuthTokenRetry();

    void clearValues();
};

} // namespace wsnet
