#include "apiresourcesmanager.h"
#include "utils/wsnet_logger.h"
#include "utils/cancelablecallback.h"
#include "utils/utils.h"
#include "settings.h"

namespace wsnet {

using namespace std::chrono;

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

ApiResourcesManager::ApiResourcesManager(boost::asio::io_context &io_context, WSNetServerAPI *serverAPI,
                                         PersistentSettings &persistentSettings, std::shared_ptr<ConnectState> connectState)
    : io_context_(io_context),
      fetchTimer_(io_context, boost::asio::chrono::seconds(1)),
      serverAPI_(serverAPI),
      persistentSettings_(persistentSettings),
      connectState_(connectState)
{
    sessionStatus_.reset(SessionStatus::createFromJson(persistentSettings_.sessionStatus()));
    prevSessionStatus_.reset(SessionStatus::createFromJson(persistentSettings_.sessionStatus()));

    // Restore inventory v2 state from persistent settings.
    inventoryLocations_ = InventoryParser::parseLocations(persistentSettings_.invLocations());

    if (!persistentSettings_.invServers().empty()) {
        std::int64_t storedRevision = 0;
        InventoryParser::deserializeServers(persistentSettings_.invServers(), inventoryServers_, storedRevision);
        // Prefer the separately stored revision — it stays current even when only an
        // empty delta arrived (no server data changed) and serializeServers was skipped.
        invRevision_ = persistentSettings_.invRevision() > 0
                           ? persistentSettings_.invRevision()
                           : storedRevision;
        lastUpdateTimeMs_[RequestType::kInventoryServers] = { steady_clock::now(), true };
    }

    // Pre-build serverLocations_ from cache so the client has immediate data.
    rebuildServerLocations();
}

ApiResourcesManager::~ApiResourcesManager()
{
    fetchTimer_.cancel();
    for (const auto &it : requestsInProgress_)
        it.second->cancel();
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

std::shared_ptr<WSNetCancelableCallback> ApiResourcesManager::setCallback(WSNetApiResourcesManagerCallback callback)
{
    std::lock_guard locker(mutex_);
    if (callback == nullptr) {
        callback_.reset();
        return nullptr;
    }
    callback_ = std::make_shared<CancelableCallback<WSNetApiResourcesManagerCallback>>(callback);
    return callback_;
}

void ApiResourcesManager::setAuthHash(const std::string &authHash)
{
    std::lock_guard locker(mutex_);
    persistentSettings_.setAuthHash(authHash);
}

bool ApiResourcesManager::isExist() const
{
    std::lock_guard locker(mutex_);
    return !persistentSettings_.authHash().empty() &&
           !persistentSettings_.sessionStatus().empty() &&
           !persistentSettings_.invLocations().empty() &&
           !persistentSettings_.invServers().empty() &&
           !persistentSettings_.serverCredentialsOvpn().empty() &&
           !persistentSettings_.serverCredentialsIkev2().empty() &&
           !persistentSettings_.serverConfigs().empty() &&
           !persistentSettings_.portMap().empty() &&
           !persistentSettings_.staticIps().empty() &&
           !persistentSettings_.notifications().empty();
}

bool ApiResourcesManager::loginWithAuthHash()
{
    std::lock_guard locker(mutex_);

    if (requestsInProgress_.find(RequestType::kSessionStatus) != requestsInProgress_.end()) {
        g_logger->error("Incorrect use of API, ApiResourcesManager::loginWithAuthHash called twice");
        assert(false);
    }

    if (persistentSettings_.authHash().empty())
        return false;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kSessionStatus] = serverAPI_->session(
        persistentSettings_.authHash(), appleId_, gpDeviceId_, invRevision_, backup_,
        std::bind(&ApiResourcesManager::onInitialSessionAnswer, this, _1, _2));

    return true;
}

void ApiResourcesManager::authTokenLogin(const std::string &username, bool useAsciiCaptcha)
{
    std::lock_guard locker(mutex_);
    if (requestsInProgress_.find(RequestType::kAuthToken) != requestsInProgress_.end()) {
        g_logger->error("Incorrect use of API, ApiResourcesManager::authTokenLogin called twice");
        assert(false);
    }
    using namespace std::placeholders;
    requestsInProgress_[RequestType::kAuthToken] = serverAPI_->authTokenLogin(
        username, useAsciiCaptcha,
        std::bind(&ApiResourcesManager::onAuthTokenAnswer, this, username, useAsciiCaptcha, _1, _2, true));
}

void ApiResourcesManager::authTokenSignup(const std::string &username, bool useAsciiCaptcha)
{
    std::lock_guard locker(mutex_);
    if (requestsInProgress_.find(RequestType::kAuthToken) != requestsInProgress_.end()) {
        g_logger->error("Incorrect use of API, ApiResourcesManager::authTokenSignup called twice");
        assert(false);
    }
    using namespace std::placeholders;
    requestsInProgress_[RequestType::kAuthToken] = serverAPI_->authTokenSignup(
        username, useAsciiCaptcha,
        std::bind(&ApiResourcesManager::onAuthTokenAnswer, this, username, useAsciiCaptcha, _1, _2, false));
}

void ApiResourcesManager::login(const std::string &username, const std::string &password,
                                const std::string &code2fa, const std::string &secureToken,
                                const std::string &captchaSolution,
                                const std::vector<float> &captchaTrailX,
                                const std::vector<float> &captchaTrailY)
{
    std::lock_guard locker(mutex_);

    if (requestsInProgress_.find(RequestType::kSessionStatus) != requestsInProgress_.end()) {
        g_logger->error("Incorrect use of API, ApiResourcesManager::login called twice");
        assert(false);
    }

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kSessionStatus] = serverAPI_->login(
        username, password, code2fa, secureToken, captchaSolution, captchaTrailX, captchaTrailY,
        std::bind(&ApiResourcesManager::onLoginAnswer, this, _1, _2,
                  username, password, code2fa, secureToken,
                  captchaSolution, captchaTrailX, captchaTrailY));
}

void ApiResourcesManager::signup(const std::string &username, const std::string &password,
                                  const std::string &referringUsername, const std::string &email,
                                  const std::string &voucherCode, const std::string &secureToken,
                                  const std::string &captchaSolution,
                                  const std::vector<float> &captchaTrailX,
                                  const std::vector<float> &captchaTrailY)
{
    std::lock_guard locker(mutex_);

    if (requestsInProgress_.find(RequestType::kSessionStatus) != requestsInProgress_.end()) {
        g_logger->error("Incorrect use of API, ApiResourcesManager::signup called twice");
        assert(false);
    }

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kSessionStatus] = serverAPI_->signup(
        username, password, referringUsername, email, voucherCode, secureToken,
        captchaSolution, captchaTrailX, captchaTrailY,
        std::bind(&ApiResourcesManager::onSignupAnswer, this, _1, _2,
                  username, password, referringUsername, email, voucherCode, secureToken,
                  captchaSolution, captchaTrailX, captchaTrailY));
}

void ApiResourcesManager::logout()
{
    std::lock_guard locker(mutex_);
    fetchTimer_.cancel();

    using namespace std::placeholders;
    serverAPI_->deleteSession(persistentSettings_.authHash(),
                              std::bind(&ApiResourcesManager::onDeleteSessionAnswer, this, _1, _2));
    clearValues();
}

void ApiResourcesManager::fetchSession()
{
    std::lock_guard locker(mutex_);
    lastUpdateTimeMs_.erase(RequestType::kSessionStatus);
}

void ApiResourcesManager::fetchServerCredentials()
{
    std::lock_guard locker(mutex_);
    assert(!isFetchingServerCredentials_);
    isFetchingServerCredentials_ = true;
    isOpenVpnCredentialsReceived_ = false;
    isIkev2CredentialsReceived_   = false;
    isServerConfigsReceived_      = false;

    lastUpdateTimeMs_.erase(RequestType::kServerCredentialsOpenVPN);
    lastUpdateTimeMs_.erase(RequestType::kServerCredentialsIkev2);
    lastUpdateTimeMs_.erase(RequestType::kServerConfigs);

    auto authHash = persistentSettings_.authHash();
    fetchServerCredentialsOpenVpn(authHash);
    fetchServerCredentialsIkev2(authHash);
    fetchServerConfigs(authHash);
}

std::string ApiResourcesManager::authHash()
{
    return persistentSettings_.authHash();
}

void ApiResourcesManager::removeFromPersistentSettings()
{
    std::lock_guard locker(mutex_);
    clearValues();
}

void ApiResourcesManager::checkUpdate(UpdateChannel channel, const std::string &appVersion,
                                       const std::string &appBuild, const std::string &osVersion,
                                       const std::string &osBuild)
{
    std::lock_guard locker(mutex_);
    checkUpdateData_.channel    = channel;
    checkUpdateData_.appVersion = appVersion;
    checkUpdateData_.appBuild   = appBuild;
    checkUpdateData_.osVersion  = osVersion;
    checkUpdateData_.osBuild    = osBuild;
    lastUpdateTimeMs_.erase(RequestType::kCheckUpdate);
    isCheckUpdateDataSet_ = true;
}

void ApiResourcesManager::setNotificationPcpid(const std::string &pcpid)
{
    std::lock_guard locker(mutex_);
    pcpidNotifications_ = pcpid;
}

void ApiResourcesManager::setMobileDeviceId(const std::string &appleId, const std::string &gpDeviceId)
{
    std::lock_guard locker(mutex_);
    appleId_    = appleId;
    gpDeviceId_ = gpDeviceId;
}

void ApiResourcesManager::setBackup(std::int32_t backup)
{
    std::lock_guard locker(mutex_);
    if (backup_ != backup) {
        g_logger->info("ApiResourcesManager: backup parameter changed from {} to {}", backup_, backup);
        backup_ = backup;
        forceRefetchSessionStatus_ = true;
        forceRefetchInventoryServers_ = true;
    }
}

std::string ApiResourcesManager::sessionStatus() const  { return persistentSettings_.sessionStatus(); }
std::string ApiResourcesManager::portMap() const         { return persistentSettings_.portMap(); }
std::string ApiResourcesManager::staticIps() const       { return persistentSettings_.staticIps(); }
std::string ApiResourcesManager::serverCredentialsOvpn() const  { return persistentSettings_.serverCredentialsOvpn(); }
std::string ApiResourcesManager::serverCredentialsIkev2() const { return persistentSettings_.serverCredentialsIkev2(); }
std::string ApiResourcesManager::serverConfigs() const   { return persistentSettings_.serverConfigs(); }
std::string ApiResourcesManager::notifications() const   { return persistentSettings_.notifications(); }
std::string ApiResourcesManager::amneziawgUnblockParams() const { return persistentSettings_.amneziawgUnblockParams(); }

std::shared_ptr<WSNetServerLocations> ApiResourcesManager::serverLocations() const
{
    std::lock_guard locker(mutex_);
    return serverLocations_;
}

std::string ApiResourcesManager::checkUpdate() const
{
    std::lock_guard locker(mutex_);
    return checkUpdate_;
}

std::string ApiResourcesManager::authTokenResult() const
{
    std::lock_guard locker(mutex_);
    return authTokenResult_;
}

void ApiResourcesManager::setUpdateIntervals(int sessionInDisconnectedStateMs, int sessionInConnectedStateMs,
                                              int locationsMs, int staticIpsMs, int serverConfigsAndCredentialsMs,
                                              int portMapMs, int notificationsMs, int checkUpdateMs,
                                              int amneziawgUnblockParamsMs)
{
    std::lock_guard locker(mutex_);
    sessionInDisconnectedStateMs_  = sessionInDisconnectedStateMs;
    sessionInConnectedStateMs_     = sessionInConnectedStateMs;
    locationsMs_                   = locationsMs;
    staticIpsMs_                   = staticIpsMs;
    serverConfigsAndCredentialsMs_ = serverConfigsAndCredentialsMs;
    portMapMs_                     = portMapMs;
    notificationsMs_               = notificationsMs;
    checkUpdateMs_                 = checkUpdateMs;
    amneziawgUnblockParamsMs_      = amneziawgUnblockParamsMs;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

bool ApiResourcesManager::rebuildServerLocations()
{
    if (inventoryLocations_.empty() || inventoryServers_.empty())
        return false;
    serverLocations_ = InventoryParser::buildServerLocations(inventoryLocations_, inventoryServers_);
    return serverLocations_ != nullptr;
}

bool ApiResourcesManager::applyInventoryDelta(const std::string &sessionJson)
{
    ServerInventoryDelta delta = InventoryParser::parseDelta(sessionJson);

    if (delta.action == ServerInventoryDelta::Action::kNone)
        return false;

    if (delta.action == ServerInventoryDelta::Action::kHold) {
        g_logger->info("ApiResourcesManager: server_inventory hold, keeping revision {}", invRevision_);
        return false;
    }

    // action == kDelta
    bool changed = !delta.enabled.empty() || !delta.disabled.empty();

    for (const auto &srv : delta.enabled)
        inventoryServers_[srv.id] = srv;

    for (int id : delta.disabled)
        inventoryServers_.erase(id);

    invRevision_ = delta.revision;
    // Always persist the new revision cheaply as a bare integer.
    persistentSettings_.setInvRevision(invRevision_);

    if (changed) {
        // Re-serialize the full server map only when its contents actually changed.
        persistentSettings_.setInvServers(
            InventoryParser::serializeServers(inventoryServers_, invRevision_));

        if (!inventoryLocations_.empty()) {
            serverLocations_ = InventoryParser::buildServerLocations(inventoryLocations_, inventoryServers_);
            return true;
        }
    }

    return false;
}

void ApiResourcesManager::handleLoginOrSessionAnswer(ServerApiRetCode serverApiRetCode,
                                                      const std::string &jsonData)
{
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        std::unique_ptr<SessionStatus> ss(SessionStatus::createFromJson(jsonData));
        if (ss) {
            if (ss->errorCode() == SessionErrorCode::kSuccess) {
                sessionStatus_ = std::move(ss);
                persistentSettings_.setSessionStatus(jsonData);
                if (!sessionStatus_->authHash().empty())
                    persistentSettings_.setAuthHash(sessionStatus_->authHash());

                lastUpdateTimeMs_[RequestType::kSessionStatus] = { steady_clock::now(), true };

                // Apply any inventory delta embedded in the login/session response.
                applyInventoryDelta(jsonData);

                updateSessionStatus();
                checkForReadyLogin();
                fetchAll();

                fetchTimer_.async_wait(
                    std::bind(&ApiResourcesManager::onFetchTimer, this, std::placeholders::_1));

            } else if (ss->errorCode() == SessionErrorCode::kBadUsername) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kBadUsername, ss->errorMessage());
            } else if (ss->errorCode() == SessionErrorCode::kMissingCode2FA) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kMissingCode2fa, ss->errorMessage());
            } else if (ss->errorCode() == SessionErrorCode::kBadCode2FA) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kBadCode2fa, ss->errorMessage());
            } else if (ss->errorCode() == SessionErrorCode::kAccountDisabled) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kAccountDisabled, ss->errorMessage());
            } else if (ss->errorCode() == SessionErrorCode::kSessionInvalid) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kSessionInvalid, ss->errorMessage());
            } else if (ss->errorCode() == SessionErrorCode::kRateLimited) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kRateLimited, ss->errorMessage());
            } else if (ss->errorCode() == SessionErrorCode::kInvalidSecurityToken) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kInvalidSecurityToken, ss->errorMessage());
            } else if (ss->errorCode() == SessionErrorCode::kUnknownError) {
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kSomeError, ss->errorMessage());
            } else {
                assert(false);
                callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kNoApiConnectivity, ss->errorMessage());
            }
        } else {
            callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kIncorrectJson, std::string());
        }
    } else if (serverApiRetCode == ServerApiRetCode::kNoNetworkConnection) {
        callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kNoConnectivity, std::string());
    } else if (serverApiRetCode == ServerApiRetCode::kIncorrectJson) {
        callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kIncorrectJson, std::string());
    } else if (serverApiRetCode == ServerApiRetCode::kFailoverFailed) {
        callback_->call(ApiResourcesManagerNotification::kLoginFailed, LoginResult::kNoApiConnectivity, std::string());
    } else {
        assert(false);
    }
}

void ApiResourcesManager::checkForReadyLogin()
{
    if (!persistentSettings_.authHash().empty() &&
        !persistentSettings_.sessionStatus().empty() &&
        !persistentSettings_.invLocations().empty() &&
        !persistentSettings_.invServers().empty() &&
        !persistentSettings_.serverCredentialsOvpn().empty() &&
        !persistentSettings_.serverCredentialsIkev2().empty() &&
        !persistentSettings_.serverConfigs().empty() &&
        !persistentSettings_.portMap().empty() &&
        !persistentSettings_.staticIps().empty() &&
        !persistentSettings_.notifications().empty() &&
        !persistentSettings_.amneziawgUnblockParams().empty())
    {
        if (!isLoginOkEmitted_) {
            isLoginOkEmitted_ = true;
            callback_->call(ApiResourcesManagerNotification::kLoginOk, LoginResult::kSuccess, std::string());
        }
    }
}

void ApiResourcesManager::checkForServerCredentialsFetchFinished()
{
    if (isFetchingServerCredentials_ &&
        isOpenVpnCredentialsReceived_ &&
        isIkev2CredentialsReceived_ &&
        isServerConfigsReceived_)
    {
        isFetchingServerCredentials_ = false;
        callback_->call(ApiResourcesManagerNotification::kServerCredentialsUpdated, LoginResult::kSuccess, std::string());
    }
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

void ApiResourcesManager::fetchAll()
{
    // Session — with current inv_rev for delta delivery.
    if (connectState_->isVPNConnected()) {
        if (isTimeoutForRequest(RequestType::kSessionStatus, sessionInConnectedStateMs_) || forceRefetchSessionStatus_)
            if (fetchSession(persistentSettings_.authHash())) {
                forceRefetchSessionStatus_ = false;
            }
    } else {
        if (isTimeoutForRequest(RequestType::kSessionStatus, sessionInDisconnectedStateMs_) || forceRefetchSessionStatus_)
            if (fetchSession(persistentSettings_.authHash())) {
                forceRefetchSessionStatus_ = false;
            }
    }

    // Inventory locations — infrequently changing metadata (countries / datacenters), every 24h
    if (isTimeoutForRequest(RequestType::kInventoryLocations, locationsMs_))
        fetchInventoryLocations();

    // Full server list — safety fallback; delta updates arrive via session polls, every 24h and on the first start
    if (isTimeoutForRequest(RequestType::kInventoryServers, locationsMs_) || forceRefetchInventoryServers_) {
        if (fetchInventoryServers()) {
            forceRefetchInventoryServers_ = false;
        }
    }

    // Static IPs every 24h.
    if (isTimeoutForRequest(RequestType::kStaticIps, staticIpsMs_))
        fetchStaticIps(persistentSettings_.authHash());

    // Server configs + credentials every 24h.
    if (isTimeoutForRequest(RequestType::kServerConfigs, serverConfigsAndCredentialsMs_))
        fetchServerConfigs(persistentSettings_.authHash());
    if (isTimeoutForRequest(RequestType::kServerCredentialsOpenVPN, serverConfigsAndCredentialsMs_))
        fetchServerCredentialsOpenVpn(persistentSettings_.authHash());
    if (isTimeoutForRequest(RequestType::kServerCredentialsIkev2, serverConfigsAndCredentialsMs_))
        fetchServerCredentialsIkev2(persistentSettings_.authHash());

    // Port map every 24h.
    if (isTimeoutForRequest(RequestType::kPortMap, portMapMs_))
        fetchPortMap(persistentSettings_.authHash());

    // Notifications every 1h.
    if (isTimeoutForRequest(RequestType::kNotifications, notificationsMs_))
        fetchNotifications(persistentSettings_.authHash());

    // Check update every 24h.
    if (isCheckUpdateDataSet_ && isTimeoutForRequest(RequestType::kCheckUpdate, checkUpdateMs_))
        fetchCheckUpdate();

    // AmneziaWG unblock params every 24h.
    if (isTimeoutForRequest(RequestType::kAmneziawgUnblockParams, amneziawgUnblockParamsMs_))
        fetchAmneziawgUnblockParams(persistentSettings_.authHash());
}

bool ApiResourcesManager::fetchSession(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kSessionStatus) != requestsInProgress_.end())
        return false;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kSessionStatus] = serverAPI_->session(
        authHash, appleId_, gpDeviceId_, invRevision_, backup_,
        std::bind(&ApiResourcesManager::onSessionAnswer, this, _1, _2));
    return true;
}

void ApiResourcesManager::fetchInventoryLocations()
{
    if (requestsInProgress_.find(RequestType::kInventoryLocations) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kInventoryLocations] = serverAPI_->getLocations(
        persistentSettings_.authHash(),
        std::bind(&ApiResourcesManager::onInventoryLocationsAnswer, this, _1, _2));
}

bool ApiResourcesManager::fetchInventoryServers()
{
    if (requestsInProgress_.find(RequestType::kInventoryServers) != requestsInProgress_.end())
        return false;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kInventoryServers] = serverAPI_->getServers(
        persistentSettings_.authHash(), backup_,
        std::bind(&ApiResourcesManager::onInventoryServersAnswer, this, _1, _2));
    return true;
}

void ApiResourcesManager::fetchStaticIps(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kStaticIps) != requestsInProgress_.end())
        return;

    if (sessionStatus_->staticIpsCount() > 0) {
        using namespace std::placeholders;
        requestsInProgress_[RequestType::kStaticIps] = serverAPI_->staticIps(
            authHash, 2,
            std::bind(&ApiResourcesManager::onStaticIpsAnswer, this, _1, _2));
    } else {
        persistentSettings_.setStaticIps("{}");
        lastUpdateTimeMs_[RequestType::kStaticIps] = { steady_clock::now(), true };
        if (isLoginOkEmitted_)
            callback_->call(ApiResourcesManagerNotification::kStaticIpsUpdated, LoginResult::kSuccess, std::string());
        else
            checkForReadyLogin();
    }
}

void ApiResourcesManager::fetchServerConfigs(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kServerConfigs) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kServerConfigs] = serverAPI_->serverConfigs(
        authHash, std::bind(&ApiResourcesManager::onServerConfigsAnswer, this, _1, _2));
}

void ApiResourcesManager::fetchServerCredentialsOpenVpn(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kServerCredentialsOpenVPN) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kServerCredentialsOpenVPN] = serverAPI_->serverCredentials(
        authHash, true,
        std::bind(&ApiResourcesManager::onServerCredentialsOpenVpnAnswer, this, _1, _2));
}

void ApiResourcesManager::fetchServerCredentialsIkev2(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kServerCredentialsIkev2) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kServerCredentialsIkev2] = serverAPI_->serverCredentials(
        authHash, false,
        std::bind(&ApiResourcesManager::onServerCredentialsIkev2Answer, this, _1, _2));
}

void ApiResourcesManager::fetchPortMap(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kPortMap) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kPortMap] = serverAPI_->portMap(
        authHash, 6, std::vector<std::string>(),
        std::bind(&ApiResourcesManager::onPortMapAnswer, this, _1, _2));
}

void ApiResourcesManager::fetchNotifications(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kNotifications) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kNotifications] = serverAPI_->notifications(
        authHash, pcpidNotifications_,
        std::bind(&ApiResourcesManager::onNotificationsAnswer, this, _1, _2));
}

void ApiResourcesManager::fetchCheckUpdate()
{
    if (requestsInProgress_.find(RequestType::kCheckUpdate) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kCheckUpdate] = serverAPI_->checkUpdate(
        checkUpdateData_.channel, checkUpdateData_.appVersion, checkUpdateData_.appBuild,
        checkUpdateData_.osVersion, checkUpdateData_.osBuild,
        std::bind(&ApiResourcesManager::onCheckUpdateAnswer, this, _1, _2));
}

void ApiResourcesManager::fetchAmneziawgUnblockParams(const std::string &authHash)
{
    if (requestsInProgress_.find(RequestType::kAmneziawgUnblockParams) != requestsInProgress_.end())
        return;

    using namespace std::placeholders;
    requestsInProgress_[RequestType::kAmneziawgUnblockParams] = serverAPI_->amneziawgUnblockParams(
        authHash, std::bind(&ApiResourcesManager::onAmneziawgUnblockParamsAnswer, this, _1, _2));
}

// ---------------------------------------------------------------------------
// Session status change handling
// ---------------------------------------------------------------------------

void ApiResourcesManager::updateSessionStatus()
{
    assert(sessionStatus_);

    if (prevSessionStatus_) {
        if (prevSessionStatus_->isPremium()          != sessionStatus_->isPremium()         ||
            prevSessionStatus_->status()             != sessionStatus_->status()             ||
            prevSessionStatus_->rebill()             != sessionStatus_->rebill()             ||
            prevSessionStatus_->billingPlanId()      != sessionStatus_->billingPlanId()      ||
            prevSessionStatus_->premiumExpiredDate() != sessionStatus_->premiumExpiredDate() ||
            prevSessionStatus_->trafficMax()         != sessionStatus_->trafficMax()         ||
            prevSessionStatus_->username()           != sessionStatus_->username()           ||
            prevSessionStatus_->userId()             != sessionStatus_->userId()             ||
            prevSessionStatus_->email()              != sessionStatus_->email()              ||
            prevSessionStatus_->emailStatus()        != sessionStatus_->emailStatus()        ||
            prevSessionStatus_->staticIpsCount()     != sessionStatus_->staticIpsCount()     ||
            prevSessionStatus_->alcList()            != sessionStatus_->alcList()            ||
            prevSessionStatus_->lastResetDate()      != sessionStatus_->lastResetDate())
        {
            g_logger->info("update session status (changed since last call)");
            sessionStatus_->debugLog();
        }

        // Force a full server list refresh whenever the user's entitlement changes.
        // The delta system only covers changes within the user's current scope,
        // so a plan change requires a fresh full list.
        if (prevSessionStatus_->revisionHash()  != sessionStatus_->revisionHash()  ||
            prevSessionStatus_->isPremium()     != sessionStatus_->isPremium()     ||
            prevSessionStatus_->billingPlanId() != sessionStatus_->billingPlanId() ||
            prevSessionStatus_->alcList()       != sessionStatus_->alcList()       ||
            (prevSessionStatus_->status() != 1 && sessionStatus_->status() == 1))
        {
            fetchInventoryLocations();
            fetchInventoryServers();
        }

        if (prevSessionStatus_->revisionHash()    != sessionStatus_->revisionHash()    ||
            prevSessionStatus_->staticIpsCount()  != sessionStatus_->staticIpsCount()  ||
            sessionStatus_->isContainsStaticDeviceId(Settings::instance().deviceId())  ||
            prevSessionStatus_->isPremium()       != sessionStatus_->isPremium()       ||
            prevSessionStatus_->billingPlanId()   != sessionStatus_->billingPlanId())
        {
            fetchStaticIps(persistentSettings_.authHash());
        }

        if (prevSessionStatus_->isPremium()     != sessionStatus_->isPremium()     ||
            prevSessionStatus_->billingPlanId() != sessionStatus_->billingPlanId())
        {
            fetchServerCredentialsOpenVpn(persistentSettings_.authHash());
            fetchServerCredentialsIkev2(persistentSettings_.authHash());
            fetchNotifications(persistentSettings_.authHash());
        }

        if (prevSessionStatus_->status() == 2 && sessionStatus_->status() == 1) {
            fetchServerCredentialsOpenVpn(persistentSettings_.authHash());
            fetchServerCredentialsIkev2(persistentSettings_.authHash());
        }
    } else {
        g_logger->info("update session status (changed since last call)");
        fetchInventoryServers();
        sessionStatus_->debugLog();
    }

    prevSessionStatus_ = std::make_unique<SessionStatus>(sessionStatus_.get());
    if (isLoginOkEmitted_)
        callback_->call(ApiResourcesManagerNotification::kSessionUpdated, LoginResult::kSuccess, std::string());
}

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

void ApiResourcesManager::onFetchTimer(const boost::system::error_code &err)
{
    if (err) return;

    std::lock_guard locker(mutex_);

    if (!persistentSettings_.authHash().empty()) {
        fetchAll();
    } else {
        g_logger->error("ApiResourcesManager::onFetchTimer: authHash is empty");
        assert(false);
    }

    fetchTimer_.expires_after(boost::asio::chrono::seconds(1));
    fetchTimer_.async_wait(std::bind(&ApiResourcesManager::onFetchTimer, this, std::placeholders::_1));
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

void ApiResourcesManager::onAuthTokenAnswer(const std::string &username, bool useAsciiCaptcha,
                                             ServerApiRetCode serverApiRetCode,
                                             const std::string &jsonData, bool isLoginCall)
{
    std::lock_guard locker(mutex_);
    requestsInProgress_.erase(RequestType::kAuthToken);

    if (serverApiRetCode == ServerApiRetCode::kNetworkError) {
        boost::asio::post(io_context_, [this, username, useAsciiCaptcha, isLoginCall] {
            if (isLoginCall) authTokenLogin(username, useAsciiCaptcha);
            else             authTokenSignup(username, useAsciiCaptcha);
        });
    } else if (serverApiRetCode == ServerApiRetCode::kNoNetworkConnection) {
        callback_->call(ApiResourcesManagerNotification::kAuthTokenFinished, LoginResult::kNoConnectivity, std::string());
    } else if (serverApiRetCode == ServerApiRetCode::kIncorrectJson) {
        callback_->call(ApiResourcesManagerNotification::kAuthTokenFinished, LoginResult::kIncorrectJson, std::string());
    } else if (serverApiRetCode == ServerApiRetCode::kFailoverFailed) {
        callback_->call(ApiResourcesManagerNotification::kAuthTokenFinished, LoginResult::kNoApiConnectivity, std::string());
    } else {
        authTokenResult_ = (serverApiRetCode == ServerApiRetCode::kSuccess) ? jsonData : std::string();
        callback_->call(ApiResourcesManagerNotification::kAuthTokenFinished, LoginResult::kSuccess, std::string());
    }
}

void ApiResourcesManager::onInitialSessionAnswer(ServerApiRetCode serverApiRetCode,
                                                  const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    requestsInProgress_.erase(RequestType::kSessionStatus);

    if (serverApiRetCode == ServerApiRetCode::kNetworkError) {
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context_);
        timer->expires_after(std::chrono::seconds(1));
        timer->async_wait([this, timer](const boost::system::error_code &ec) {
            if (!ec) loginWithAuthHash();
        });
    } else {
        handleLoginOrSessionAnswer(serverApiRetCode, jsonData);
    }
}

void ApiResourcesManager::onLoginAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData,
                                         const std::string &username, const std::string &password,
                                         const std::string &code2fa, const std::string &secureToken,
                                         const std::string &captchaSolution,
                                         const std::vector<float> &captchaTrailX,
                                         const std::vector<float> &captchaTrailY)
{
    std::lock_guard locker(mutex_);
    requestsInProgress_.erase(RequestType::kSessionStatus);

    if (serverApiRetCode == ServerApiRetCode::kNetworkError) {
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context_);
        timer->expires_after(std::chrono::seconds(1));
        timer->async_wait([this, timer, username, password, code2fa, secureToken,
                           captchaSolution, captchaTrailX, captchaTrailY](const boost::system::error_code &ec) {
            if (!ec) login(username, password, code2fa, secureToken, captchaSolution, captchaTrailX, captchaTrailY);
        });
    } else {
        handleLoginOrSessionAnswer(serverApiRetCode, jsonData);
    }
}

void ApiResourcesManager::onSignupAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData,
                                          const std::string &username, const std::string &password,
                                          const std::string &referringUsername, const std::string &email,
                                          const std::string &voucherCode, const std::string &secureToken,
                                          const std::string &captchaSolution,
                                          const std::vector<float> &captchaTrailX,
                                          const std::vector<float> &captchaTrailY)
{
    std::lock_guard locker(mutex_);
    requestsInProgress_.erase(RequestType::kSessionStatus);

    if (serverApiRetCode == ServerApiRetCode::kNetworkError) {
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context_);
        timer->expires_after(std::chrono::seconds(1));
        timer->async_wait([this, timer, username, password, referringUsername, email, voucherCode,
                           secureToken, captchaSolution, captchaTrailX, captchaTrailY](const boost::system::error_code &ec) {
            if (!ec) signup(username, password, referringUsername, email, voucherCode, secureToken,
                            captchaSolution, captchaTrailX, captchaTrailY);
        });
    } else {
        handleLoginOrSessionAnswer(serverApiRetCode, jsonData);
    }
}

void ApiResourcesManager::onSessionAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData)
{
    std::lock_guard locker(mutex_);

    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        std::unique_ptr<SessionStatus> ss(SessionStatus::createFromJson(jsonData));
        if (ss) {
            if (ss->errorCode() == SessionErrorCode::kSuccess) {
                sessionStatus_ = std::move(ss);
                persistentSettings_.setSessionStatus(jsonData);
                updateSessionStatus();

                // Apply the server_inventory delta and notify the client if anything changed.
                bool serverListChanged = applyInventoryDelta(jsonData);
                if (serverListChanged && isLoginOkEmitted_)
                    callback_->call(ApiResourcesManagerNotification::kLocationsUpdated, LoginResult::kSuccess, std::string());

            } else if (ss->errorCode() == SessionErrorCode::kSessionInvalid) {
                callback_->call(ApiResourcesManagerNotification::kSessionDeleted, LoginResult::kSuccess, std::string());
            }
        }
    }

    lastUpdateTimeMs_[RequestType::kSessionStatus] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kSessionStatus);
}

void ApiResourcesManager::onInventoryLocationsAnswer(ServerApiRetCode serverApiRetCode,
                                                      const std::string &jsonData)
{
    std::lock_guard locker(mutex_);

    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        auto parsed = InventoryParser::parseLocations(jsonData);
        if (!parsed.empty()) {
            bool locationsChanged = (parsed != inventoryLocations_);
            if (locationsChanged) {
                inventoryLocations_ = std::move(parsed);
                persistentSettings_.setInvLocations(jsonData);
            }

            if (locationsChanged || !serverLocations_) {
                bool rebuilt = rebuildServerLocations();
                if (isLoginOkEmitted_) {
                    if (rebuilt)
                        callback_->call(ApiResourcesManagerNotification::kLocationsUpdated, LoginResult::kSuccess, std::string());
                } else {
                    checkForReadyLogin();
                }
            } else {
                g_logger->info("ApiResourcesManager::onInventoryLocationsAnswer: locations unchanged, suppressing kLocationsUpdated");
                if (!isLoginOkEmitted_)
                    checkForReadyLogin();
            }
        } else {
            g_logger->error("ApiResourcesManager::onInventoryLocationsAnswer: failed to parse locations JSON");
        }
    }

    lastUpdateTimeMs_[RequestType::kInventoryLocations] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kInventoryLocations);
}

void ApiResourcesManager::onInventoryServersAnswer(ServerApiRetCode serverApiRetCode,
                                                    const std::string &jsonData)
{
    std::lock_guard locker(mutex_);

    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        std::map<int, InventoryServer> newServers;
        std::int64_t newRevision = 0;

        if (InventoryParser::parseServers(jsonData, newServers, newRevision)) {
            bool serversChanged = (newServers != inventoryServers_);

            // Always persist the new revision — it may advance even without server changes.
            invRevision_ = newRevision;
            persistentSettings_.setInvRevision(invRevision_);

            if (serversChanged) {
                inventoryServers_ = std::move(newServers);
                persistentSettings_.setInvServers(
                    InventoryParser::serializeServers(inventoryServers_, invRevision_));
            }

            if (serversChanged || !serverLocations_) {
                bool rebuilt = rebuildServerLocations();
                if (isLoginOkEmitted_) {
                    if (rebuilt)
                        callback_->call(ApiResourcesManagerNotification::kLocationsUpdated, LoginResult::kSuccess, std::string());
                } else {
                    checkForReadyLogin();
                }
            } else {
                g_logger->info("ApiResourcesManager::onInventoryServersAnswer: servers unchanged, suppressing kLocationsUpdated");
                if (!isLoginOkEmitted_)
                    checkForReadyLogin();
            }
        } else {
            g_logger->error("ApiResourcesManager::onInventoryServersAnswer: failed to parse servers JSON");
        }
    }

    lastUpdateTimeMs_[RequestType::kInventoryServers] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kInventoryServers);
}

void ApiResourcesManager::onStaticIpsAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        persistentSettings_.setStaticIps(jsonData);
        checkForReadyLogin();
        if (isLoginOkEmitted_)
            callback_->call(ApiResourcesManagerNotification::kStaticIpsUpdated, LoginResult::kSuccess, std::string());
    }
    lastUpdateTimeMs_[RequestType::kStaticIps] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kStaticIps);
}

void ApiResourcesManager::onServerConfigsAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        persistentSettings_.setServerConfigs(jsonData);
        isServerConfigsReceived_ = true;
        checkForServerCredentialsFetchFinished();
        checkForReadyLogin();
    }
    lastUpdateTimeMs_[RequestType::kServerConfigs] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kServerConfigs);
}

void ApiResourcesManager::onServerCredentialsOpenVpnAnswer(ServerApiRetCode serverApiRetCode,
                                                            const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        persistentSettings_.setServerCredentialsOvpn(jsonData);
        isOpenVpnCredentialsReceived_ = true;
        checkForServerCredentialsFetchFinished();
        checkForReadyLogin();
    }
    lastUpdateTimeMs_[RequestType::kServerCredentialsOpenVPN] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kServerCredentialsOpenVPN);
}

void ApiResourcesManager::onServerCredentialsIkev2Answer(ServerApiRetCode serverApiRetCode,
                                                          const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        persistentSettings_.setServerCredentialsIkev2(jsonData);
        isIkev2CredentialsReceived_ = true;
        checkForServerCredentialsFetchFinished();
        checkForReadyLogin();
    }
    lastUpdateTimeMs_[RequestType::kServerCredentialsIkev2] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kServerCredentialsIkev2);
}

void ApiResourcesManager::onPortMapAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        persistentSettings_.setPortMap(jsonData);
        checkForReadyLogin();
    }
    lastUpdateTimeMs_[RequestType::kPortMap] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kPortMap);
}

void ApiResourcesManager::onNotificationsAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        persistentSettings_.setNotifications(jsonData);
        if (isLoginOkEmitted_)
            callback_->call(ApiResourcesManagerNotification::kNotificationsUpdated, LoginResult::kSuccess, std::string());
        else
            checkForReadyLogin();
    }
    lastUpdateTimeMs_[RequestType::kNotifications] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kNotifications);
}

void ApiResourcesManager::onCheckUpdateAnswer(ServerApiRetCode serverApiRetCode, const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        checkUpdate_ = jsonData;
        callback_->call(ApiResourcesManagerNotification::kCheckUpdate, LoginResult::kSuccess, std::string());
    }
    lastUpdateTimeMs_[RequestType::kCheckUpdate] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kCheckUpdate);
}

void ApiResourcesManager::onAmneziawgUnblockParamsAnswer(ServerApiRetCode serverApiRetCode,
                                                          const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    if (serverApiRetCode == ServerApiRetCode::kSuccess) {
        persistentSettings_.setAmneziawgUnblockParams(jsonData);
        if (isLoginOkEmitted_)
            callback_->call(ApiResourcesManagerNotification::kAmneziawgUnblockParamsFinished, LoginResult::kSuccess, std::string());
        else
            checkForReadyLogin();
    }
    lastUpdateTimeMs_[RequestType::kAmneziawgUnblockParams] = { steady_clock::now(), serverApiRetCode == ServerApiRetCode::kSuccess };
    requestsInProgress_.erase(RequestType::kAmneziawgUnblockParams);
}

void ApiResourcesManager::onDeleteSessionAnswer(ServerApiRetCode serverApiRetCode,
                                                 const std::string &jsonData)
{
    std::lock_guard locker(mutex_);
    g_logger->info("ApiResourcesManager::onDeleteSessionAnswer retCode: {}", (int)serverApiRetCode);
    callback_->call(ApiResourcesManagerNotification::kLogoutFinished, LoginResult::kSuccess, std::string());
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

bool ApiResourcesManager::isTimeoutForRequest(RequestType requestType, int timeout)
{
    auto it = lastUpdateTimeMs_.find(requestType);
    if (it == lastUpdateTimeMs_.end())
        return true;

    if (it->second.isRequestSuccess) {
        return utils::since(it->second.updateTime).count() > timeout;
    } else {
        return utils::since(it->second.updateTime).count() > kDelayBetweenFailedRequests;
    }
}

void ApiResourcesManager::clearValues()
{
    g_logger->info("ApiResourcesManager::clearValues");
    isFetchingServerCredentials_ = false;
    isLoginOkEmitted_            = false;
    sessionStatus_.reset();
    prevSessionStatus_.reset();
    serverLocations_.reset();
    inventoryLocations_.clear();
    inventoryServers_.clear();
    invRevision_ = 0;
    checkUpdate_.clear();
    lastUpdateTimeMs_.clear();

    persistentSettings_.setAuthHash(std::string());
    persistentSettings_.setSessionStatus(std::string());
    persistentSettings_.setInvLocations(std::string());
    persistentSettings_.setInvServers(std::string());
    persistentSettings_.setInvRevision(0);
    persistentSettings_.setServerCredentialsOvpn(std::string());
    persistentSettings_.setServerCredentialsIkev2(std::string());
    persistentSettings_.setServerConfigs(std::string());
    persistentSettings_.setPortMap(std::string());
    persistentSettings_.setStaticIps(std::string());
    persistentSettings_.setNotifications(std::string());
    persistentSettings_.setAmneziawgUnblockParams(std::string());
    persistentSettings_.setSessionTokens({});
}

} // namespace wsnet
