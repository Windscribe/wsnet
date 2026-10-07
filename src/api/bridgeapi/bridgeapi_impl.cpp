#include "bridgeapi_impl.h"

#include "bridgeapi_utils.h"
#include "bridgeapi_requestsfactory.h"
#include "bridgetokenrequest.h"
#include "settings.h"
#include "utils/cancelablecallback.h"
#include "utils/utils.h"
#include "utils/wsnet_logger.h"
#include "utils/requesterror.h"

namespace wsnet {

BridgeAPI_impl::BridgeAPI_impl(WSNetHttpNetworkManager *httpNetworkManager, PersistentSettings &persistentSettings, WSNetAdvancedParameters *advancedParameters, std::shared_ptr<ConnectState> connectState) :
    httpNetworkManager_(httpNetworkManager),
    advancedParameters_(advancedParameters),
    connectState_(connectState),
    persistentSettings_(persistentSettings)
{
    std::lock_guard locker(sessionTokenMutex_);
    sessionTokens_ = persistentSettings_.sessionTokens();
}

BridgeAPI_impl::~BridgeAPI_impl()
{
    for (auto &it : activeHttpRequests_) {
        it.second.asyncCallback_->cancel();
    }

    // Clean up any queued pinIp request
    if (queuedPinIpRequest_) {
        queuedPinIpRequest_->setRetCode(ApiRetCode::kNoToken);
        queuedPinIpRequest_->callCallback();
        queuedPinIpRequest_.reset();
    }
    // Dropped without a callback, like the in-flight requests above: the io_context is stopped by
    // now and the waiter (TunnelTest) is destroyed before this object, so a callback would land in freed memory.
    queuedCheckIpRequests_.clear();
}

void BridgeAPI_impl::setConnectedState(bool isConnected)
{
    if (isConnected != isConnected_) {
        ++connectionGeneration_;
    }

    if (isConnected && !isConnected_) {
        auto nodeId = currentNodeId();
        if (isTokenRequestSuppressed()) {
            isFetchingToken_ = false;
            g_logger->info("BridgeAPI_impl::setConnectedState, suppressing token request for node {}", nodeId);
            if (apiAvailableCallback_) {
                apiAvailableCallback_(false);
            }
            if (queuedPinIpRequest_) {
                completeRequestAsNoop(std::move(queuedPinIpRequest_));
                queuedPinIpRequest_.reset();
            }
            isConnected_ = isConnected;
            return;
        }

        std::string currentToken;
        auto token = sessionToken();
        if (token) {
            if (token->second > 0) {
                // We have a valid token with an expiry time, check if it's expired
                auto now = std::chrono::system_clock::now();
                auto nowTimestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
                if (nowTimestamp >= token->second) {
                    g_logger->info("Removing expired session token for node {}", nodeId);
                    clearSessionToken();
                } else {
                    // Token is not expired, set expiry time to 0 since it's valid until disconnection
                    currentToken = token->first;
                    setSessionTokenForCurrentNode(currentToken, 0);
                }
            } else {
                currentToken = token->first;
            }
        }

        g_logger->info("BridgeAPI_impl::setConnectedState, fetching token for node {}{}", nodeId, currentToken.empty() ? "" : " with cached token");
        isFetchingToken_ = true;
        auto request = std::unique_ptr<BaseRequest>(bridgeapi_requests_factory::fetchToken(currentToken, nullptr));
        executeRequestImpl(std::move(request));
    } else if (!isConnected) {
        setSessionTokenExpiry();
        clearSessionTokenIfNodeless();
        isFetchingToken_ = false;

        // Clear any queued pinIp request since we're disconnected
        if (queuedPinIpRequest_) {
            g_logger->info("Clearing queued pinIp request due to disconnection");
            queuedPinIpRequest_->setRetCode(ApiRetCode::kNoNetworkConnection);
            queuedPinIpRequest_->callCallback();
            queuedPinIpRequest_.reset();
        }
        failQueuedCheckIpRequests(ApiRetCode::kNoNetworkConnection);

        // Notify that the API is no longer available
        if (apiAvailableCallback_) {
            apiAvailableCallback_(false);
        }
    }

    isConnected_ = isConnected;
}

void BridgeAPI_impl::setIgnoreSslErrors(bool bIgnore)
{
    bIgnoreSslErrors_ = bIgnore;
    g_logger->info("BridgeAPI_impl::setIgnoreSslErrors, {}", bIgnore);
}

// execute request if the failover detected or queue
void BridgeAPI_impl::executeRequest(std::unique_ptr<BaseRequest> request)
{
    // if request already canceled do nothing
    if (request->isCanceled()) {
        return;
    }

    // check if we are online
    if (!connectState_->isOnline() || !isConnected_) {
        request->setRetCode(ApiRetCode::kNoNetworkConnection);
        request->callCallback();
        return;
    }

    if (isTokenRequestSuppressed()) {
        completeRequestAsNoop(std::move(request));
        return;
    }

    // Check if we need a token and don't have one
    if (!sessionToken()) {
        request->setRetCode(ApiRetCode::kNoToken);
        request->callCallback();
        return;
    }
    applySessionToken(request);

    // in the connected mode always use the primary domain
    executeRequestImpl(std::move(request));
}

void BridgeAPI_impl::executeRequestImpl(std::unique_ptr<BaseRequest> request)
{
    using namespace std::placeholders;

    g_logger->info("BridgeAPI_impl::executeRequestImpl, bIgnoreSslErrors_: {}", bIgnoreSslErrors_);
    auto httpRequest = serverapi_utils::createHttpRequest(httpNetworkManager_, Settings::instance().bridgeApiAddress(), request.get(), bIgnoreSslErrors_, advancedParameters_->isAPIExtraTLSPadding());
    httpRequest->setIsDebugLogCurlError(true);
    std::uint64_t requestId = curUniqueId_++;
    auto asyncCallback_ = httpNetworkManager_->executeRequestEx(httpRequest, requestId, std::bind(&BridgeAPI_impl::onHttpNetworkRequestFinished, this, _1, _2, _3, _4),
                                                                std::bind(&BridgeAPI_impl::onHttpNetworkRequestProgressCallback, this, _1, _2, _3));
    HttpRequestInfo hti { std::move(request), asyncCallback_, connectionGeneration_ };
    activeHttpRequests_[requestId] = std::move(hti);
}

void BridgeAPI_impl::completeRequestAsNoop(std::unique_ptr<BaseRequest> request)
{
    if (!request) {
        return;
    }

    g_logger->info("BridgeAPI request '{}' no-op because token requests are suppressed", request->name());
    request->setRetCode(ApiRetCode::kSuccess);
    request->callCallback();
}

bool BridgeAPI_impl::isTokenRequestSuppressed() const
{
    return advancedParameters_ && advancedParameters_->isSuppressBridgeApiTokenRequest();
}

void BridgeAPI_impl::setErrorCodeAndEmitRequestFinished(BaseRequest *request, ApiRetCode retCode)
{
    request->setRetCode(retCode);
    request->callCallback();
}

void BridgeAPI_impl::onHttpNetworkRequestFinished(std::uint64_t requestId, std::uint32_t elapsedMs, std::shared_ptr<WSNetRequestError> error, const std::string &data)
{
    auto it = activeHttpRequests_.find(requestId);
    assert(it != activeHttpRequests_.end());

    if (it->second.request->isCanceled()) {
        activeHttpRequests_.erase(it);
        return;
    }

    // Answering about a tunnel that no longer exists. Its token belongs to a node and a source IP
    // we have left, and its outcome says nothing about the connection we are on now -- storing it
    // would put one node's token under another's key, which is the whole thing node ids prevent.
    if (it->second.generation != connectionGeneration_) {
        g_logger->info("BridgeAPI request '{}' finished on a previous connection, ignoring result", it->second.request->name());
        setErrorCodeAndEmitRequestFinished(it->second.request.get(), ApiRetCode::kNoNetworkConnection);
        activeHttpRequests_.erase(it);
        return;
    }

    // Extract HTTP response code from the error object
    int httpResponseCode = 0;
    auto requestError = std::dynamic_pointer_cast<RequestError>(error);
    if (requestError) {
        httpResponseCode = requestError->httpResponseCode();
    }

    // Check if this is a token fetch request
    auto tokenRequest = dynamic_cast<BridgeTokenRequest*>(it->second.request.get());
    bool isTokenRequest = (tokenRequest != nullptr);

    if (error->isSuccess() && httpResponseCode == 200) {
        if (advancedParameters_->isLogApiResponce()) {
            g_logger->info("API request {} finished", it->second.request->name());
            g_logger->info("{}", data);
        }
        it->second.request->handle(data);
        if (it->second.request->retCode() == ApiRetCode::kSuccess) {
            if (isTokenRequest) {
                isFetchingToken_ = false;
                std::string newToken = tokenRequest->getSessionToken();
                setSessionTokenForCurrentNode(newToken, 0);
                g_logger->info("Successfully received session token for node {}", currentNodeId());

                // Notify that the API is now available
                if (apiAvailableCallback_) {
                    apiAvailableCallback_(true);
                }

                // Execute any queued pinIp request now that we have a token
                if (queuedPinIpRequest_) {
                    g_logger->info("Executing queued pinIp request with fresh token");
                    executeRequest(std::move(queuedPinIpRequest_));
                    queuedPinIpRequest_.reset();
                }
                runQueuedCheckIpRequests();
            } else {
                it->second.request->callCallback();
            }
            activeHttpRequests_.erase(it);
            return;
        }
    }

    // Failure
    if (isTokenRequest) {
        auto token = sessionToken();
        // We have an existing token and server told us it's no good (i.e. httpResponseCode != 200), try getting a new one
        const bool isRetrying = token && error->isSuccess();
        if (isRetrying) {
            clearSessionToken();
            g_logger->info("Token request failed {} (HTTP response code: {}), clearing cached token for node {} and trying again", error->toString(), httpResponseCode, currentNodeId());
            auto request = std::unique_ptr<BaseRequest>(bridgeapi_requests_factory::fetchToken("", nullptr));
            executeRequestImpl(std::move(request));
        } else {
            isFetchingToken_ = false;
            g_logger->info("Token request failed: {} (HTTP response code: {}), body: {}", error->toString(), httpResponseCode, data);
        }

        // The queued pin is the whole reason a token is being fetched, and the retry above -- which
        // asks for a fresh token instead of presenting the one the node rejected -- is the attempt
        // most likely to get one. Failing the pin here would throw it away a moment before that
        // lands. The retry cleared the token, so a second failure takes the branch above and ends it.
        if (!isRetrying && queuedPinIpRequest_) {
            g_logger->info("Clearing queued pinIp request due to token fetch failure");
            queuedPinIpRequest_->setRetCode(ApiRetCode::kNoToken);
            queuedPinIpRequest_->callCallback();
            queuedPinIpRequest_.reset();
        }
        if (!isRetrying) {
            failQueuedCheckIpRequests(ApiRetCode::kNoToken);
        }
    } else {
        g_logger->info("API request {} failed with error = {} (HTTP response code: {}) in {} ms", it->second.request->name(), error->toString(), httpResponseCode, elapsedMs);
        // A transport failure never reached the node, so it says nothing about what the node would
        // answer; callers retry it, unlike an answer the node actually gave.
        ApiRetCode retCode = ApiRetCode::kNetworkError;
        if (error->isSuccess()) {
            retCode = it->second.request->retCode() == ApiRetCode::kSuccess ? ApiRetCode::kBridgeApiError : it->second.request->retCode();
        }
        setErrorCodeAndEmitRequestFinished(it->second.request.get(), retCode);
    }
    activeHttpRequests_.erase(it);
}

void BridgeAPI_impl::onHttpNetworkRequestProgressCallback(std::uint64_t requestId, std::uint64_t bytesReceived, std::uint64_t bytesTotal)
{
    auto it = activeHttpRequests_.find(requestId);
    assert(it != activeHttpRequests_.end());
    if (it->second.request->isCanceled()) {
        it->second.asyncCallback_->cancel();
        activeHttpRequests_.erase(it);
    }
}

std::optional<std::pair<std::string, std::int64_t>> BridgeAPI_impl::sessionToken() const
{
    std::lock_guard locker(sessionTokenMutex_);
    return currentToken_;
}

bool BridgeAPI_impl::hasSessionToken() const
{
    return sessionToken().has_value();
}

void BridgeAPI_impl::setApiAvailableCallback(WSNetApiAvailableCallback callback)
{
    apiAvailableCallback_ = callback;
}

void BridgeAPI_impl::pinIp(std::unique_ptr<BaseRequest> request)
{
    // Store the request to be executed when session token is available
    queuedPinIpRequest_ = std::move(request);

    // If we are connected, and not currently fetching a new token, execute immediately
    if (isConnected_ && !isFetchingToken_) {
        executeRequest(std::move(queuedPinIpRequest_));
        queuedPinIpRequest_.reset();
    }

    // Otherwise, the request will be executed when the token fetch completes, or cancelled if the token request fails
}

void BridgeAPI_impl::checkIp(std::unique_ptr<BaseRequest> request)
{
    // On reconnect the cached token is current while its refresh is in flight, and the node rejects
    // it until the refresh lands.
    if (isConnected_ && isFetchingToken_) {
        queuedCheckIpRequests_.emplace_back(std::move(request), std::chrono::steady_clock::now());
        return;
    }
    executeRequest(std::move(request));
}

void BridgeAPI_impl::runQueuedCheckIpRequests()
{
    auto requests = std::move(queuedCheckIpRequests_);
    queuedCheckIpRequests_.clear();
    for (auto &[request, queuedAt] : requests) {
        // Split out so the logs show how much of a slow checkIp was the token, not the node.
        g_logger->info("BridgeAPI checkIp waited {} ms for the token refresh", utils::since(queuedAt).count());
        executeRequest(std::move(request));
    }
}

void BridgeAPI_impl::failQueuedCheckIpRequests(ApiRetCode retCode)
{
    auto requests = std::move(queuedCheckIpRequests_);
    queuedCheckIpRequests_.clear();
    for (auto &entry : requests) {
        entry.first->setRetCode(retCode);
        entry.first->callCallback();
    }
}

void BridgeAPI_impl::clearSessionToken()
{
    std::map<std::string, std::pair<std::string, std::int64_t>> sessionTokens;
    bool persist = false;
    {
        std::lock_guard locker(sessionTokenMutex_);
        currentToken_.reset();
        if (currentNodeId_ != 0 && sessionTokens_.erase(std::to_string(currentNodeId_)) > 0) {
            sessionTokens = sessionTokens_;
            persist = true;
        }
    }
    if (persist) {
        persistentSettings_.setSessionTokens(sessionTokens);
    }
}

void BridgeAPI_impl::clearSessionTokenIfNodeless()
{
    // A custom config's token was never keyed by anything, so nothing will look it up again -- and
    // the next nodeless connection is a different tunnel source IP, which the token is scoped to.
    // Drop it with the connection instead of letting it outlive it and be presented to a node that
    // never issued it.
    std::lock_guard locker(sessionTokenMutex_);
    if (currentNodeId_ == 0) {
        currentToken_.reset();
    }
}

void BridgeAPI_impl::setCurrentNodeId(std::int32_t nodeId)
{
    g_logger->info("BridgeAPI_impl::setCurrentNodeId: {}", nodeId);
    std::lock_guard locker(sessionTokenMutex_);
    // Only a positive id names a node we can key on. The persisted form is a JSON object whose keys
    // are digits, so a negative id would be written and then dropped by the next load -- a token
    // silently lost rather than a cache miss anyone could see. Collapse it to "no node" up front.
    const std::int32_t newNodeId = nodeId > 0 ? nodeId : 0;
    // Re-stating the same node changes nothing and must not: a nodeless token lives only here, so
    // dropping it on a repeat call would lose it for good and leave a live connection with nothing
    // to sign with. A token that genuinely has to go is dropped on disconnect instead.
    if (newNodeId == currentNodeId_) {
        return;
    }
    currentNodeId_ = newNodeId;
    // Whatever the previous connection was signing with is not this connection's to present: the
    // token belongs to one node and one tunnel source IP. Only a stored token for this very node can
    // still be live, and only until the node drops its own copy.
    currentToken_.reset();
    if (currentNodeId_ == 0) {
        return;
    }
    auto it = sessionTokens_.find(std::to_string(currentNodeId_));
    if (it != sessionTokens_.end()) {
        currentToken_ = it->second;
    }
}

void BridgeAPI_impl::setSessionTokenExpiry()
{
    std::int32_t nodeId = 0;
    std::map<std::string, std::pair<std::string, std::int64_t>> sessionTokens;
    bool updated = false;
    {
        std::lock_guard locker(sessionTokenMutex_);
        if (currentNodeId_ != 0 && currentToken_ && currentToken_->second == 0) {
            auto expiryTime = std::chrono::system_clock::now() + std::chrono::hours(24);
            auto expiryTimestamp = std::chrono::duration_cast<std::chrono::seconds>(expiryTime.time_since_epoch()).count();
            currentToken_->second = expiryTimestamp;
            sessionTokens_[std::to_string(currentNodeId_)] = *currentToken_;
            sessionTokens = sessionTokens_;
            nodeId = currentNodeId_;
            updated = true;
        }
    }
    if (updated) {
        persistentSettings_.setSessionTokens(sessionTokens);
        g_logger->info("Set session token expiry to 24 hours from disconnect for node {}", nodeId);
    }
}

void BridgeAPI_impl::setSessionTokenForCurrentNode(const std::string &token, std::int64_t expiry)
{
    std::map<std::string, std::pair<std::string, std::int64_t>> sessionTokens;
    bool persist = false;
    {
        std::lock_guard locker(sessionTokenMutex_);
        currentToken_ = std::make_pair(token, expiry);
        // A custom config has no node to key on, so its token stays with the connection that got it.
        if (currentNodeId_ != 0) {
            sessionTokens_[std::to_string(currentNodeId_)] = *currentToken_;
            sessionTokens = sessionTokens_;
            persist = true;
        }
    }
    if (persist) {
        persistentSettings_.setSessionTokens(sessionTokens);
    }
}

void BridgeAPI_impl::applySessionToken(std::unique_ptr<BaseRequest> &request) const
{
    auto bridgeRequest = dynamic_cast<BridgeAPIRequest*>(request.get());
    if (!bridgeRequest) {
        return;
    }

    auto token = sessionToken();
    if (token) {
        bridgeRequest->setSessionToken(token->first);
    }
}

std::int32_t BridgeAPI_impl::currentNodeId() const
{
    std::lock_guard locker(sessionTokenMutex_);
    return currentNodeId_;
}

} // namespace wsnet
