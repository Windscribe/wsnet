#pragma once

#include "WSNetBridgeAPI.h"
#include <mutex>
#include <queue>
#include <map>
#include <optional>
#include <atomic>
#include <chrono>
#include <vector>
#include "WSNetHttpNetworkManager.h"
#include "WSNetAdvancedParameters.h"
#include "../baserequest.h"
#include "bridgeapi_request.h"
#include "connectstate.h"
#include "utils/cancelablecallback.h"
#include "utils/persistentsettings.h"

namespace wsnet {

class BridgeAPI_impl
{
public:
    explicit BridgeAPI_impl(WSNetHttpNetworkManager *httpNetworkManager, PersistentSettings &persistentSettings, WSNetAdvancedParameters *advancedParameters, std::shared_ptr<ConnectState> connectState);
    virtual ~BridgeAPI_impl();

    void setConnectedState(bool isConnected);
    void setIgnoreSslErrors(bool bIgnore);

    std::optional<std::pair<std::string, std::int64_t>> sessionToken() const;
    bool hasSessionToken() const;
    void setApiAvailableCallback(WSNetApiAvailableCallback callback);
    void setCurrentNodeId(std::int32_t nodeId);

    void executeRequest(std::unique_ptr<BaseRequest> request);
    void pinIp(std::unique_ptr<BaseRequest> request);
    // Waits out a token refresh in flight, then runs with the refreshed token. With no refresh in
    // flight it runs at once, so a missing token fails fast instead of holding the caller.
    void checkIp(std::unique_ptr<BaseRequest> request);

private:
    WSNetHttpNetworkManager *httpNetworkManager_;
    WSNetAdvancedParameters *advancedParameters_;
    std::shared_ptr<ConnectState> connectState_;

    std::uint64_t curUniqueId_ = 0;     // for generate unique identifiers for HTTP-requests

    PersistentSettings &persistentSettings_;    // The BridgeAPISettings class is protected by mutex, so it's thread-safe

    bool bIgnoreSslErrors_ = false;
    bool isConnected_ = false;
    bool isFetchingToken_ = false;
    // Tokens kept across connections, keyed by node id (as a string -- the persisted form is a JSON
    // object). Only a node the API named gets an entry; a custom config has no node to key on, so it
    // never lands here. The one thing this buys is a client restart that finds the tunnel still up:
    // the node still holds the token it minted, and presenting anything else gets a 403.
    std::map<std::string, std::pair<std::string, std::int64_t>> sessionTokens_;
    std::int32_t currentNodeId_ = 0;
    // Token for the connection in flight, and the only thing requests are signed with. Seeded from
    // sessionTokens_ when the node is known; a custom config gets one too, it just never persists.
    std::optional<std::pair<std::string, std::int64_t>> currentToken_;
    // Mutations of sessionTokens_/currentNodeId_/currentToken_ happen only on the io_context thread;
    // this mutex guards against off-thread readers such as hasSessionToken().
    mutable std::mutex sessionTokenMutex_;
    std::unique_ptr<BaseRequest> queuedPinIpRequest_;
    // Unlike the pin, several lookups may wait at once; a caller that gave up cancels its own.
    std::vector<std::pair<std::unique_ptr<BaseRequest>, std::chrono::steady_clock::time_point>> queuedCheckIpRequests_;
    WSNetApiAvailableCallback apiAvailableCallback_;

    // Bumped on every connected/disconnected transition. A request carries the value it was sent
    // under, which is what makes a late answer recognisable as describing a tunnel that is gone --
    // the connected flag alone cannot: it reads true again the moment the next tunnel comes up.
    std::uint64_t connectionGeneration_ = 0;

    struct HttpRequestInfo {
        std::unique_ptr<BaseRequest> request;
        std::shared_ptr<WSNetCancelableCallback> asyncCallback_;
        std::uint64_t generation = 0;
    };
    std::map<std::uint64_t, HttpRequestInfo> activeHttpRequests_;

    void executeRequestImpl(std::unique_ptr<BaseRequest> request);
    void completeRequestAsNoop(std::unique_ptr<BaseRequest> request);
    void runQueuedCheckIpRequests();
    void failQueuedCheckIpRequests(ApiRetCode retCode);
    bool isTokenRequestSuppressed() const;
    void setErrorCodeAndEmitRequestFinished(BaseRequest *request, ApiRetCode retCode);

    void onHttpNetworkRequestFinished(std::uint64_t requestId, std::uint32_t elapsedMs, std::shared_ptr<WSNetRequestError> error, const std::string &data);
    // This callback function is necessary to cancel the request as quickly as possible if it was canceled on the calling side
    void onHttpNetworkRequestProgressCallback(std::uint64_t requestId, std::uint64_t bytesReceived, std::uint64_t bytesTotal);

    void clearSessionToken();
    void clearSessionTokenIfNodeless();
    void setSessionTokenExpiry();
    void setSessionTokenForCurrentNode(const std::string &token, std::int64_t expiry);
    void applySessionToken(std::unique_ptr<BaseRequest> &request) const;
    std::int32_t currentNodeId() const;
};

} // namespace wsnet
