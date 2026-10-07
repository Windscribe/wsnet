#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include "scapix_object.h"
#include "WSNetCancelableCallback.h"
#include "WSNetServerAPI.h"

namespace wsnet {

using WSNetApiAvailableCallback = std::function<void(bool isAvailable)>;

class WSNetBridgeAPI : public scapix_object<WSNetBridgeAPI>
{
public:
    virtual ~WSNetBridgeAPI() {}

    virtual void setConnectedState(bool isConnected) = 0;
    virtual void setIgnoreSslErrors(bool bIgnore) = 0;
    virtual bool hasSessionToken() const = 0;
    virtual void setApiAvailableCallback(WSNetApiAvailableCallback callback) = 0;
    // Identity of the node the tunnel is on, which is what a bridge session token is scoped to:
    // the token lives in that node's own store, keyed by the tunnel source IP, and no other node
    // will honour it. A hostname cannot stand in for this -- every node in a datacenter can answer
    // to one protocol-level hostname. Any id that is not positive means "no API node" (a custom
    // config), which caches nothing.
    virtual void setCurrentNodeId(std::int32_t nodeId) = 0;

    virtual std::shared_ptr<WSNetCancelableCallback> rotateIp(WSNetRequestFinishedCallback callback) = 0;
    // The tunnel's own view of the exit addresses, as {"ipv4":"...","ipv6":"..."} with an
    // unavailable family omitted. While a session token refresh is in flight the request waits for
    // it and is signed with the refreshed token. A missing token comes back as kNoToken; a token the
    // node no longer honours (403) and an assignment it cannot report (503) as kBridgeApiError. Either
    // way the caller falls back to another source instead of reconnecting just to learn an IP. A request
    // that never reached the node comes back as kNetworkError and is worth retrying. kSuccess is
    // not by itself an answer: a bridge request suppressed by advanced parameters is completed
    // locally with an empty body, so the address has to come from the payload or not at all.
    virtual std::shared_ptr<WSNetCancelableCallback> checkIp(WSNetRequestFinishedCallback callback) = 0;
    virtual std::shared_ptr<WSNetCancelableCallback> pinIp(const std::string &ip, WSNetRequestFinishedCallback callback) = 0;
};

} // namespace wsnet
