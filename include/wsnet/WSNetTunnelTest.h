#pragma once

#include <functional>
#include <memory>
#include <string>
#include "scapix_object.h"
#include "WSNetCancelableCallback.h"

namespace wsnet {

// ipv4 and ipv6 are the exit IPs the tunnel was seen from. Both are empty on failure. On success the
// node's bridge checkIp may report just one family, and the exit IP probe always reports ipv4 while
// ipv6 is best-effort, so either may be empty.
typedef std::function<void(bool isSuccess, const std::string &ipv4, const std::string &ipv6)> WSNetTunnelTestCallback;

class WSNetTunnelTest : public scapix_object<WSNetTunnelTest>
{
public:
    virtual ~WSNetTunnelTest() {}

    // Checks that a freshly established tunnel carries traffic. The tunnel-test hostname must
    // resolve first; then the exit IP comes from the node's bridge checkIp when isBridgeAllowed,
    // otherwise from the exit IP probe. ipv4 decides success, ipv6 is best-effort.
    // Call once the tunnel is up, after any settle time the protocol needs (OpenVPN DNS), and
    // cancel the returned callback as soon as it goes down: probing continues for ~14s, and a
    // late result describes a tunnel that no longer exists. One answer per call.
    // isBridgeAllowed is false for a custom config. The bridge address is internal to a
    // Windscribe node, so it is not a valid exit-IP source there.
    virtual std::shared_ptr<WSNetCancelableCallback> start(bool isBridgeAllowed, WSNetTunnelTestCallback callback) = 0;
};

} // namespace wsnet
