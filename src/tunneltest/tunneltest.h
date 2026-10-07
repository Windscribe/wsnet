#pragma once

#include <boost/asio.hpp>
#include "WSNetTunnelTest.h"
#include "exitipprobe.h"
#include "tunneltest_impl.h"

namespace wsnet {

class WSNetBridgeAPI;
class WSNetDnsResolver;

// Thread safe. start() may be called from any thread; the run itself happens on the io_context thread.
class TunnelTest : public WSNetTunnelTest
{
public:
    TunnelTest(boost::asio::io_context &io_context, WSNetDnsResolver *dnsResolver, WSNetBridgeAPI *bridgeAPI,
               WSNetHttpNetworkManager *httpNetworkManager);

    std::shared_ptr<WSNetCancelableCallback> start(bool isBridgeAllowed, WSNetTunnelTestCallback callback) override;

private:
    boost::asio::io_context &io_context_;
    WSNetDnsResolver *dnsResolver_;
    // Declared before impl_ so it outlives the probe calls impl_ makes into it.
    ExitIpProbe exitIpProbe_;
    TunnelTest_impl impl_;
};

} // namespace wsnet
