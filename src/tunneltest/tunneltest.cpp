#include "tunneltest.h"
#include "WSNetBridgeAPI.h"
#include "WSNetDnsResolver.h"
#include "utils/cancelablecallback.h"

namespace wsnet {

TunnelTest::TunnelTest(boost::asio::io_context &io_context, WSNetDnsResolver *dnsResolver,
                       WSNetBridgeAPI *bridgeAPI, WSNetHttpNetworkManager *httpNetworkManager) :
    io_context_(io_context),
    dnsResolver_(dnsResolver),
    exitIpProbe_(httpNetworkManager),
    impl_(io_context,
          [this](IpFamily ipFamily, std::uint32_t timeoutMs, RequestFinishedCallback callback) {
              exitIpProbe_.probe(ipFamily, timeoutMs, callback);
          },
          [this](const std::string &hostname, ResolveCallback callback) {
              // c-ares completes on its own thread. Post before the impl touches State.
              dnsResolver_->lookup(hostname, 0, IpFamily::kIpv4,
                  // io_context_ belongs to WSNet_impl and outlives this object. The c-ares thread
                  // can still complete a lookup after ~TunnelTest and before ~DnsResolver_cares
                  // joins it, so the completion must not touch this.
                  [io = &io_context_, callback](std::uint64_t, const std::string &, std::shared_ptr<WSNetDnsRequestResult> result) {
                      boost::asio::post(*io, [callback, result] { callback(result); });
                  });
          },
          [bridgeAPI](RequestFinishedCallback callback) {
              return bridgeAPI->checkIp([callback](ApiRetCode retCode, const std::string &data) {
                  callback->call(retCode, data);
              });
          })
{
}

std::shared_ptr<WSNetCancelableCallback> TunnelTest::start(bool isBridgeAllowed, WSNetTunnelTestCallback callback)
{
    auto cancelableCallback = std::make_shared<CancelableCallback<WSNetTunnelTestCallback>>(callback);
    boost::asio::post(io_context_, [this, isBridgeAllowed, cancelableCallback] { impl_.run(cancelableCallback, isBridgeAllowed); });
    return cancelableCallback;
}

} // namespace wsnet
