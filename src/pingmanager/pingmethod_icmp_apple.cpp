#include "pingmethod_icmp_apple.h"
#include "utils/utils.h"
#include "utils/wsnet_logger.h"

namespace wsnet {

PingMethodIcmp_apple::PingMethodIcmp_apple(PingManager_apple &pingManager_apple, std::uint64_t id, const std::string &ip, const std::string &hostname, bool isParallelPing,
        PingFinishedCallback callback, PingMethodFinishedCallback pingMethodFinishedCallback) :
    IPingMethod(id, ip, hostname, isParallelPing, callback, pingMethodFinishedCallback),
    pingManager_apple_(pingManager_apple)
{
}

PingMethodIcmp_apple::~PingMethodIcmp_apple()
{
}

void PingMethodIcmp_apple::ping(bool isFromDisconnectedVpnState)
{
    if (!utils::isIpAddress(ip_) && !utils::isIpv6Address(ip_)) {
        g_logger->error("PingMethodIcmp_apple::ping incorrect IP-address: {}", ip_);
        callFinished();
        return;
    }
    pingManager_apple_.ping(ip_, std::bind(&PingMethodIcmp_apple::callback, this, std::placeholders::_1));
}

void PingMethodIcmp_apple::callback(int timeMs)
{
    timeMs_ = timeMs;
    isSuccess_ = (timeMs_ > 0);
    callFinished();
}


} // namespace wsnet
