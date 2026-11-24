#pragma once

#include <string>
#include <utility>
#include <vector>

namespace wsnet {

struct DohLookupParsed {
    std::vector<std::string> ips;
    std::string echConfig;
    unsigned long ttl = 300;
};

bool isPoisonedOrSinkholeIp(const std::string &ip);
bool hasPoisonedDnsResult(const std::vector<std::string> &ips);
DohLookupParsed parseDohJsonResponse(const std::string &jsonBody, bool wantIpv6 = false);
const std::vector<std::pair<std::string, std::string>> &bareIpDohEndpoints();

}
