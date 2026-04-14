#pragma once

#include <memory>
#include <string>
#include <vector>
#include "scapix_object.h"

namespace wsnet {

class InventoryParser;  // forward declaration — grants friendship without pulling in internal headers

// The following plain structs are only available on desktop platforms.
// On Android/iOS (IS_MOBILE_PLATFORM) all data is accessed via locationsJson().
#ifndef IS_MOBILE_PLATFORM

struct ServerNode
{
    std::string host;
    std::string ip;
    std::string ip2;
    std::string ip3;
    int weight = 0;
    int ipv6 = 0;
};

struct ServerGroup
{
    int id = 0;
    std::string city;
    std::string nick;
    bool premiumOnly = false;
    std::string pingIp;
    std::string pingHost;
    std::string wgPubKey;
    std::string ovpnX509;
    int linkSpeed = 100;
    int netLoad = 0;
    int p2p = 0;
    std::string dnsHostName;  // if non-empty, overrides the parent location's dnsHostName
    std::vector<ServerNode> nodes;
};

struct ServerLocation
{
    int id = 0;
    std::string name;
    std::string countryCode;
    std::string shortName;
    bool premiumOnly = false;
    std::string dnsHostName;
    std::vector<ServerGroup> groups;
};

#endif // IS_MOBILE_PLATFORM

// Parsed representation of the serverlist API response.
// Created in wsnet from the raw JSON and passed to the client as a shared_ptr.
class WSNetServerLocations : public scapix_object<WSNetServerLocations>
{
public:
#ifndef IS_MOBILE_PLATFORM
    const std::vector<ServerLocation> &locations() const { return locations_; }
#else
    // On Android/iOS the struct types are not available; use the JSON representation instead.
    const std::string &locationsJson() const { return locationsJson_; }
#endif

private:
#ifndef IS_MOBILE_PLATFORM
    std::vector<ServerLocation> locations_;
#else
    std::string locationsJson_;
#endif

    friend class ServerLocationsParser;
    friend class InventoryParser;
};

} // namespace wsnet
