#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "WSNetServerLocations.h"

namespace wsnet {

// ---------------------------------------------------------------------------
// Raw structs matching the /Inventory/locations response
// ---------------------------------------------------------------------------

struct InventoryDatacenter {
    int         id          = 0;
    std::string city;
    std::string nick;
    std::string iata;
    int         status      = 1;   // 1 = active, 0 = disabled
    int         p2p         = 0;
    bool        premiumOnly = false;
    std::string wgPubkey;
    std::string wgEndpoint;
    std::string ovpnX509;
    int         linkSpeed   = 100;

    bool operator==(const InventoryDatacenter &o) const {
        return id == o.id && city == o.city && nick == o.nick && iata == o.iata &&
               status == o.status && p2p == o.p2p && premiumOnly == o.premiumOnly &&
               wgPubkey == o.wgPubkey && wgEndpoint == o.wgEndpoint &&
               ovpnX509 == o.ovpnX509 && linkSpeed == o.linkSpeed;
    }
};

struct InventoryLocation {
    int         id          = 0;
    std::string name;
    std::string countryCode;
    std::string shortName;
    bool        premiumOnly = false;
    std::vector<InventoryDatacenter> datacenters;

    bool operator==(const InventoryLocation &o) const {
        return id == o.id && name == o.name && countryCode == o.countryCode &&
               shortName == o.shortName && premiumOnly == o.premiumOnly &&
               datacenters == o.datacenters;
    }
};

// ---------------------------------------------------------------------------
// Raw struct matching a server entry in /Inventory/servers and delta enabled[]
// ---------------------------------------------------------------------------

struct InventoryServer {
    int         id       = 0;
    std::string host;
    std::string ip;
    std::string ip2;
    std::string ip3;
    int         ipv6     = 0;
    int         dcId     = 0;
    int         weight   = 1;
    int         netLoad  = 0;
    int         sClass   = 0;

    bool operator==(const InventoryServer &o) const {
        return id == o.id && host == o.host && ip == o.ip &&
               ip2 == o.ip2 && ip3 == o.ip3 && ipv6 == o.ipv6 &&
               dcId == o.dcId && weight == o.weight &&
               netLoad == o.netLoad && sClass == o.sClass;
    }
};

// ---------------------------------------------------------------------------
// Delta payload extracted from GET /Session server_inventory field
// ---------------------------------------------------------------------------

struct ServerInventoryDelta {
    enum class Action { kNone, kDelta, kHold };

    Action                     action   = Action::kNone;
    std::vector<InventoryServer> enabled;
    std::vector<int>           disabled;   // server IDs to remove
    std::int64_t               revision = 0;
};

// ---------------------------------------------------------------------------
// Parser / builder class
// ---------------------------------------------------------------------------

class InventoryParser {
public:
    // Parse GET /Inventory/locations JSON.
    // Returns an empty vector on parse failure.
    static std::vector<InventoryLocation> parseLocations(const std::string &json);

    // Parse GET /Inventory/servers JSON.
    // Fills |servers| (keyed by server id) and sets |revision|.
    // Returns false on parse failure.
    static bool parseServers(const std::string &json,
                             std::map<int, InventoryServer> &servers,
                             std::int64_t &revision);

    // Serialize in-memory server state to a compact JSON blob for persistence.
    static std::string serializeServers(const std::map<int, InventoryServer> &servers,
                                        std::int64_t revision);

    // Restore server state from a blob produced by serializeServers().
    // Returns false if the blob is empty or malformed.
    static bool deserializeServers(const std::string &json,
                                   std::map<int, InventoryServer> &servers,
                                   std::int64_t &revision);

    // Extract the server_inventory delta from a full GET /Session response JSON.
    // Returns a delta with action==kNone if the field is absent.
    static ServerInventoryDelta parseDelta(const std::string &sessionJson);

    // Combine location metadata with the current server map into a
    // WSNetServerLocations object (the type consumed by client-desktop).
    //
    // Mapping: InventoryDatacenter → ServerGroup, InventoryServer → ServerNode.
    // Datacenters with no servers in |servers| will have empty node lists.
    // pingIp / pingHost are taken from the first server in each datacenter (pingHost is a full URL: http://<host>:6464/latency).
    // Group health is the average of all server net_load values in the datacenter.
    // Group.pro is always false (server-side filtering ensures access).
    // Location.p2p is 1 if any of its datacenters has p2p != 0.
    static std::shared_ptr<WSNetServerLocations> buildServerLocations(
        const std::vector<InventoryLocation> &locations,
        const std::map<int, InventoryServer> &servers);

private:
    using DcServersMap = std::map<int, std::vector<const InventoryServer *>>;

#ifndef IS_MOBILE_PLATFORM
    static void fillServerLocations(WSNetServerLocations &result,
                                    const std::vector<InventoryLocation> &locations,
                                    const DcServersMap &dcServersMap);
#else
    static void fillServerLocationsJson(WSNetServerLocations &result,
                                        const std::vector<InventoryLocation> &locations,
                                        const DcServersMap &dcServersMap);
#endif
};

} // namespace wsnet
