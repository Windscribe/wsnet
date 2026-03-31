#include "inventoryparser.h"

#include <algorithm>
#include <functional>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "settings.h"
#include "utils/wsnet_logger.h"

namespace wsnet {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

// Parse a single server JSON object (shared by /Inventory/servers and delta).
// Sets |ok| to true on success.
InventoryServer parseServerObj(const rapidjson::Value &obj, bool &ok)
{
    ok = false;
    InventoryServer srv;
    if (!obj.IsObject()) return srv;

    if (!obj.HasMember("id")            || !obj["id"].IsInt()            ||
        !obj.HasMember("hostname")      || !obj["hostname"].IsString()   ||
        !obj.HasMember("ip")            || !obj["ip"].IsString()         ||
        !obj.HasMember("ip2")           || !obj["ip2"].IsString()        ||
        !obj.HasMember("ip3")           || !obj["ip3"].IsString()        ||
        !obj.HasMember("datacenter_id") || !obj["datacenter_id"].IsInt() ||
        !obj.HasMember("weight")        || !obj["weight"].IsInt()        ||
        !obj.HasMember("health")        || !obj["health"].IsInt())
    {
        g_logger->error("parseServerObj: missing required fields (id/hostname/ip/ip2/ip3/datacenter_id/weight/health)");
        return srv;
    }

    srv.id           = obj["id"].GetInt();
    srv.hostname     = obj["hostname"].GetString();
    srv.ip           = obj["ip"].GetString();
    srv.ip2          = obj["ip2"].GetString();
    srv.ip3          = obj["ip3"].GetString();
    srv.datacenterId = obj["datacenter_id"].GetInt();
    srv.weight       = obj["weight"].GetInt();
    srv.health       = obj["health"].GetInt();

    ok = true;
    return srv;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// InventoryParser::parseLocations
// ---------------------------------------------------------------------------

std::vector<InventoryLocation> InventoryParser::parseLocations(const std::string &json)
{
    std::vector<InventoryLocation> result;
    if (json.empty()) return result;

    using namespace rapidjson;
    Document doc;
    doc.Parse(json.c_str());
    if (doc.HasParseError() || !doc.IsObject()) {
        g_logger->error("InventoryParser::parseLocations: JSON parse error");
        return result;
    }

    const auto &root = doc.GetObject();
    if (!root.HasMember("data") || !root["data"].IsObject()) {
        g_logger->error("InventoryParser::parseLocations: missing 'data' object");
        return result;
    }

    const auto &data = root["data"].GetObject();
    if (!data.HasMember("locations") || !data["locations"].IsArray()) {
        g_logger->error("InventoryParser::parseLocations: missing 'locations' array");
        return result;
    }

    for (const auto &locVal : data["locations"].GetArray()) {
        if (!locVal.IsObject()) continue;
        if (!locVal.HasMember("id")           || !locVal["id"].IsInt()          ||
            !locVal.HasMember("name")         || !locVal["name"].IsString()     ||
            !locVal.HasMember("country_code") || !locVal["country_code"].IsString() ||
            !locVal.HasMember("short_name")   || !locVal["short_name"].IsString() ||
            !locVal.HasMember("datacenters")  || !locVal["datacenters"].IsArray())
        {
            g_logger->error("InventoryParser::parseLocations: skipping location with missing required fields (id/name/country_code/short_name/datacenters)");
            continue;
        }

        InventoryLocation loc;
        loc.id          = locVal["id"].GetInt();
        loc.name        = locVal["name"].GetString();
        loc.countryCode = locVal["country_code"].GetString();
        loc.shortName   = locVal["short_name"].GetString();

        for (const auto &dcVal : locVal["datacenters"].GetArray()) {
            if (!dcVal.IsObject()) continue;

            if (!dcVal.HasMember("id")           || !dcVal["id"].IsInt()           ||
                !dcVal.HasMember("city")         || !dcVal["city"].IsString()      ||
                !dcVal.HasMember("nick")         || !dcVal["nick"].IsString()      ||
                !dcVal.HasMember("iata")         || !dcVal["iata"].IsString()      ||
                !dcVal.HasMember("status")       || !dcVal["status"].IsInt()       ||
                !dcVal.HasMember("p2p")          || !dcVal["p2p"].IsInt()          ||
                !dcVal.HasMember("premium") || !dcVal["premium"].IsInt() ||
                !dcVal.HasMember("wg_pubkey")    || !dcVal["wg_pubkey"].IsString() ||
                !dcVal.HasMember("wg_endpoint")  || !dcVal["wg_endpoint"].IsString() ||
                !dcVal.HasMember("ovpn_x509")    || !dcVal["ovpn_x509"].IsString() ||
                !dcVal.HasMember("link_speed")   || !dcVal["link_speed"].IsInt())
            {
                g_logger->error("InventoryParser::parseLocations: skipping datacenter with missing required fields (id/city/nick/iata/status/p2p/premium/wg_pubkey/wg_endpoint/ovpn_x509/link_speed)");
                continue;
            }

            InventoryDatacenter dc;
            dc.id          = dcVal["id"].GetInt();
            dc.city        = dcVal["city"].GetString();
            dc.nick        = dcVal["nick"].GetString();
            dc.iata        = dcVal["iata"].GetString();
            dc.status      = dcVal["status"].GetInt();
            dc.p2p         = dcVal["p2p"].GetInt();
            dc.premiumOnly = dcVal["premium"].GetInt() != 0;
            dc.wgPubkey    = dcVal["wg_pubkey"].GetString();
            dc.wgEndpoint  = dcVal["wg_endpoint"].GetString();
            dc.ovpnX509    = dcVal["ovpn_x509"].GetString();
            dc.linkSpeed   = dcVal["link_speed"].GetInt();

            loc.datacenters.push_back(std::move(dc));
        }

        // Location is premium only when every one of its datacenters is premium.
        loc.premiumOnly = !loc.datacenters.empty() &&
                          std::all_of(loc.datacenters.begin(), loc.datacenters.end(),
                                      [](const InventoryDatacenter &dc) {
                                          return dc.premiumOnly;
                                      });

        result.push_back(std::move(loc));
    }

    return result;
}

// ---------------------------------------------------------------------------
// InventoryParser::parseServers
// ---------------------------------------------------------------------------

bool InventoryParser::parseServers(const std::string &json,
                                   std::map<int, InventoryServer> &servers,
                                   std::int64_t &revision)
{
    if (json.empty()) return false;

    using namespace rapidjson;
    Document doc;
    doc.Parse(json.c_str());
    if (doc.HasParseError() || !doc.IsObject()) {
        g_logger->error("InventoryParser::parseServers: JSON parse error");
        return false;
    }

    const auto &root = doc.GetObject();
    if (!root.HasMember("data") || !root["data"].IsObject()) {
        g_logger->error("InventoryParser::parseServers: missing 'data' object");
        return false;
    }

    const auto &data = root["data"].GetObject();
    if (!data.HasMember("servers") || !data["servers"].IsArray()) {
        g_logger->error("InventoryParser::parseServers: missing 'servers' array");
        return false;
    }

    if (!data.HasMember("revision") || !data["revision"].IsInt64()) {
        g_logger->error("InventoryParser::parseServers: missing 'revision'");
        return false;
    }
    revision = data["revision"].GetInt64();

    servers.clear();
    for (const auto &srvVal : data["servers"].GetArray()) {
        bool ok = false;
        InventoryServer srv = parseServerObj(srvVal, ok);
        if (ok)
            servers[srv.id] = std::move(srv);
    }

    g_logger->info("InventoryParser::parseServers: loaded {} servers, revision {}", servers.size(), revision);
    return true;
}

// ---------------------------------------------------------------------------
// InventoryParser::serializeServers
// ---------------------------------------------------------------------------

std::string InventoryParser::serializeServers(const std::map<int, InventoryServer> &servers,
                                               std::int64_t revision)
{
    using namespace rapidjson;
    Document doc;
    doc.SetObject();
    auto &alloc = doc.GetAllocator();

    doc.AddMember("revision", revision, alloc);

    Value arr(kArrayType);
    for (const auto &[id, srv] : servers) {
        Value obj(kObjectType);
        obj.AddMember("id",            srv.id,                                    alloc);
        obj.AddMember("hostname",      Value(srv.hostname.c_str(),  alloc),       alloc);
        obj.AddMember("ip",            Value(srv.ip.c_str(),        alloc),       alloc);
        obj.AddMember("ip2",           Value(srv.ip2.c_str(),       alloc),       alloc);
        obj.AddMember("ip3",           Value(srv.ip3.c_str(),       alloc),       alloc);
        obj.AddMember("datacenter_id", srv.datacenterId,                          alloc);
        obj.AddMember("weight",        srv.weight,                                alloc);
        obj.AddMember("health",        srv.health,                                alloc);
        arr.PushBack(obj, alloc);
    }
    doc.AddMember("servers", arr, alloc);

    StringBuffer sb;
    Writer<StringBuffer> writer(sb);
    doc.Accept(writer);
    return sb.GetString();
}

// ---------------------------------------------------------------------------
// InventoryParser::deserializeServers
// ---------------------------------------------------------------------------

bool InventoryParser::deserializeServers(const std::string &json,
                                          std::map<int, InventoryServer> &servers,
                                          std::int64_t &revision)
{
    if (json.empty()) return false;

    using namespace rapidjson;
    Document doc;
    doc.Parse(json.c_str());
    if (doc.HasParseError() || !doc.IsObject()) {
        g_logger->error("InventoryParser::deserializeServers: JSON parse error");
        return false;
    }

    const auto &root = doc.GetObject();
    if (!root.HasMember("revision") || !root["revision"].IsInt64()) {
        g_logger->error("InventoryParser::deserializeServers: missing 'revision'");
        return false;
    }
    revision = root["revision"].GetInt64();

    if (!root.HasMember("servers") || !root["servers"].IsArray()) {
        g_logger->error("InventoryParser::deserializeServers: missing 'servers' array");
        return false;
    }

    servers.clear();
    for (const auto &srvVal : root["servers"].GetArray()) {
        bool ok = false;
        InventoryServer srv = parseServerObj(srvVal, ok);
        if (ok)
            servers[srv.id] = std::move(srv);
    }

    return !servers.empty() || revision > 0;
}

// ---------------------------------------------------------------------------
// InventoryParser::parseDelta
// ---------------------------------------------------------------------------

ServerInventoryDelta InventoryParser::parseDelta(const std::string &sessionJson)
{
    ServerInventoryDelta delta;
    if (sessionJson.empty()) return delta;

    using namespace rapidjson;
    Document doc;
    doc.Parse(sessionJson.c_str());
    if (doc.HasParseError() || !doc.IsObject()) {
        g_logger->error("InventoryParser::parseDelta: JSON parse error");
        return delta;
    }

    const auto &root = doc.GetObject();
    if (!root.HasMember("data") || !root["data"].IsObject()) {
        g_logger->error("InventoryParser::parseDelta: missing 'data' object");
        return delta;
    }

    const auto &data = root["data"].GetObject();
    if (!data.HasMember("server_inventory") || !data["server_inventory"].IsObject()) {
        g_logger->error("InventoryParser::parseDelta: missing 'server_inventory' object");
        return delta;
    }

    const auto &inv = data["server_inventory"].GetObject();
    if (!inv.HasMember("action")   || !inv["action"].IsString()   ||
        !inv.HasMember("revision") || !inv["revision"].IsInt64()) {
        g_logger->error("InventoryParser::parseDelta: missing 'action' or 'revision'");
        return delta;
    }

    delta.revision = inv["revision"].GetInt64();

    const std::string action = inv["action"].GetString();

    if (action == "hold") {
        delta.action = ServerInventoryDelta::Action::kHold;
        return delta;
    }

    if (action != "delta") return delta;

    delta.action = ServerInventoryDelta::Action::kDelta;

    if (inv.HasMember("enabled") && inv["enabled"].IsArray()) {
        for (const auto &srvVal : inv["enabled"].GetArray()) {
            bool ok = false;
            InventoryServer srv = parseServerObj(srvVal, ok);
            if (ok)
                delta.enabled.push_back(std::move(srv));
        }
    }

    if (inv.HasMember("disabled") && inv["disabled"].IsArray()) {
        for (const auto &disVal : inv["disabled"].GetArray()) {
            if (disVal.IsObject() && disVal.HasMember("id") && disVal["id"].IsInt())
                delta.disabled.push_back(disVal["id"].GetInt());
        }
    }

    return delta;
}

// ---------------------------------------------------------------------------
// InventoryParser::buildServerLocations — platform-specific helpers
// ---------------------------------------------------------------------------

#ifndef IS_MOBILE_PLATFORM

void InventoryParser::fillServerLocations(WSNetServerLocations &result,
                                          const std::vector<InventoryLocation> &locations,
                                          const DcServersMap &dcServersMap)
{
    for (const auto &loc : locations) {
        ServerLocation serverLoc;
        serverLoc.id          = loc.id;
        serverLoc.name        = loc.name;
        serverLoc.countryCode = loc.countryCode;
        serverLoc.shortName   = loc.shortName;
        serverLoc.premiumOnly = loc.premiumOnly;
        serverLoc.p2p         = 1;

        for (const auto &dc : loc.datacenters) {
            if (dc.status != 1) continue;

            // If any datacenter in this location prohibits P2P, mark the location.
            if (dc.p2p == 0)
                serverLoc.p2p = 0;

            ServerGroup group;
            group.id          = dc.id;
            group.city        = dc.city;
            group.nick        = dc.nick;
            group.premiumOnly = dc.premiumOnly;
            group.wgPubKey    = dc.wgPubkey;
            group.ovpnX509    = dc.ovpnX509;
            group.linkSpeed   = dc.linkSpeed;
            group.dnsHostName = dc.ovpnX509;
            group.health      = -1;

            auto it = dcServersMap.find(dc.id);
            if (it != dcServersMap.end() && !it->second.empty()) {
                const auto &dcServers = it->second;

                // Pick a stable ping target that distributes load across users.
                // Hashing deviceId ensures the same device always picks the same server
                // (so latency readings are comparable across sessions), while different
                // devices spread the ping traffic across all servers in the datacenter.
                // XOR-ing with dc.id prevents every datacenter from landing on the same
                // positional index for a given device.
                // pingHost must be a full URL — PingMethodHttp validates it with skyr::url().
                const std::size_t pingSeed = std::hash<std::string>{}(Settings::instance().deviceId())
                                             ^ (std::hash<int>{}(dc.id) << 1);
                const auto &pingServer = *dcServers[pingSeed % dcServers.size()];
                group.pingIp   = pingServer.ip;
                group.pingHost = "http://" + pingServer.hostname + ":6464/latency";

                // Average health across all servers in this datacenter.
                int totalHealth = 0;
                for (const auto *srv : dcServers)
                    totalHealth += srv->health;
                group.health = static_cast<int>(totalHealth / static_cast<int>(dcServers.size()));
                if (group.health < 0 || group.health > 100)
                    group.health = -1;

                for (const auto *srv : dcServers) {
                    ServerNode node;
                    node.hostname = srv->hostname;
                    node.ip       = srv->ip;
                    node.ip2      = srv->ip2;
                    node.ip3      = srv->ip3;
                    node.weight   = srv->weight;
                    group.nodes.push_back(std::move(node));
                }
            }

            serverLoc.groups.push_back(std::move(group));
        }

        result.locations_.push_back(std::move(serverLoc));
    }
}

#else // IS_MOBILE_PLATFORM

void InventoryParser::fillServerLocationsJson(WSNetServerLocations &result,
                                              const std::vector<InventoryLocation> &locations,
                                              const DcServersMap &dcServersMap)
{
    rapidjson::Document doc;
    doc.SetObject();
    auto &alloc = doc.GetAllocator();
    rapidjson::Value jsonLocs(rapidjson::kArrayType);

    for (const auto &loc : locations) {
        rapidjson::Value jsonLoc(rapidjson::kObjectType);
        jsonLoc.AddMember("id",           loc.id, alloc);
        jsonLoc.AddMember("name",         rapidjson::Value(loc.name.c_str(), alloc), alloc);
        jsonLoc.AddMember("country_code", rapidjson::Value(loc.countryCode.c_str(), alloc), alloc);
        jsonLoc.AddMember("short_name",   rapidjson::Value(loc.shortName.c_str(), alloc), alloc);
        jsonLoc.AddMember("premium_only", loc.premiumOnly, alloc);

        int p2pLoc = 1;
        rapidjson::Value jsonGroups(rapidjson::kArrayType);

        for (const auto &dc : loc.datacenters) {
            if (dc.status != 1) continue;

            if (dc.p2p == 0)
                p2pLoc = 0;

            std::string pingIp;
            std::string pingHost;
            int health = -1;
            rapidjson::Value jsonNodes(rapidjson::kArrayType);

            auto it = dcServersMap.find(dc.id);
            if (it != dcServersMap.end() && !it->second.empty()) {
                const auto &dcServers = it->second;

                // Pick a stable ping target that distributes load across users.
                // Hashing deviceId ensures the same device always picks the same server
                // (so latency readings are comparable across sessions), while different
                // devices spread the ping traffic across all servers in the datacenter.
                // XOR-ing with dc.id prevents every datacenter from landing on the same
                // positional index for a given device.
                // pingHost must be a full URL — PingMethodHttp validates it with skyr::url().
                const std::size_t pingSeed = std::hash<std::string>{}(Settings::instance().deviceId())
                                             ^ (std::hash<int>{}(dc.id) << 1);
                const auto &pingServer = *dcServers[pingSeed % dcServers.size()];
                pingIp   = pingServer.ip;
                pingHost = "http://" + pingServer.hostname + ":6464/latency";

                // Average health across all servers in this datacenter.
                int totalHealth = 0;
                for (const auto *srv : dcServers)
                    totalHealth += srv->health;
                health = static_cast<int>(totalHealth / static_cast<int>(dcServers.size()));
                if (health < 0 || health > 100)
                    health = -1;

                for (const auto *srv : dcServers) {
                    rapidjson::Value jsonNode(rapidjson::kObjectType);
                    jsonNode.AddMember("hostname", rapidjson::Value(srv->hostname.c_str(), alloc), alloc);
                    jsonNode.AddMember("ip",       rapidjson::Value(srv->ip.c_str(), alloc), alloc);
                    jsonNode.AddMember("ip2",      rapidjson::Value(srv->ip2.c_str(), alloc), alloc);
                    jsonNode.AddMember("ip3",      rapidjson::Value(srv->ip3.c_str(), alloc), alloc);
                    jsonNode.AddMember("weight",   srv->weight, alloc);
                    jsonNodes.PushBack(std::move(jsonNode), alloc);
                }
            }

            rapidjson::Value jsonGroup(rapidjson::kObjectType);
            jsonGroup.AddMember("id",            dc.id, alloc);
            jsonGroup.AddMember("city",          rapidjson::Value(dc.city.c_str(), alloc), alloc);
            jsonGroup.AddMember("nick",          rapidjson::Value(dc.nick.c_str(), alloc), alloc);
            jsonGroup.AddMember("premium_only",  dc.premiumOnly, alloc);
            jsonGroup.AddMember("ping_ip",       rapidjson::Value(pingIp.c_str(), alloc), alloc);
            jsonGroup.AddMember("ping_host",     rapidjson::Value(pingHost.c_str(), alloc), alloc);
            jsonGroup.AddMember("wg_pub_key",    rapidjson::Value(dc.wgPubkey.c_str(), alloc), alloc);
            jsonGroup.AddMember("ovpn_x509",     rapidjson::Value(dc.ovpnX509.c_str(), alloc), alloc);
            jsonGroup.AddMember("link_speed",    dc.linkSpeed, alloc);
            jsonGroup.AddMember("health",        health, alloc);
            jsonGroup.AddMember("dns_host_name", rapidjson::Value(dc.ovpnX509.c_str(), alloc), alloc);
            jsonGroup.AddMember("nodes",         std::move(jsonNodes), alloc);
            jsonGroups.PushBack(std::move(jsonGroup), alloc);
        }

        jsonLoc.AddMember("p2p",          p2pLoc, alloc);
        jsonLoc.AddMember("dns_host_name", rapidjson::Value("", alloc), alloc);
        jsonLoc.AddMember("groups",        std::move(jsonGroups), alloc);
        jsonLocs.PushBack(std::move(jsonLoc), alloc);
    }

    doc.AddMember("locations", std::move(jsonLocs), alloc);

    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    doc.Accept(writer);
    result.locationsJson_ = sb.GetString();
}

#endif // IS_MOBILE_PLATFORM

// ---------------------------------------------------------------------------
// InventoryParser::buildServerLocations
// ---------------------------------------------------------------------------

std::shared_ptr<WSNetServerLocations> InventoryParser::buildServerLocations(
    const std::vector<InventoryLocation> &locations,
    const std::map<int, InventoryServer> &servers)
{
    // Build a datacenter_id → servers index for O(N log N) instead of O(N*M).
    DcServersMap dcServersMap;
    for (const auto &[id, srv] : servers)
        dcServersMap[srv.datacenterId].push_back(&srv);

    // WSNetServerLocations has private members; InventoryParser is a friend.
    auto result = std::shared_ptr<WSNetServerLocations>(new WSNetServerLocations());

#ifndef IS_MOBILE_PLATFORM
    fillServerLocations(*result, locations, dcServersMap);
#else
    fillServerLocationsJson(*result, locations, dcServersMap);
#endif

    return result;
}

} // namespace wsnet
