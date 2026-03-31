#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace wsnet {

// Stores persistent settings for lib. Uses the json format.
// thread safe
class PersistentSettings
{
public:
    explicit PersistentSettings(const std::string &settings);

    // empty string means no value for all functions
    void setFailoverId(const std::string &failoverId);
    std::string failoverId() const;

    void setCountryOverride(const std::string &countryOverride);
    std::string countryOverride() const;

    void setAuthHash(const std::string &authHash);
    std::string authHash() const;

    void setSessionStatus(const std::string &sessionStatus);
    std::string sessionStatus() const;

    // Inventory v2: raw /Inventory/locations JSON.
    void setInvLocations(const std::string &invLocations);
    std::string invLocations() const;

    // Inventory v2: serialized server map (produced by InventoryParser::serializeServers).
    void setInvServers(const std::string &invServers);
    std::string invServers() const;

    // Inventory v2: last known server revision. Stored separately so that a
    // revision-only update (empty delta) does not require re-serializing the
    // entire server map.
    void setInvRevision(std::int64_t revision);
    std::int64_t invRevision() const;

    void setServerCredentialsOvpn(const std::string &serverCredentials);
    std::string serverCredentialsOvpn() const;

    void setServerCredentialsIkev2(const std::string &serverCredentials);
    std::string serverCredentialsIkev2() const;

    // openvpn config
    void setServerConfigs(const std::string &serverConfigs);
    std::string serverConfigs() const;

    void setPortMap(const std::string &portMap);
    std::string portMap() const;

    void setStaticIps(const std::string &staticIps);
    std::string staticIps() const;

    void setNotifications(const std::string &notifications);
    std::string notifications() const;

    void setAmneziawgUnblockParams(const std::string &amneziawgUnblockParams);
    std::string amneziawgUnblockParams() const;

    void setSessionTokens(const std::map<std::string, std::pair<std::string, std::int64_t>> &sessionTokens);
    std::map<std::string, std::pair<std::string, std::int64_t>> sessionTokens() const;

    std::string getAsString() const;

private:
    // should increment the version if the data format is changed
    static constexpr int kVersion = 1;

    std::string failoverId_;
    std::string countryOverride_;

    std::string authHash_;
    std::string sessionStatus_;
    std::string invLocations_;
    std::string invServers_;
    std::int64_t invRevision_ = 0;
    std::string serverCredentialsOvpn_;
    std::string serverCredentialsIkev2_;
    std::string serverConfigs_;
    std::string portMap_;
    std::string staticIps_;
    std::string notifications_;
    std::string amneziawgUnblockParams_;
    std::map<std::string, std::pair<std::string, std::int64_t>> sessionTokens_;

    mutable std::mutex mutex_;
};

} // namespace wsnet
