#pragma once

#include "ifailovercontainer.h"
#include <map>

#define FAILOVER_CONTAINER_PUBLIC  1
#define FAILOVER_DEFAULT_HARDCODED               "300fa426-4640-4a3f-b95c-1f0277462358"
#define FAILOVER_BACKUP_HARDCODED                "9d6b3f20-4a8e-4e6c-9c52-2e6f2c7b1e01"
#define FAILOVER_DOH_HTTPS_PRIMARY               "b4c1c8f2-77a3-4b9a-8c34-61e9f3a2d402"
#define FAILOVER_DOH_HTTPS_BACKUP                "d8e4a291-53b2-4f18-a9e1-74c3b8e9f503"

namespace wsnet {

class FailoverContainer : public IFailoverContainer
{
public:
    explicit FailoverContainer(WSNetHttpNetworkManager *httpNetworkManager);

    int count() const override;

    // return first failover
    std::unique_ptr<BaseFailover> first() override;

    // return next failover after failoverUniqueId or null if not found
    std::unique_ptr<BaseFailover> next(const std::string &failoverUniqueId) override;

    // return failover by unique identifier or null if not found
    std::unique_ptr<BaseFailover> failoverById(const std::string &failoverUniqueId, int *outInd = nullptr) override;

    // return all failover unique identifiers in priority order
    std::vector<std::string> allUids() const override;

private:
    WSNetHttpNetworkManager *httpNetworkManager_;
    std::vector<std::string> failovers_;
    std::map<std::string, int> map_;        // map failoverId to index in failovers_
};

} // namespace wsnet
