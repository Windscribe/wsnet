#pragma once

#include "WSNetUtils.h"
#include <boost/asio.hpp>
#include <map>
#include <memory>
#include "WSNetAdvancedParameters.h"
#include "WSNetHttpNetworkManager.h"
#include "../baserequest.h"
#include "failover/ifailovercontainer.h"
#include "failover/basefailover.h"
#include "failover/failoverdata.h"
#include "failedfailovers.h"

namespace wsnet {

// Debug/testing helper. Runs `myIP` once via the requested failover index,
// resolving its FailoverData via getData() first. Replaces the old usage of
// RequestExecuterViaFailover with an inline coordination tailored to this
// single-shot, single-failover request.
class WSNetUtils_impl : public WSNetUtils
{
public:
    explicit WSNetUtils_impl(boost::asio::io_context &io_context, WSNetHttpNetworkManager *httpNetworkManager,
                             IFailoverContainer *failoverContainer, WSNetAdvancedParameters *advancedParameters);
    virtual ~WSNetUtils_impl();

    std::int32_t failoverCount() const override;
    std::string failoverName(int failoverInd) const override;

    std::shared_ptr<WSNetCancelableCallback> myIPViaFailover(int failoverInd, WSNetRequestFinishedCallback callback) override;

private:
    struct PendingRequest {
        std::unique_ptr<BaseRequest> request;
        std::unique_ptr<BaseFailover> failover;
        std::shared_ptr<WSNetCancelableCallback> httpAsyncCallback;
    };

    boost::asio::io_context &io_context_;
    WSNetHttpNetworkManager *httpNetworkManager_;
    WSNetAdvancedParameters *advancedParameters_;
    IFailoverContainer *failoverContainer_;
    std::uint64_t curUniqueId_ = 0;
    std::map<std::uint64_t, std::unique_ptr<PendingRequest>> activeRequests_;
    FailedFailovers failedFailovers_;

    void myIPViaFailover_impl(int failoverInd, std::unique_ptr<BaseRequest> request);
    void onFailoverData(std::uint64_t id, FailoverResult result, const std::vector<FailoverData> &data);
    void runHttpRequest(std::uint64_t id, const FailoverData &failoverData);
    void onHttpFinished(std::uint64_t id, std::shared_ptr<WSNetRequestError> error, const std::string &data);
    void finishWithError(std::uint64_t id, ServerApiRetCode retCode);

    std::unique_ptr<BaseFailover> failoverByInd(int ind) const;
};

} // namespace wsnet
