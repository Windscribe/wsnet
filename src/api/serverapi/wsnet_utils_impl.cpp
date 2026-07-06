#include "wsnet_utils_impl.h"

#include "serverapi_requestsfactory.h"
#include "serverapi_utils.h"
#include "utils/cancelablecallback.h"

namespace wsnet {

WSNetUtils_impl::WSNetUtils_impl(boost::asio::io_context &io_context, WSNetHttpNetworkManager *httpNetworkManager,
                                 IFailoverContainer *failoverContainer, WSNetAdvancedParameters *advancedParameters) :
    io_context_(io_context),
    httpNetworkManager_(httpNetworkManager),
    advancedParameters_(advancedParameters),
    failoverContainer_(failoverContainer)
{
}

WSNetUtils_impl::~WSNetUtils_impl()
{
    for (auto &kv : activeRequests_) {
        if (kv.second->httpAsyncCallback) kv.second->httpAsyncCallback->cancel();
    }
    activeRequests_.clear();
}

std::int32_t WSNetUtils_impl::failoverCount() const
{
    return failoverContainer_->count();
}

std::string WSNetUtils_impl::failoverName(int failoverInd) const
{
    return failoverByInd(failoverInd)->name();
}

std::shared_ptr<WSNetCancelableCallback> WSNetUtils_impl::myIPViaFailover(int failoverInd, WSNetRequestFinishedCallback callback)
{
    auto cancelableCallback = std::make_shared<CancelableCallback<WSNetRequestFinishedCallback>>(callback);
    BaseRequest *request = serverapi_requests_factory::myIP(cancelableCallback);
    boost::asio::post(io_context_, [this, failoverInd, request] { myIPViaFailover_impl(failoverInd, std::unique_ptr<BaseRequest>(request)); });
    return cancelableCallback;
}

void WSNetUtils_impl::myIPViaFailover_impl(int failoverInd, std::unique_ptr<BaseRequest> request)
{
    auto failover = failoverByInd(failoverInd);
    if (!failover) {
        request->setRetCode(ServerApiRetCode::kFailoverFailed);
        request->callCallback();
        return;
    }

    const auto id = curUniqueId_++;
    auto pending = std::make_unique<PendingRequest>();
    pending->request = std::move(request);
    pending->failover = std::move(failover);
    BaseFailover *failoverPtr = pending->failover.get();
    activeRequests_[id] = std::move(pending);

    std::vector<FailoverData> data;
    const bool syncResult = failoverPtr->getData(
        false, data,
        [this, id](FailoverResult result, const std::vector<FailoverData> &data) {
            onFailoverData(id, result, data);
        });
    if (syncResult) {
        onFailoverData(id, FailoverResult::kSuccess, data);
    }
}

void WSNetUtils_impl::onFailoverData(std::uint64_t id, FailoverResult result, const std::vector<FailoverData> &data)
{
    auto it = activeRequests_.find(id);
    if (it == activeRequests_.end()) return;

    if (result == FailoverResult::kNoNetwork) {
        finishWithError(id, ServerApiRetCode::kNoNetworkConnection);
        return;
    }
    if (result != FailoverResult::kSuccess || data.empty()) {
        finishWithError(id, ServerApiRetCode::kFailoverFailed);
        return;
    }

    runHttpRequest(id, data.front());
}

void WSNetUtils_impl::runHttpRequest(std::uint64_t id, const FailoverData &failoverData)
{
    using namespace std::placeholders;

    auto it = activeRequests_.find(id);
    if (it == activeRequests_.end()) return;

    auto httpRequest = serverapi_utils::createHttpRequestWithFailoverParameters(
        httpNetworkManager_, failoverData, it->second->request.get(),
        false, advancedParameters_->isAPIExtraTLSPadding());
    httpRequest->setIsDebugLogCurlError(true);

    it->second->httpAsyncCallback = httpNetworkManager_->executeRequest(
        httpRequest, id,
        [this](std::uint64_t reqId, std::uint32_t /*elapsedMs*/, std::shared_ptr<WSNetRequestError> error, const std::string &data) {
            onHttpFinished(reqId, error, data);
        });
}

void WSNetUtils_impl::onHttpFinished(std::uint64_t id, std::shared_ptr<WSNetRequestError> error, const std::string &data)
{
    auto it = activeRequests_.find(id);
    if (it == activeRequests_.end()) return;

    auto pending = std::move(it->second);
    activeRequests_.erase(it);

    if (error->isNoNetworkError()) {
        pending->request->setRetCode(ServerApiRetCode::kNoNetworkConnection);
        pending->request->callCallback();
        return;
    }
    if (!error->isSuccess()) {
        pending->request->setRetCode(ServerApiRetCode::kNetworkError);
        pending->request->callCallback();
        return;
    }
    pending->request->handle(data);
    pending->request->callCallback();
}

void WSNetUtils_impl::finishWithError(std::uint64_t id, ServerApiRetCode retCode)
{
    auto it = activeRequests_.find(id);
    if (it == activeRequests_.end()) return;
    auto pending = std::move(it->second);
    activeRequests_.erase(it);
    pending->request->setRetCode(retCode);
    pending->request->callCallback();
}

std::unique_ptr<BaseFailover> WSNetUtils_impl::failoverByInd(int ind) const
{
    assert (ind >= 0 && ind < failoverContainer_->count());
    int i = 0;
    std::unique_ptr<BaseFailover> failover = failoverContainer_->first();
    assert(failover);

    while (failover) {
        if (ind == i)
            return failover;
        failover = failoverContainer_->next(failover->uniqueId());
        i++;
    }
    return nullptr;
}


} // namespace wsnet
