#pragma once

#include "../basefailover.h"
#include "httpnetworkmanager/dohjsonparser.h"
#include "utils/utils.h"
#include <atomic>
#include <memory>

namespace wsnet {

class DohHttpsFailover : public BaseFailover
{
public:
    explicit DohHttpsFailover(const std::string &uniqueId, WSNetHttpNetworkManager *httpNetworkManager, const std::string &domain)
        : BaseFailover(uniqueId, httpNetworkManager), domain_(domain)
    {
    }

    ~DohHttpsFailover() override
    {
        if (state_) {
            state_->canceled.store(true);
            if (state_->activeReq) {
                state_->activeReq->cancel();
            }
        }
    }

    bool getData(bool bIgnoreSslErrors, std::vector<FailoverData> &data, FailoverCallback callback) override
    {
        data.clear();
        if (!httpNetworkManager_) {
            if (callback) {
                callback(FailoverResult::kFailed, data);
            }
            return true;
        }
        state_ = std::make_shared<AsyncState>();
        state_->domain = domain_;
        state_->ignoreSsl = bIgnoreSslErrors;
        state_->httpNetworkManager = httpNetworkManager_;
        state_->callback = callback;
        launchAttempt(state_, 0);
        return false;
    }

    std::string name() const override
    {
        return "doh65: " + utils::leftSubStr(domain_, 3);
    }

private:
    struct AsyncState {
        std::atomic<bool> canceled{false};
        std::string domain;
        bool ignoreSsl = false;
        WSNetHttpNetworkManager *httpNetworkManager = nullptr;
        FailoverCallback callback;
        std::shared_ptr<WSNetCancelableCallback> activeReq;
    };

    static void launchAttempt(const std::shared_ptr<AsyncState> &st, std::size_t idx)
    {
        if (st->canceled.load()) {
            return;
        }
        const auto &endpoints = bareIpDohEndpoints();
        if (idx >= endpoints.size()) {
            if (st->callback && !st->canceled.load()) {
                st->callback(FailoverResult::kFailed, {});
            }
            return;
        }

        const auto &ep = endpoints[idx];
        const std::string url = ep.second + "?name=" + st->domain + "&type=65";
        auto req = st->httpNetworkManager->createGetRequest(url, 3000, st->ignoreSsl);
        req->setOverrideIp(ep.first);
        req->addHttpHeader("Accept: application/dns-json");
        req->setUseDnsCache(false);

        static std::atomic<std::uint64_t> nextReqId{900000};
        const std::uint64_t reqId = nextReqId.fetch_add(1);
        st->activeReq = st->httpNetworkManager->executeRequest(
            req, reqId,
            [st, idx](std::uint64_t, std::uint32_t, std::shared_ptr<WSNetRequestError> err, const std::string &body) {
                if (st->canceled.load()) {
                    return;
                }
                if (err && err->isSuccess()) {
                    DohLookupParsed parsed = parseDohJsonResponse(body, false);
                    if (!parsed.echConfig.empty()) {
                        std::vector<FailoverData> out;
                        out.emplace_back(st->domain, parsed.echConfig, parsed.ttl);
                        if (st->callback) {
                            st->callback(FailoverResult::kSuccess, out);
                        }
                        return;
                    }
                    if (!parsed.ips.empty()) {
                        std::vector<FailoverData> out;
                        out.emplace_back(st->domain);
                        if (st->callback) {
                            st->callback(FailoverResult::kSuccess, out);
                        }
                        return;
                    }
                }
                launchAttempt(st, idx + 1);
            });
    }

    std::string domain_;
    std::shared_ptr<AsyncState> state_;
};

}
