#include "serverlocations_request.h"
#include <skyr/url.hpp>
#include "utils/wsnet_logger.h"
#include <rapidjson/document.h>

namespace wsnet {

ServerLocationsRequest::ServerLocationsRequest(RequestPriority priority, const std::string &name,
        std::map<std::string, std::string> extraParams, PersistentSettings &persistentSettings,
        std::shared_ptr<ConnectState> connectState, WSNetAdvancedParameters *advancedParameters, RequestFinishedCallback callback) :
    BaseRequest(HttpMethod::kGet, SubdomainType::kAssets, priority, name, extraParams, callback),
    persistentSettings_(persistentSettings),
    connectState_(connectState),
    advancedParameters_(advancedParameters)
{
}

std::string ServerLocationsRequest::url(const std::string &domain) const
{
    isFromDisconnectedVPNState_ = !connectState_->isVPNConnected();

    std::string rawUrl = "https://" + hostname(domain, subDomainType_) + "/" + name();
    auto parsedUrl = skyr::make_url(rawUrl);
    if (!parsedUrl) {
        g_logger->error("ServerLocationsRequest: failed to parse URL: {}", rawUrl);
        return rawUrl;
    }
    auto url = std::move(parsedUrl.value());
    auto &sp = url.search_parameters();
    for (auto &it : extraParams_)
        if (!it.second.empty())
            sp.set(it.first, it.second);

    // country override logic
    std::string countryOverride;
    if (advancedParameters_->isIgnoreCountryOverride()) {
        // Instruct the serverlist endpoint to ignore geolocation based on our IP.
        countryOverride = "ZZ";
    }
    else {
        if (!advancedParameters_->countryOverrideValue().empty()) {
            countryOverride = advancedParameters_->countryOverrideValue();
        } else if (connectState_->isVPNConnected()) {
            if (!persistentSettings_.countryOverride().empty()) {
                countryOverride = persistentSettings_.countryOverride();
            }
        }
    }

    if (!countryOverride.empty()) {
        sp.set("country_override", countryOverride);
        g_logger->info("API request ServerLocations added countryOverride = {}", countryOverride);
    }

    return url.c_str();
}

void ServerLocationsRequest::handle(const std::string &arr)
{
    if (arr.empty()) {
        setRetCode(ServerApiRetCode::kIncorrectJson);
        return;
    }

    if (!isIgnoreJsonParse_) {
        using namespace rapidjson;
        Document doc;
        doc.Parse(arr.c_str());
        if (doc.HasParseError() || !doc.IsObject()) {
            setRetCode(ServerApiRetCode::kIncorrectJson);
            return;
        }
        auto jsonObject = doc.GetObject();
        // all responses must contain errorCode or/and data fields
        if (!jsonObject.HasMember("errorCode") && !jsonObject.HasMember("data")) {
            setRetCode(ServerApiRetCode::kIncorrectJson);
            return;
        }

        // manage the country override flag according to the documentation
        // https://gitlab.int.windscribe.com/ws/client/desktop/client-desktop-public/-/issues/354
        if (!jsonObject.HasMember("info")) {
            setRetCode(ServerApiRetCode::kIncorrectJson);
            return;
        }

        if (!jsonObject["info"].IsObject()) {
            setRetCode(ServerApiRetCode::kIncorrectJson);
            return;
        }
        auto jsonInfo = jsonObject["info"].GetObject();

        if (jsonInfo.HasMember("country_override") && jsonInfo["country_override"].IsString()) {
            if (isFromDisconnectedVPNState_ && (!connectState_->isVPNConnected())) {
                auto countryOverride = jsonInfo["country_override"].GetString();
                persistentSettings_.setCountryOverride(countryOverride);
                g_logger->info("API request ServerLocations saved countryOverride = {}", countryOverride);
            }
        } else {
            if (isFromDisconnectedVPNState_ && (!connectState_->isVPNConnected())) {
                persistentSettings_.setCountryOverride(std::string());
                g_logger->info("API request ServerLocations removed countryOverride flag");
            }
        }
    }
    json_ = arr;
}



} // namespace wsnet

