#include "dohjsonparser.h"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>

namespace wsnet {

namespace {

bool parseIpv4Octets(const std::string &ip, unsigned int (&octets)[4])
{
    std::size_t pos = 0;
    for (int idx = 0; idx < 4; ++idx) {
        if (pos >= ip.size()) {
            return false;
        }
        unsigned int val = 0;
        std::size_t digits = 0;
        while (pos < ip.size() && std::isdigit(static_cast<unsigned char>(ip[pos]))) {
            val = val * 10 + static_cast<unsigned int>(ip[pos] - '0');
            if (val > 255) {
                return false;
            }
            ++pos;
            ++digits;
        }
        if (digits == 0) {
            return false;
        }
        octets[idx] = val;
        if (idx < 3) {
            if (pos >= ip.size() || ip[pos] != '.') {
                return false;
            }
            ++pos;
        }
    }
    return pos == ip.size();
}

void skipWs(const std::string &s, std::size_t &pos)
{
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) {
        ++pos;
    }
}

bool readJsonString(const std::string &s, std::size_t &pos, std::string &out)
{
    skipWs(s, pos);
    if (pos >= s.size() || s[pos] != '"') {
        return false;
    }
    ++pos;
    out.clear();
    while (pos < s.size()) {
        char ch = s[pos++];
        if (ch == '"') {
            return true;
        }
        if (ch == '\\' && pos < s.size()) {
            char esc = s[pos++];
            switch (esc) {
            case '"':
            case '\\':
            case '/':
                out.push_back(esc);
                break;
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case 't':
                out.push_back('\t');
                break;
            default:
                out.push_back(esc);
                break;
            }
        } else {
            out.push_back(ch);
        }
    }
    return false;
}

void skipJsonValue(const std::string &s, std::size_t &pos)
{
    skipWs(s, pos);
    if (pos >= s.size()) {
        return;
    }
    char ch = s[pos];
    if (ch == '"') {
        std::string ignored;
        readJsonString(s, pos, ignored);
        return;
    }
    if (ch == '{' || ch == '[') {
        char openCh = ch;
        char closeCh = (ch == '{') ? '}' : ']';
        int depth = 0;
        while (pos < s.size()) {
            if (s[pos] == '"') {
                std::string ignored;
                readJsonString(s, pos, ignored);
                continue;
            }
            if (s[pos] == openCh) {
                ++depth;
            } else if (s[pos] == closeCh) {
                --depth;
                if (depth == 0) {
                    ++pos;
                    return;
                }
            }
            ++pos;
        }
        return;
    }
    while (pos < s.size() && s[pos] != ',' && s[pos] != '}' && s[pos] != ']' && !std::isspace(static_cast<unsigned char>(s[pos]))) {
        ++pos;
    }
}

bool readJsonUint(const std::string &s, std::size_t &pos, unsigned long &out)
{
    skipWs(s, pos);
    if (pos >= s.size() || !std::isdigit(static_cast<unsigned char>(s[pos]))) {
        return false;
    }
    out = 0;
    while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) {
        out = out * 10 + static_cast<unsigned long>(s[pos] - '0');
        ++pos;
    }
    return true;
}

std::string stripWrappingQuotes(const std::string &val)
{
    std::size_t start = 0;
    std::size_t end = val.size();
    while (start < end && (std::isspace(static_cast<unsigned char>(val[start])) || val[start] == '"')) {
        ++start;
    }
    while (end > start && (std::isspace(static_cast<unsigned char>(val[end - 1])) || val[end - 1] == '"')) {
        --end;
    }
    return val.substr(start, end - start);
}

std::string extractKvToken(const std::string &data, const std::string &prefix)
{
    std::size_t pos = data.find(prefix);
    while (pos != std::string::npos) {
        if (pos == 0 || std::isspace(static_cast<unsigned char>(data[pos - 1]))) {
            std::size_t valStart = pos + prefix.size();
            std::size_t valEnd = valStart;
            while (valEnd < data.size() && !std::isspace(static_cast<unsigned char>(data[valEnd]))) {
                ++valEnd;
            }
            return stripWrappingQuotes(data.substr(valStart, valEnd - valStart));
        }
        pos = data.find(prefix, pos + 1);
    }
    return std::string();
}

void pushUniqueIp(std::vector<std::string> &ips, const std::string &candidate)
{
    if (candidate.empty() || isPoisonedOrSinkholeIp(candidate)) {
        return;
    }
    if (std::find(ips.begin(), ips.end(), candidate) == ips.end()) {
        ips.push_back(candidate);
    }
}

}

bool isPoisonedOrSinkholeIp(const std::string &ip)
{
    unsigned int o[4] = {};
    if (!parseIpv4Octets(ip, o)) {
        return false;
    }
    if (o[0] == 10 || o[0] == 127 || o[0] == 0) {
        return true;
    }
    if (o[0] == 192 && o[1] == 168) {
        return true;
    }
    if (o[0] == 169 && o[1] == 254) {
        return true;
    }
    if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) {
        return true;
    }
    return false;
}

bool hasPoisonedDnsResult(const std::vector<std::string> &ips)
{
    if (ips.empty()) {
        return true;
    }
    for (const auto &ip : ips) {
        if (isPoisonedOrSinkholeIp(ip)) {
            return true;
        }
    }
    return false;
}

DohLookupParsed parseDohJsonResponse(const std::string &jsonBody, bool wantIpv6)
{
    DohLookupParsed parsed;
    std::vector<std::string> hintIps;
    bool hasTtl = false;

    std::size_t ansKey = jsonBody.find("\"Answer\"");
    if (ansKey == std::string::npos) {
        return parsed;
    }
    std::size_t pos = jsonBody.find('[', ansKey);
    if (pos == std::string::npos) {
        return parsed;
    }
    ++pos;

    while (pos < jsonBody.size()) {
        skipWs(jsonBody, pos);
        if (pos >= jsonBody.size() || jsonBody[pos] == ']') {
            break;
        }
        if (jsonBody[pos] == ',') {
            ++pos;
            continue;
        }
        if (jsonBody[pos] != '{') {
            skipJsonValue(jsonBody, pos);
            continue;
        }
        ++pos;

        unsigned long recType = 0;
        unsigned long recTtl = 300;
        std::string recData;
        bool hasRecTtl = false;

        while (pos < jsonBody.size()) {
            skipWs(jsonBody, pos);
            if (pos >= jsonBody.size() || jsonBody[pos] == '}') {
                if (pos < jsonBody.size()) {
                    ++pos;
                }
                break;
            }
            if (jsonBody[pos] == ',') {
                ++pos;
                continue;
            }
            std::string key;
            if (!readJsonString(jsonBody, pos, key)) {
                break;
            }
            skipWs(jsonBody, pos);
            if (pos < jsonBody.size() && jsonBody[pos] == ':') {
                ++pos;
            }
            if (key == "type") {
                readJsonUint(jsonBody, pos, recType);
            } else if (key == "TTL" || key == "ttl") {
                hasRecTtl = readJsonUint(jsonBody, pos, recTtl);
            } else if (key == "data") {
                readJsonString(jsonBody, pos, recData);
            } else {
                skipJsonValue(jsonBody, pos);
            }
        }

        if ((!wantIpv6 && recType == 1) || (wantIpv6 && recType == 28)) {
            std::string ip = stripWrappingQuotes(recData);
            if (!isPoisonedOrSinkholeIp(ip)) {
                pushUniqueIp(parsed.ips, ip);
                if (hasRecTtl && (!hasTtl || recTtl < parsed.ttl)) {
                    parsed.ttl = recTtl;
                    hasTtl = true;
                }
            }
        } else if (recType == 65) {
            if (parsed.echConfig.empty()) {
                std::string ech = extractKvToken(recData, "ech=");
                if (!ech.empty()) {
                    parsed.echConfig = ech;
                    if (hasRecTtl && (!hasTtl || recTtl < parsed.ttl)) {
                        parsed.ttl = recTtl;
                        hasTtl = true;
                    }
                }
            }
            std::string hint = extractKvToken(recData, wantIpv6 ? "ipv6hint=" : "ipv4hint=");
            std::size_t hpos = 0;
            while (hpos < hint.size()) {
                std::size_t comma = hint.find(',', hpos);
                std::string item = (comma == std::string::npos) ? hint.substr(hpos) : hint.substr(hpos, comma - hpos);
                pushUniqueIp(hintIps, stripWrappingQuotes(item));
                if (comma == std::string::npos) {
                    break;
                }
                hpos = comma + 1;
            }
        }
    }

    if (parsed.ips.empty() && !hintIps.empty()) {
        parsed.ips = std::move(hintIps);
    }
    return parsed;
}

const std::vector<std::pair<std::string, std::string>> &bareIpDohEndpoints()
{
    static const std::vector<std::pair<std::string, std::string>> endpoints = {
        {"1.1.1.1", "https://1.1.1.1/dns-query"},
        {"1.0.0.1", "https://1.0.0.1/dns-query"},
        {"8.8.8.8", "https://8.8.8.8/resolve"},
        {"8.8.4.4", "https://8.8.4.4/resolve"},
    };
    return endpoints;
}

}
