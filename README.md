**wsnet** is a library that is designed for Windscribe clients for all platforms Windows/Mac/Linux/Android/iOS providing access to server APIs in a unified way. Also contains some other networking features such as an asynchronous DNS resolver with the ability to use custom DNS servers and a http network manager with some much needed Windscribe client specific features.

# Motivation

The server API can be accessed by several dozen anti-censorship bypass methods. Implementing and debugging all of these methods for each platform is rather laborious and difficult to test. So the library hides all these details and provides clients with a single and simple interface. Further modification of the server API access methods will only require changes to the library code.  Also the library uses libraries like curl and openssl modified by ECH patches + our own to bypass censorship. Some such methods may be difficult or unrealizable to implement separately for Android/iOS platforms.

# Features
* Support for any architecture (x64, arm64 and so on) and platforms (Windows/Mac/Linux/Android/iOS).
* Ability to connect the library to a project via vcpkg tool (this is more relevant for desktop platforms).
* Asynchronous DNS resolver with support for custom DNS servers.
* Asynchronous HTTP manager providing the ability to whitelist IP-addresses in the firewall via callback functions.
* Asynchronous access to the Windscribe Server API with the ability to switch to staging servers.
* Implemented several dozen methods to bypass censorship used when accessing the server API.
* Functionality for ICMP and HTTP pinging.
* The library maintains logs that can be passed to the client.
* Asynchronous and thread-safe.
* Ready to use in Android and iOS immediately without writing additional code. Connection to Android and iOS projects through aar file and framework accordingly.
* Has automatic and semi-automatic tests. Tested with fairly good code coverage.

# How to build

The C++ compiler (XCode/Visual C++/clang), vcpkg tool and cmake must be installed before build.

## Desktop
To use the library in a desktop project, it is recommended to use vcpkg. Example of vcpkg settings to use the library.

vcpkg.json
```
{
    "dependencies": ["wsnet"]
}
```


vcpkg-configuration.json
```
{
  "$schema": "https://raw.githubusercontent.com/microsoft/vcpkg-tool/main/docs/vcpkg-configuration.schema.json",
  "default-registry": {
    "kind": "git",
    "repository": "https://github.com/microsoft/vcpkg",
    "baseline": "61f610845fb206298a69f708104a51d651872877"
  },
  "registries": [
    {
      "kind": "git",
      "repository": "git@gitlab.int.windscribe.com:ws/client/client-libs/ws-vcpkg-registry.git",
      "baseline": "0bff463c4aa39cdd251337a36e43f8eb9c05cb57",
      "packages": [ "openssl", "curl", "wsnet"]
    }
  ]
}
```

The vcpkg port and some of its dependencies(curl, openssl) are in the repository: `ws/client/client-libs/ws-vcpkg-registry.git`

## Android
* Android Studio must be installed.
* Run the build script: `build_android.sh`.
* Get a file `wsnet.aar` ready to use.

## iOS
* Run the build script: `build_ios.sh`.
* Get a framework `wsnet.framework` ready to use.
# How to use

The library must be initialized before it can be used, once during the lifetime of the application. Once initialized, all library functionality is available through a global instance of the WSNet class.

It is also recommended to install the logger callback function if necessary.

After finishing using the library, it is recommended to call the cleanup function, although not necessarily. The library will be cleaned in any case when the program finished. After calling cleanup, all pending callback functions will be canceled.

### Example (initialization):
```

#inlude <wsnet/WSNet.h>

using namespace wsnet;

void logger(const std::string &str)
{
    printf("%s\n", str.c_str());
}

int main()
{
    WSNet::setLogger(logger);
    WSNet::initialize("macos", "2.7.10", false, "");
    auto wsnet = WSNet::instance();

    // Working with the library
    ....

    WSNet::cleanup();
    return 0;
}

```
``
### Example (Dns resolver):
```

    wsnet->dnsResolver()->setDnsServers({ "1.1.1.1", "1.0.0.1"});
    // Blocking DNS resolution, waiting until complete
    auto res = wsnet->dnsResolver()->lookupBlocked("google.com", IpFamily::kBoth);
    // work with res
    ...

    // Asynchronous DNS resolution
    auto callback = [](std::uint64_t requestId, const std::string &hostname, std::shared_ptr<WSNetDnsRequestResult> result)
    {

    };
    auto request = wsnet->dnsResolver()->lookup("google.com", 0, IpFamily::kBoth, callback);

    // To cancel a request early, you can call: request->cancel()
```

### Example (Server API):
```
    wsnet->serverApi()->myIP([](ServerApiRetCode serverApiRetCode, const std::string &jsonData) {
        printf("%s\n", jsonData.c_str());
    });

```


All asynchronous functions (implying the return of the result after some time) take a callback function as a parameter and return an object(CancelableCallback), through which the client can cancel the request early, if required. After canceling the request, the callback function is guaranteed not to be called. It is important that the function exists in memory at the time the callback is called. If the callback function is being removed from memory, you should call cancel for the request before doing so. If you don't need to cancel the request, you can ignore the return value(CancelableCallback).

All library functions/classes are fairly obvious and documented in the public library header files (todo: link here). So look there for full documentation.

Example code for Android(Kotlin):
```

    val logFunc = WSNet.Function0 { strLog : String ->
        runOnUiThread {
            // out log
        }
    }
    WSNet.setLogger(logFunc)
    WSNet.initialize("android", "1.1", false, "")

    WSNet.instance().serverAPI().myIP({ serverApiRetCode: Int, jsonData: String ->
        Log.v("Windscribe", jsonData)
    })

```
Note: It is necessary to connect `wsnet.aar` file to the project before use the library.


Example for iOS(Swift):
```

    let loggerFunc = { [](logStr: String) -> Void in
        print(logStr)
    }
    WSNet.setLogger(loggerFunc)
    WSNet.initialize("ios", appVersion: "1.1", isUseStagingDomains: false, serverApiSettings: "")
    let wsnet = WSNet.instance()
    wsnet.serverAPI().setIgnoreSslErrors(false)
    wsnet.serverAPI().myIP(
        { [](requestId: Int32, data: String) -> Void in
            print(data)
        })

```
Note: It is necessary to add `wsnet.framework` folder to the project before use the library. It is also necessary to create a bridging header and import the necessary library header files there.
# ServerAPI Notes

For the most part, ServerAPI functionality is what will mostly be used from this library. Here are some notes on how to work with it properly.

For serverAPI to work efficiently, it needs to save some settings to persistent storage. In particular this is the latest working method of circumventing censorship.

Thus the client before finalization should call `string settings = serverAPI()->currentSettings()`  and save the `settings` string to persistent storage.

When initializing the client, you should restore the settings from the storage and transfer them with the last parameter when initializing the library.
```
string serverApiSettings = readStringFromPersistentStorage();
WSNet::initialize("macos", "2.7.10", false, serverApiSettings);
```

Also the client must call functions `serverAPI()->setConnectivityState(bool isOnline)` when the connectivity state changes and `severAPI()->setIsConnectedToVpnState(bool isConnected)` when the VPN connectivity state changes.

The client can also control options such as whether to ignore SSL errors and set api resolution settings. The setTryingBackupEndpointCallback function can be useful when you want to show progress when searching for working failovers. In particular, this is implemented in the desktop client at the login stage.

Keep in mind that the ServerAPI server functions can be called in any order any number of times from any thread. The callback function will be guaranteed to be called (unless of course it has been canceled) but the time after which it will be called can be any. It can also be quite long while the failovers are being gone through.
The following results may be returned in the callback function:
* *kSuccess = 0*. Successful execution and the json data can be used. The json is guaranteed to be correct(it will definitely be json and will contain fields such as data and error(if this field is present).
* *kNetworkError = 1*, *kNoNetworkConnection = 2*. Various network errors, it is recommended to repeat the request from the client side
* *kFailoverFailed = 3*. This means that all failovers have been tried and none of them work. In this case, it is recommended to prompt the user to ignore SSL-errors and try the queries again. Otherwise, there's nothing more we can do. There will be no connection to the server API.

# Control-plane transport, retries and failover

This reference consolidates the wsnet-owned contracts from [Client API Traffic: Timeouts, Retries & Failover](https://www.notion.so/3ba3486d7afd80b7bca6edd59b4a0b2d) and [Client Control Plane Behavior & Failover](https://www.notion.so/e4a5a0d1cf1045c99a9789db782fb19e). Implementation statements below are checked against [source commit 3634de8462f9](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/commit/3634de8462f918123ba549231db2c805d901c267), not a certification of every shipped desktop/mobile pin. Browser-extension behavior, backend proxy configuration, historical rollout dates and cross-team planning remain in the source pages. Keep both pages until this replacement is accepted; this section does not authorize archival.

## Request and timeout boundaries

Ordinary requests use `https://<subdomain>.<domain>/<Endpoint>`. API requests add `platform` and `app_version` to query parameters for GET/DELETE or the form body for POST/PUT. The assets server-list request has its own URL builder, without those automatic platform fields. Authenticated request factories set a bearer token; unauthenticated endpoints do not acquire one automatically. The User-Agent is `Windscribe/<app_version> (<platform>)`. See [request construction](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/api/baserequest.cpp), [request factories](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/api/serverapi/serverapi_requestsfactory.cpp) and [HTTP setup](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/httpnetworkmanager/curlnetworkmanager.cpp).

- The normal API timeout is **10 seconds per attempt**, including client DNS time, not a deadline for the entire failover/retry operation. DNS elapsed time is subtracted before curl runs. Individual request types can override this default.
- Curl's connection-phase budget is `5000 ms * resolved IP count`, still bounded by the remaining total timeout. The older page's blanket 5-second failure rule is not the current total request timeout.
- HTTP requests default to IPv4 resolution with DNS caching and fresh connections. `CURLOPT_FRESH_CONNECT` and `CURLOPT_FORBID_REUSE` prevent connection reuse by default; these are request options, not an immutable limitation of the HTTP manager.
- TLS has a 1.2 minimum, verification uses the configured bundled trust material, and redirect following is not enabled. Ignoring SSL errors is an explicit client-controlled option, not automatic failover policy.
- Async dispatch can overlap requests on the worker event loop. There is no general transport retry loop: distinguish route replacement in ServerAPI from caller/resource-manager backoff. Cancellation suppresses the callback, as described above.

Sources: [timeout constant](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/settings.h), [DNS budget accounting](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/httpnetworkmanager/httpnetworkmanager_impl.cpp), [HTTP defaults](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/httpnetworkmanager/httprequest.cpp).

## API answer versus broken route

A successful transport is not necessarily an API answer. For ordinary JSON requests, the response must be a JSON object containing `data` or `errorCode`; endpoint-specific parsing can add requirements. `kSuccess` here means a valid API answer, including application errors, not a successful login or entitlement change.

| Observation | ServerAPI handling |
|---|---|
| Non-5xx with a valid expected envelope, including 403 or 429 | Deliver the API answer; HTTP 429 alone does not trigger backoff or route replacement. |
| HTTP 5xx | Return `kNetworkError`, retain the route and let caller backoff pace retries. A disconnected route returning only 5xx for the 5-minute doubt window can be replaced; a successful API answer resets that window. |
| Empty, malformed or missing-envelope body | Treat as incorrect JSON and potentially replace the disconnected route. A middlebox HTML page is not a valid API error. |
| Raw-body request such as ServerConfigs | Non-2xx is not accepted merely because JSON parsing is disabled. |
| Device offline | Return `kNoNetworkConnection`; do not blame the route. |
| Other transport failure | Reprobe while disconnected, except a DNS failure on an already confirmed route is normally returned as `kNetworkError`. An unconfirmed persisted/fast-path route can reprobe even after DNS failure. |

The [response classifier](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/api/serverapi/serverapi_impl.cpp) re-executes failed requests through failover and marks sibling in-flight requests for discard when changing route. This is not an exactly-once guarantee for POST/PUT: a lost response does not prove the server did not apply a request. Do not add application retries assuming they are harmless. When every probe fails, prior API success yields `kNetworkError` with reset state; without prior success the queue receives `kFailoverFailed`.

## Route selection and anti-censorship mechanisms

VPN-connected requests use the primary domain rather than cycling the disconnected failover set. Disconnected routing can reuse the persisted working method, then validate it with a real request. Requests queue behind shared discovery, not a separate probe fan-out per request. A validated route has a 15-minute probe-cache freshness window, renewed by successful requests; when route data expires, a fresh cache permits re-resolving that method rather than a full probe. Save/restore settings and notify connectivity/VPN state as required in ServerAPI Notes above.

The private [failover container](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/private/failover/failovercontainer.cpp) defines this **priority order**, not a promise of serial network execution:

1. Primary `windscribe.com`, then backup `totallyacdn.com`.
2. Dynamic TXT discovery through Cloudflare candidates, then Google candidates.
3. Legacy monthly generated domains (`RandomDomainFailover`), still in the candidate list. This is distinct from the historical, unshipped `api-dga` replacement proposal in Notion. Do not copy generator secrets into documentation or interpret a deprecation intention as removal.
4. ECH discovery, then fallback ECH configuration.
5. API-access IP discovery, with the two access-IP candidates randomized.
6. CDN domain fronting (Fastly).

[FailoverProbeExecutor](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/api/serverapi/failoverprobeexecutor.cpp) launches discovery in parallel and probes candidates with `MyIp`, taking the first valid winner and canceling losing probes. The [limits](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/api/serverapi/failoverprobeexecutor.h) are four concurrent probes and a 250 ms hedge timer. Readiness and priority determine launches; the old instruction to wait for Cloudflare failure before trying Google is not current execution semantics. Staging restricts the private container to the default domain; the public build has a separate minimal container.

| Mechanism | Current wsnet contract |
|---|---|
| Dynamic DoH | TXT name `dynamic-api-host2.windscribe.com` for desktop, `dynamic-api-host3.windscribe.com` for Android/iOS. JSON DoH discovery uses the normal 10-second timeout. The source page's extension name `dynamic-api-host.windscribe.com` belongs to the extension, not this native library. |
| ECH | TXT configuration at `echconfig001.windscribe.dev`, or `fallback.echconfig001.windscribe.dev`, used with `ech-public-test.windscribe.dev`. Normal configuration honors its nonzero TTL; fallback is treated as non-expiring by this code. |
| Direct IP | Access-IP discovery obtains routes. API requests use the IP root; assets use the `/assets` path transformation rather than an `assets.<IP>` hostname. Historical fixed IP examples are not a current endpoint inventory. |
| Fastly | Backend root `pizdets.ca`; fronting candidates `www.esquire.com`, `cdn.yelp.com`, `pypi.org`. Curl connects using the fronting URL/SNI but preserves the real API/assets hostname in `Host`. Do not test ordinary DNS for `api.pizdets.ca` as though it were the fronting transport. Country/IP handling in Fastly VCL and the backend is a separate owner contract, not implemented by this library. |

Sources: [private settings](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/private/privatesettings.h), [DoH](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/private/failover/failovers/dynamicdomainfailover.cpp), [ECH](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/private/failover/failovers/echfailover.cpp), [direct-IP discovery](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/private/failover/failovers/accessipsfailover.cpp).

Tunnel validation and BridgeAPI are separate paths, not additional ServerAPI failover stages. The source pages refer to the older `pingTest` API and `checkip.windscribe.com`; current source has a [tunnel-test subsystem](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/tunneltest/tunneltest_impl.cpp) and configures `checkip.cdn8088.com` plus `checkip.level91.net`. Do not equate those hosts with `MyIp` probe routing or copy old queue/backup behavior onto the new subsystem. [BridgeAPI](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/api/bridgeapi/bridgeapi_impl.cpp) uses the separate in-tunnel address `10.255.255.1:19800`, session-token requests and no ServerAPI failover. WireGuard init/connect requests remain high-priority in the request factory.

## Resource refresh and backoff

The desktop-oriented `ApiResourcesManager` owns the following defaults. They are configurable through `setUpdateIntervals`; mobile app foreground policy is not established by these defaults.

| Resource | Default interval |
|---|---|
| Session, VPN connected | 1 minute |
| Session, VPN disconnected | 1 hour |
| Notifications | 1 hour |
| Inventory locations/servers, StaticIps, server configs/credentials, PortMap, CheckUpdate, AmneziaWG unblock parameters | 24 hours |

The [manager implementation](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/apiresourcesmanager/apiresourcesmanager.cpp) maintains Inventory v2 snapshots and Session inventory deltas, not simply the old assets-list revision flow. Initial authenticated fetches, explicit fetch calls, account changes and inventory deltas can cause earlier updates; the table is not a minimum request spacing guarantee. WireGuard connect-intent/key initialization is not an unconditional 24-hour resource fetch.

Failed resource requests use per-resource exponential backoff with nominal bounds 1s, 2s, 4s and so on, capped at 5 minutes, then uniform jitter in `[bound/2, bound]`. Thus the first delay can be 0.5 seconds, not an exact 1-second sleep. Interactive login/session/signup/auth-token retries cap at 1 minute. Offline failures do not advance the failure count. Explicit new interactive attempts reset their counters and cancel superseded retry timers. See [defaults and retry state](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/apiresourcesmanager/apiresourcesmanager.h).

The older source page's launch/foreground/connect-error schedule is cross-platform intended behavior, not proof every consumer implements it. Its proposed `Session.refetch_res` array protocol (empty means all resources, otherwise named resources, with a 12-hour repeat guard cleared when the flag disappears) remains **unimplemented planning**, not a supported wsnet API contract. Do not confuse it with existing explicit fetch methods or inventory deltas.

## Sticky country-specific server lists

The original requirement is to retain a restricted-network list while connected through a VPN, rather than replacing it with a list geolocated from the VPN exit. The current [legacy assets ServerLocations implementation](https://gitlab.int.windscribe.com/ws/client/client-libs/wsnet/-/blob/3634de8462f918123ba549231db2c805d901c267/src/api/serverapi/serverlocations_request.cpp) is more precise than the source page's unconditional append/reset wording:

- Learn or clear persisted `info.country_override` only if the request began disconnected and the client is still disconnected when the answer arrives.
- Automatically send that saved override only while VPN-connected. A disconnected request can be geolocated again without the sticky value.
- An explicit advanced override takes precedence; the ignore-country-override option sends `ZZ`.
- Do not erase or replace the saved value if the request began connected or the client is connected when the response arrives. These are start/completion checks, not a transition-epoch guard. Missing override clears it only in the disconnected-to-disconnected case.
- Inventory v2 request construction is separate and can use an explicit advanced override. Do not generalize the legacy assets sticky-list lifecycle to all inventory endpoints or every shipped consumer.

The source pages retain browser-extension limits, node TLS identity context, backend/edge setup, historical endpoint and user-agent rollout records, proposed refetch behavior, and consumer launch/foreground requirements. Those sections are not made redundant by this bounded wsnet migration.

# Versioning

The library version is derived automatically from git tags at build time — no manual edits to `CMakeLists.txt` are needed.

## Version format

Tags follow the `MAJOR.MINOR.PATCH` format (e.g. `1.4.8`). Two macros are available in the generated `wsnet_version.h` header:

| Macro | Example value | Description |
|---|---|---|
| `WSNET_VERSION_STRING` | `"1.4.8"` | Clean version from the nearest tag |
| `WSNET_VERSION_DESCRIBE` | `"1.4.8-20-ga2bf011"` | Full build ID: tag + commits since tag + commit hash |
| `WSNET_VERSION_MAJOR` | `1` | Major version number |
| `WSNET_VERSION_MINOR` | `4` | Minor version number |
| `WSNET_VERSION_PATCH` | `8` | Patch version number |

On an untagged commit `WSNET_VERSION_DESCRIBE` includes the number of commits since the last tag and the short commit hash, which makes it easy to identify the exact build from logs.

## Releasing a new version

```bash
git tag -a 1.5.0 -m "Release 1.5.0"
git push origin 1.5.0
```

The next CI build will automatically pick up the new version.

## Fallback

If git is unavailable or the repository has no tags, the build falls back to the hardcoded version defined by `WSNET_VERSION_FALLBACK` in `CMakeLists.txt`.

# Further improvements
* For Server API functions to make results return as wrapper classes instead of raw json data?
