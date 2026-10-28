target_sources(wsnet PRIVATE
    cancelablecallback.h
    wsnet_callback_sink.h
    utils.h
    utils.cpp
    crypto_utils.cpp
    crypto_utils.h
    wsnet_logger.cpp
    wsnet_logger.h
    persistentsettings.cpp
    persistentsettings.h
    requesterror.cpp
    requesterror.h
    spdlog_utils.h
    urlquery_utils.cpp
    urlquery_utils.h
)

if (ANDROID)
    # --wrap rewrites the clock_gettime references in wsnet's objects and in the static libraries
    # linked into it, which is the only way to reach the call inside curl's prebuilt Curl_now().
    target_sources(wsnet PRIVATE clock_gettime_android.cpp)
    target_link_options(wsnet PRIVATE "-Wl,--wrap=clock_gettime")
endif()
