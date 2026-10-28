// Routes every CLOCK_MONOTONIC_RAW reader in this library to CLOCK_MONOTONIC.
//
// curl builds Curl_now() with HAVE_CLOCK_GETTIME_MONOTONIC_RAW, so all of its timing uses
// CLOCK_MONOTONIC_RAW and only falls back to CLOCK_MONOTONIC if the call returns an error.
// On some Android images CLOCK_MONOTONIC_RAW is unusable: an API 24 arm64 emulator advances it
// at ~3x real time and steps it backwards by ~906 s, which drives Curl_timeleft() negative and
// aborts every transfer with CURLE_OPERATION_TIMEDOUT a few milliseconds in, mid-TLS-handshake.
//
// boost::asio and std::chrono::steady_clock already use CLOCK_MONOTONIC, so this also collapses
// the library's two monotonic clock domains into one.  Reached via -Wl,--wrap=clock_gettime,
// which rewrites the references in wsnet's own objects and in the static libraries linked into
// it, curl included.

#include <time.h>

extern "C" {

int __real_clock_gettime(clockid_t clk_id, struct timespec *tp);

int __wrap_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    return __real_clock_gettime(clk_id == CLOCK_MONOTONIC_RAW ? CLOCK_MONOTONIC : clk_id, tp);
}

}
