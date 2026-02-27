# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**wsnet** is a cross-platform C++17 networking library for Windscribe VPN clients (Windows/Mac/Linux/Android/iOS). It provides unified access to Windscribe's server APIs with built-in anti-censorship bypass methods, along with DNS resolution, HTTP networking, and ping functionality.

The library uses:
- **Boost.ASIO** for async I/O (single io_context thread model)
- **libcurl** (with ECH patches) for HTTP requests
- **c-ares** for asynchronous DNS resolution
- **OpenSSL** (with ECH patches) for TLS
- **Scapix** for automatic C++ → Java/Swift bindings on mobile platforms
- **vcpkg** for dependency management

## Building

### Desktop (Windows/Mac/Linux)

The library integrates via vcpkg. CMake must be installed along with platform-specific C++ compiler (Visual C++/XCode/clang).

**Build with tests (desktop only):**
```bash
cmake -B build -S . \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DIS_BUILD_TESTS=ON
cmake --build build
```

**Run tests:**
```bash
./build/test/wsnet_test
```

Tests use Google Test and are located in `src/private/tests/`. Tests are only built when `IS_BUILD_TESTS` is defined and are excluded from mobile builds.

### Android

**Requirements:** Android Studio, `$VCPKG_ROOT` and `$JAVA_HOME` environment variables set.

```bash
cd tools
./build_android.sh
```

Output: `wsnet.aar` (Android Archive ready for integration)

### iOS

**Requirements:** XCode, `$VCPKG_ROOT` environment variable set.

```bash
cd tools
./build_ios.sh
```

Output: `build/WSNet.xcframework` (supports iOS, iOS Simulator, tvOS, tvOS Simulator)

## Architecture

### Core Components

The library is accessed through a singleton `WSNet::instance()` after initialization. Main components:

- **ServerAPI** - Main Windscribe API access (login, session, server locations, WireGuard configs, etc.) with full failover support
- **BridgeAPI** - Legacy Bridge protocol API (IP rotation, simple session-based, no failover)
- **DnsResolver** - Async DNS with custom server support and caching
- **HttpNetworkManager** - HTTP client with custom DNS integration and TLS modifications (SNI spoofing, ECH)
- **EmergencyConnect** - Fallback connectivity via hardcoded OpenVPN endpoints
- **PingManager** - ICMP and HTTP ping functionality
- **DecoyTraffic** - Traffic obfuscation features
- **ApiResourcesManager** - Manages API resources like server lists

All async operations return `shared_ptr<WSNetCancelableCallback>` for cancellation and use callback pattern.

### Public/Private Build System

The codebase has a **dual-build configuration**:

- **`src/private/`** - Production build with proprietary censorship bypass methods (16+ failover strategies including ECH, CDN fronting, dynamic domains). Contains `privatesettings.h` with hardcoded (obfuscated) endpoints and credentials.

- **`src/public/`** - Open-source fallback with minimal failover (only hardcoded domains).

CMake automatically selects private if it exists, otherwise uses public. Both implement the same `IFailoverContainer` interface.

### Failover Mechanism

ServerAPI uses a **hierarchical failover system** to bypass censorship:

1. Each request goes through `RequestExecutorViaFailover`
2. Tries failovers sequentially (tracked by UUID to prevent loops)
3. Each `BaseFailover` returns `FailoverData` containing:
   - `domain` - Target domain
   - `sniDomain` - SNI for domain fronting
   - `echConfig` - Encrypted Client Hello configuration
   - `ttl` - Time-to-live for dynamic failovers
4. If all failovers fail → returns `ApiRetCode::kFailoverFailed`

Failover types (private build): hardcoded domains → ECH with Cloudflare → dynamic Cloudflare → dynamic Google DoH → direct IP access → CDN fronting (Fastly/Yelp/PyPI).

### Mobile Bindings (Scapix)

For Android/iOS builds, Scapix automatically generates Java/Swift bindings from C++ headers:

- All public headers in `include/wsnet/WSNet*.h` are bridged
- Each header must contain exactly one class matching the filename (Java requirement)
- All public classes inherit from `scapix_object<T>` (empty on desktop, actual bridge on mobile)
- Generated code: `generated/bridge/java/com/wsnet/lib/` (Android) or `generated/bridge/objc/` (iOS)

Android-specific: Custom JNI with thread auto-attach and class loader caching.

iOS-specific: Builds as framework with Objective-C bridge headers.

### Threading Model

- Single worker thread runs Boost.ASIO `io_context`
- All callbacks dispatched to this thread
- Thread-safe from client perspective (can call from any thread)
- Protected by mutexes where needed (e.g., `PersistentSettings`)

### Key Patterns

1. **Pimpl** - Public interfaces delegate to `*_impl` classes for ABI stability
2. **Async callbacks** - All I/O returns cancelable callbacks with guaranteed invocation (unless canceled)
3. **Request queueing** - ServerAPI queues requests during failover attempts
4. **Persistent state** - Client must save/restore settings via `serverAPI()->currentSettings()` for optimal failover performance
5. **State management** - `ConnectState` tracks device online/offline and VPN connection status

## Common Development Tasks

### Adding a new ServerAPI endpoint

1. Add method signature to `include/wsnet/WSNetServerAPI.h`
2. Implement in `src/api/serverapi/serverapi_impl.h` and `.cpp`
3. Create a `Request` subclass (e.g., `MyIPRequest`) that inherits from `BaseRequest`
4. Override `getUrl()`, `getPlatformNamePostfix()`, and optionally `execute()`
5. Use `RequestExecutorViaFailover` helper for automatic failover handling

### Running a single test

Tests are Google Test based:

```bash
./build/test/wsnet_test --gtest_filter=TestSuiteName.TestName
```

Test files are in `src/private/tests/` and named `*.test.cpp`.

### Code Coverage

Coverage is enabled automatically when building with tests on non-Windows platforms:

```bash
# Build with coverage
cmake -B build -S . -DIS_BUILD_TESTS=ON \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build

# Run tests
./build/test/wsnet_test

# Generate coverage report (requires lcov)
lcov --capture --directory build --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage.info  # Remove system files
genhtml coverage.info --output-directory coverage_report
```

## Important Constraints

### ServerAPI State Management

Clients **must**:
1. Call `serverAPI()->setConnectivityState(bool)` when device connectivity changes
2. Call `serverAPI()->setIsConnectedToVpnState(bool)` when VPN state changes
3. Save `serverAPI()->currentSettings()` to persistent storage before shutdown
4. Restore settings via `WSNet::initialize(..., serverApiSettings)` on startup

This enables the library to remember the last working failover method for faster recovery.

### Request Behavior

- Requests can be called from any thread in any order
- Callbacks are **always** invoked unless explicitly canceled
- Callback timing is unpredictable (can be long during failover attempts)
- Return codes:
  - `kSuccess = 0` - JSON data is valid and usable
  - `kNetworkError = 1`, `kNoNetworkConnection = 2` - Retry recommended
  - `kFailoverFailed = 3` - All bypass methods failed; recommend user enable "ignore SSL errors"

### Public Headers

When adding new public APIs:
- Filename must start with `WSNet` prefix
- Filename must match class name exactly (e.g., `WSNetFoo.h` → `class WSNetFoo`)
- Must be in `include/wsnet/` directory
- Must inherit from `scapix_object<ClassName>` for mobile compatibility

## File Locations

- **Public API**: `include/wsnet/WSNet*.h`
- **Implementation**: `src/api/`, `src/httpnetworkmanager/`, `src/dnsresolver/`, etc.
- **Failover logic**: `src/private/failover/` or `src/public/failover/`
- **Tests**: `src/private/tests/*.test.cpp`
- **Resources**: `resources/` (embedded via CMakeRC as `wsnet::rc`)
- **Build scripts**: `tools/build_android.sh`, `tools/build_ios.sh`

## Dependencies (vcpkg)

Main dependencies managed via vcpkg:
- `c-ares` - DNS resolution
- `curl` - HTTP (with ECH patches from private vcpkg registry)
- `openssl` - TLS (with ECH patches from private vcpkg registry)
- `spdlog` - Logging
- `rapidjson` - JSON parsing
- `skyr-url` - URL parsing
- `boost-filesystem` - File operations
- `gtest` - Testing
- `scapix` - Mobile bindings (Android/iOS only)
- `cmakerc` - Resource embedding

Custom patches for curl/openssl are in the private vcpkg registry: `ws/client/client-libs/ws-vcpkg-registry.git`
