#include "processmanager.h"
#include "utils/wsnet_logger.h"
#include <sys/stat.h>

namespace wsnet {

ProcessManager::ProcessManager(boost::asio::io_context &io_context) :
    io_context_(io_context)
{
}

ProcessManager::~ProcessManager()
{
    // Lifetime invariant: WSNet stops the io_context and joins its worker thread
    // (see ~WSNet_impl in wsnet.cpp) before any owner destroys this ProcessManager.
    // The on_exit handler in execute() captures a raw `this` and is dispatched on the
    // io_context thread; since that thread is already joined by the time we get here,
    // no on_exit completion can run during or after destruction, so the raw capture is
    // safe. If shutdown is ever reordered to destroy this while the io_context is still
    // running, that guarantee breaks and on_exit would touch freed memory.
    std::lock_guard locker(mutex_);
    for (auto &it : processes_) {
        it.second->process.terminate();
    }
}

bool ProcessManager::execute(const std::string &cmd, const std::vector<std::string> &args, ProcessManagerCallback callback)
{
    try {
        std::lock_guard locker(mutex_); // NOLINT

        // NOLINTBEGIN(clang-analyzer-cplusplus.NewDelete): false positive in Boost's PATH-split
        // (boost::is_any_of copy/destroy) reachable through boost::process::child; that branch is
        // unreachable here since exePath is absolute. The analyzer anchors several paths across this
        // block, so the suppression spans the whole resolve/validate/spawn region.
        // Resolve the executable via PATH, then validate it is safe to run even when wsnet is
        // hosted in an elevated (root) helper: the canonicalized binary must be a regular file
        // owned by root and not group/world-writable, and its containing directory must likewise
        // be root-owned and not group/world-writable. This stops an unprivileged user from
        // redirecting us to a trojan binary via a poisoned PATH or a writable directory, and the
        // directory check closes the stat->exec TOCTOU window (CWE-426). We exec the canonical
        // path so symlinks cannot redirect the final target.
        namespace fs = boost::process::v1::filesystem;
        auto resolved = boost::process::v1::search_path(cmd);
        if (resolved.empty()) {
            g_logger->error("Cannot find executable: {}", cmd);
            return false;
        }
        auto exePath = fs::canonical(resolved);   // resolves symlinks; throws if missing (caught below)
        struct stat fileStat;
        struct stat dirStat;
        if (::stat(exePath.c_str(), &fileStat) != 0 ||
            ::stat(exePath.parent_path().c_str(), &dirStat) != 0 ||
            !S_ISREG(fileStat.st_mode) ||
            fileStat.st_uid != 0 || dirStat.st_uid != 0 ||
            (fileStat.st_mode & (S_IWGRP | S_IWOTH)) ||
            (dirStat.st_mode & (S_IWGRP | S_IWOTH))) {
            g_logger->error("Refusing to execute untrusted binary: {}", exePath.string());
            return false;
        }

        auto childProcess = std::make_unique<ChildProcess>();
        childProcess->callback = callback;
        childProcess->process = boost::process::v1::child(exePath, args,
            boost::process::v1::std_out >  childProcess->data,
            io_context_,
            boost::process::v1::on_exit = [this, id = curId_](int exit, std::error_code ec) {
                // on exit function handler
                std::string data;
                ProcessManagerCallback callback;
                // copy data and callback and remove an item from processes
                {
                    std::lock_guard locker(mutex_);
                    auto it = processes_.find(id);
                    if (it != processes_.end()) {
                        std::ostringstream os;
                        os << it->second->data.rdbuf();
                        data = os.str();
                        callback = it->second->callback;
                        processes_.erase(it);
                    } else {
                        assert(false);
                    }
                }
                // call callback
                callback(exit, data);
            });
        // NOLINTEND(clang-analyzer-cplusplus.NewDelete)

        processes_[curId_++] = std::move(childProcess);

    } catch(...) {
        g_logger->error("Cannot start a process: {}", cmd);
        return false;
    }

    return true;
}

} // namespace wsnet
