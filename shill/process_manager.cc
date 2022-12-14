// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/process_manager.h"

#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/check.h>
#include <base/logging.h>
#include <base/notreached.h>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kManager;
static std::string ObjectID(const ProcessManager* pm) {
  return "process_manager";
}
}  // namespace Logging

namespace {

base::LazyInstance<ProcessManager>::DestructorAtExit g_process_manager =
    LAZY_INSTANCE_INITIALIZER;

static const int kTerminationTimeoutSeconds = 2;
static const int kWaitpidPollTimesForSIGTERM = 10;
static const int kWaitpidPollTimesForSIGKILL = 8;
static const unsigned int kWaitpidPollIntervalUpperBoundMilliseconds = 2000;
static const unsigned int kWaitpidPollInitialIntervalMilliseconds = 4;

bool SetupChild(const std::map<std::string, std::string>& env,
                bool terminate_with_parent) {
  // Setup environment variables.
  clearenv();
  for (const auto& key_value : env) {
    setenv(key_value.first.c_str(), key_value.second.c_str(), 0);
  }
  if (terminate_with_parent) {
    prctl(PR_SET_PDEATHSIG, SIGTERM);
  }
  return true;
}

}  // namespace

ProcessManager::ProcessManager() = default;

ProcessManager::~ProcessManager() = default;

// static
ProcessManager* ProcessManager::GetInstance() {
  return g_process_manager.Pointer();
}

void ProcessManager::Init(EventDispatcher* dispatcher) {
  SLOG(this, 2) << __func__;
  CHECK(!async_signal_handler_);
  async_signal_handler_.reset(new brillo::AsynchronousSignalHandler());
  async_signal_handler_->Init();
  process_reaper_.Register(async_signal_handler_.get());
  dispatcher_ = dispatcher;
  minijail_ = brillo::Minijail::GetInstance();
}

void ProcessManager::Stop() {
  SLOG(this, 2) << __func__;
  CHECK(async_signal_handler_);
  process_reaper_.Unregister();
  async_signal_handler_.reset();
}

pid_t ProcessManager::StartProcess(
    const base::Location& spawn_source,
    const base::FilePath& program,
    const std::vector<std::string>& arguments,
    const std::map<std::string, std::string>& environment,
    bool terminate_with_parent,
    const base::Callback<void(int)>& exit_callback) {
  SLOG(this, 2) << __func__ << "(" << program.value() << ")";

  // Setup/create child process.
  std::unique_ptr<brillo::Process> process(new brillo::ProcessImpl());
  process->AddArg(program.value());
  for (const auto& option : arguments) {
    process->AddArg(option);
  }
  // Important to close unused fds. See crbug.com/531655 and crbug.com/911234.
  process->SetCloseUnusedFileDescriptors(true);
  process->SetPreExecCallback(
      base::BindOnce(&SetupChild, environment, terminate_with_parent));
  if (!process->Start()) {
    LOG(ERROR) << "Failed to start child process for " << program.value();
    return -1;
  }

  // Setup watcher for the child process.
  pid_t pid = process->pid();
  CHECK(process_reaper_.WatchForChild(
      spawn_source, pid,
      base::Bind(&ProcessManager::OnProcessExited, weak_factory_.GetWeakPtr(),
                 pid)));

  // Release ownership of the child process from the |process| object, so that
  // child process will not get killed on destruction of |process| object.
  process->Release();

  watched_processes_[pid] = std::move(exit_callback);
  return pid;
}

pid_t ProcessManager::StartProcessInMinijailWithPipes(
    const base::Location& spawn_source,
    const base::FilePath& program,
    const std::vector<std::string>& arguments,
    const std::map<std::string, std::string>& environment,
    const MinijailOptions& minijail_options,
    const base::Callback<void(int)>& exit_callback,
    struct std_file_descriptors std_fds) {
  SLOG(this, 2) << __func__ << "(" << program.value() << ")";

  std::vector<char*> args;
  args.push_back(const_cast<char*>(program.value().c_str()));
  for (const auto& arg : arguments) {
    args.push_back(const_cast<char*>(arg.c_str()));
  }
  args.push_back(nullptr);

  std::vector<std::string> env_strings;
  for (const auto& var : environment) {
    env_strings.push_back(
        base::StringPrintf("%s=%s", var.first.c_str(), var.second.c_str()));
  }
  std::vector<char*> env;
  for (const auto& str : env_strings) {
    env.push_back(const_cast<char*>(str.c_str()));
  }
  env.push_back(nullptr);

  struct minijail* jail = minijail_->New();

  if (!minijail_->DropRoot(jail, minijail_options.user.c_str(),
                           minijail_options.group.c_str())) {
    LOG(ERROR) << "Minijail failed to drop root privileges?";
    return -1;
  }

  if (minijail_options.inherit_supplementary_groups) {
    minijail_inherit_usergroups(jail);
  }

  minijail_->UseCapabilities(jail, minijail_options.capmask);
  minijail_->ResetSignalMask(jail);
  // Important to close non-standard fds. See crbug.com/531655,
  // crbug.com/911234 and crbug.com/914444.
  if (minijail_options.close_nonstd_fds) {
    minijail_->PreserveFd(jail, STDIN_FILENO, STDIN_FILENO);
    minijail_->PreserveFd(jail, STDOUT_FILENO, STDOUT_FILENO);
    minijail_->PreserveFd(jail, STDERR_FILENO, STDERR_FILENO);
    minijail_->CloseOpenFds(jail);
  }

  if (minijail_options.rlimit_as_soft.has_value()) {
    minijail_rlimit(jail, RLIMIT_AS, minijail_options.rlimit_as_soft.value(),
                    RLIM_INFINITY);
  }

  pid_t pid;
  if (!minijail_->RunEnvPipesAndDestroy(jail, args, env, &pid, std_fds.stdin_fd,
                                        std_fds.stdout_fd, std_fds.stderr_fd)) {
    LOG(ERROR) << "Unable to spawn " << program.value() << " in a jail.";
    return -1;
  }

  CHECK(process_reaper_.WatchForChild(
      spawn_source, pid,
      base::Bind(&ProcessManager::OnProcessExited, weak_factory_.GetWeakPtr(),
                 pid)));

  watched_processes_[pid] = std::move(exit_callback);
  return pid;
}

bool ProcessManager::StopProcess(pid_t pid) {
  SLOG(this, 2) << __func__ << "(" << pid << ")";

  if (pending_termination_processes_.find(pid) !=
      pending_termination_processes_.end()) {
    LOG(ERROR) << "Process " << pid << " already being stopped.";
    return false;
  }

  if (watched_processes_.find(pid) == watched_processes_.end()) {
    LOG(ERROR) << "Process " << pid << " not being watched";
    return false;
  }
  // Caller not interested in watching this process anymore, since the
  // process termination is initiated by the caller.
  watched_processes_.erase(pid);

  // Attempt to send SIGTERM signal first.
  return TerminateProcess(pid, false);
}

bool ProcessManager::StopProcessAndBlock(pid_t pid) {
  SLOG(this, 2) << __func__ << "(" << pid << ")";

  auto terminated_process = pending_termination_processes_.find(pid);

  if (terminated_process != pending_termination_processes_.end()) {
    LOG(INFO) << "Process " << pid << " already being stopped.";
    terminated_process->second->Cancel();
    pending_termination_processes_.erase(terminated_process);
  } else {
    if (watched_processes_.find(pid) == watched_processes_.end()) {
      LOG(ERROR) << "Process " << pid << " not being watched";
      return false;
    }
    // Caller not interested in watching this process anymore, since the
    // process termination is initiated by the caller.
    watched_processes_.erase(pid);
  }

  // We are no longer interested in tracking the exit of this process.
  // Also, we will hopefully reap this process ourselves, so remove any
  // record of this pid from process_reaper_.
  process_reaper_.ForgetChild(pid);

  // Try SIGTERM firstly.
  // Send SIGKILL signal if SIGTERM was not handled in a timely manner.
  if (KillProcessWithTimeout(pid, false) || KillProcessWithTimeout(pid, true)) {
    return true;
  }

  // In case of killing failure.
  LOG(ERROR) << "Timeout waiting for process " << pid << " to be killed.";

  return false;
}

bool ProcessManager::KillProcessWithTimeout(pid_t pid, bool kill_signal) {
  SLOG(this, 2) << __func__ << "(pid: " << pid << ")";

  bool killed = false;
  if (KillProcess(pid, kill_signal ? SIGKILL : SIGTERM, &killed)) {
    if (killed) {
      return true;
    }

    int poll_times =
        kill_signal ? kWaitpidPollTimesForSIGKILL : kWaitpidPollTimesForSIGTERM;

    if (WaitpidWithTimeout(pid, kWaitpidPollInitialIntervalMilliseconds,
                           kWaitpidPollIntervalUpperBoundMilliseconds,
                           poll_times)) {
      return true;
    }
  }
  return false;
}

bool ProcessManager::KillProcess(pid_t pid, int signal, bool* killed) {
  SLOG(this, 2) << __func__ << "(pid: " << pid << ")";

  if (kill(pid, signal) < 0) {
    if (errno == ESRCH) {
      SLOG(this, 2) << "Process " << pid << " has exited.";
      *killed = true;
      return true;
    }
    PLOG(ERROR) << "Failed to send " << signal << "signal to process " << pid;
    return false;
  }
  return true;
}

bool ProcessManager::WaitpidWithTimeout(pid_t pid,
                                        unsigned int sleep_ms,
                                        unsigned int upper_bound_ms,
                                        int tries) {
  SLOG(this, 2) << __func__ << "(pid: " << pid << ")";

  while (tries-- > 0) {
    if (waitpid(pid, nullptr, WNOHANG) == pid) {
      return true;
    }
    usleep(sleep_ms * 1000);
    if (2 * sleep_ms < upper_bound_ms) {
      sleep_ms *= 2;
    }
  }
  return false;
}

bool ProcessManager::UpdateExitCallback(
    pid_t pid, const base::Callback<void(int)>& new_callback) {
  SLOG(this, 2) << __func__ << "(pid: " << pid << ")";

  const auto process_entry = watched_processes_.find(pid);
  if (process_entry == watched_processes_.end()) {
    LOG(ERROR) << "Process " << pid << " not being watched";
    return false;
  }

  process_entry->second = new_callback;
  return true;
}

void ProcessManager::OnProcessExited(pid_t pid, const siginfo_t& info) {
  SLOG(this, 2) << __func__ << "(pid: " << pid << ")";

  // Invoke the exit callback if the process is being watched.
  auto watched_process = watched_processes_.find(pid);
  if (watched_process != watched_processes_.end()) {
    base::Callback<void(int)> callback = watched_process->second;
    watched_processes_.erase(watched_process);
    callback.Run(info.si_status);
    return;
  }

  // Process terminated by us, cancel timeout handler.
  auto terminated_process = pending_termination_processes_.find(pid);
  if (terminated_process != pending_termination_processes_.end()) {
    terminated_process->second->Cancel();
    pending_termination_processes_.erase(terminated_process);
    return;
  }

  NOTREACHED() << "Unknown process " << pid << " status " << info.si_status;
}

void ProcessManager::ProcessTerminationTimeoutHandler(pid_t pid,
                                                      bool kill_signal) {
  SLOG(this, 2) << __func__ << "(pid: " << pid << ")";

  CHECK(pending_termination_processes_.find(pid) !=
        pending_termination_processes_.end());
  pending_termination_processes_.erase(pid);
  // Process still not killed after SIGKILL signal.
  if (kill_signal) {
    LOG(ERROR) << "Timeout waiting for process " << pid << " to be killed.";
    return;
  }

  // Retry using SIGKILL signal.
  TerminateProcess(pid, true);
}

bool ProcessManager::TerminateProcess(pid_t pid, bool kill_signal) {
  SLOG(this, 2) << __func__ << "(pid: " << pid << ", "
                << "use_sigkill: " << kill_signal << ")";

  int signal = (kill_signal) ? SIGKILL : SIGTERM;
  bool killed = false;
  if (!KillProcess(pid, signal, &killed)) {
    return false;
  }
  if (killed) {
    return true;
  }
  auto termination_callback = std::make_unique<TerminationTimeoutCallback>(
      base::Bind(&ProcessManager::ProcessTerminationTimeoutHandler,
                 weak_factory_.GetWeakPtr(), pid, kill_signal));
  dispatcher_->PostDelayedTask(FROM_HERE, termination_callback->callback(),
                               kTerminationTimeoutSeconds * 1000);
  pending_termination_processes_[pid] = std::move(termination_callback);
  return true;
}

}  // namespace shill
