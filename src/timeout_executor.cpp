#include "timeout_executor.h"
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>

namespace fuzz {

namespace {

volatile sig_atomic_t g_child_pid = 0;
volatile sig_atomic_t g_timeout_occurred = 0;

void timeoutHandler(int signum) {
    (void)signum;
    g_timeout_occurred = 1;
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGKILL);
    }
}

} // anonymous namespace

TimeoutExecutor::TimeoutExecutor(int timeout_ms)
    : timeout_ms_(timeout_ms)
    , target_function_(nullptr)
{
}

TimeoutExecutor::~TimeoutExecutor() = default;

void TimeoutExecutor::setTimeout(int timeout_ms) {
    timeout_ms_ = timeout_ms;
}

int TimeoutExecutor::getTimeout() const {
    return timeout_ms_;
}

void TimeoutExecutor::setTargetFunction(TargetFunction func) {
    target_function_ = std::move(func);
}

ExecutionOutput TimeoutExecutor::execute(const std::vector<uint8_t>& input) {
    if (target_function_) {
        return executeWithFunction(input, target_function_);
    }
    
    ExecutionOutput output;
    output.result = ExecutionResult::ERROR;
    output.exit_code = -1;
    output.elapsed_ms = 0;
    return output;
}

ExecutionOutput TimeoutExecutor::executeWithFunction(
    const std::vector<uint8_t>& input,
    TargetFunction func)
{
    return executeInProcess(input, func, timeout_ms_);
}

ExecutionOutput TimeoutExecutor::executeInProcess(
    const std::vector<uint8_t>& input,
    TargetFunction func,
    int timeout_ms)
{
    ExecutionOutput output;
    output.result = ExecutionResult::ERROR;
    output.exit_code = -1;
    output.elapsed_ms = 0;

    if (!func) {
        return output;
    }

    struct sigaction old_sa;
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeoutHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, &old_sa) != 0) {
        return output;
    }

    pid_t pid = fork();
    
    if (pid < 0) {
        sigaction(SIGALRM, &old_sa, nullptr);
        return output;
    }
    
    if (pid == 0) {
        alarm(0);
        
        sigaction(SIGALRM, &old_sa, nullptr);
        
        try {
            int result = func(input);
            _exit(result);
        } catch (...) {
            _exit(255);
        }
    }
    
    g_child_pid = pid;
    g_timeout_occurred = 0;
    
    int timeout_sec = timeout_ms / 1000;
    int timeout_usec = (timeout_ms % 1000) * 1000;
    
    struct itimerval timer;
    timer.it_value.tv_sec = timeout_sec;
    timer.it_value.tv_usec = timeout_usec;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    
    if (setitimer(ITIMER_REAL, &timer, nullptr) != 0) {
        alarm(timeout_sec > 0 ? timeout_sec : 1);
    }
    
    int status = 0;
    pid_t wait_result = waitpid(pid, &status, 0);
    
    setitimer(ITIMER_REAL, nullptr, nullptr);
    alarm(0);
    
    g_child_pid = 0;
    
    auto elapsed = std::chrono::duration<double, std::milli>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    output.elapsed_ms = elapsed;
    
    if (wait_result < 0) {
        sigaction(SIGALRM, &old_sa, nullptr);
        return output;
    }
    
    if (g_timeout_occurred) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        
        output.result = ExecutionResult::TIMEOUT;
        output.exit_code = -1;
    } else if (WIFEXITED(status)) {
        output.result = ExecutionResult::SUCCESS;
        output.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        output.result = ExecutionResult::CRASH;
        output.exit_code = 128 + WTERMSIG(status);
    } else {
        output.result = ExecutionResult::ERROR;
        output.exit_code = -1;
    }
    
    sigaction(SIGALRM, &old_sa, nullptr);
    
    return output;
}

} // namespace fuzz
