#ifndef TIMEOUT_EXECUTOR_H
#define TIMEOUT_EXECUTOR_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>
#include <chrono>

namespace fuzz {

enum class ExecutionResult {
    SUCCESS,
    TIMEOUT,
    CRASH,
    ERROR
};

struct ExecutionOutput {
    ExecutionResult result;
    int exit_code;
    double elapsed_ms;
    std::vector<uint8_t> output_data;
};

using TargetFunction = std::function<int(const std::vector<uint8_t>&)>;

class TimeoutExecutor {
public:
    explicit TimeoutExecutor(int timeout_ms = 1000);
    ~TimeoutExecutor();

    void setTimeout(int timeout_ms);
    int getTimeout() const;

    void setTargetFunction(TargetFunction func);

    ExecutionOutput execute(const std::vector<uint8_t>& input);

    ExecutionOutput executeWithFunction(
        const std::vector<uint8_t>& input,
        TargetFunction func);

    static ExecutionOutput executeInProcess(
        const std::vector<uint8_t>& input,
        TargetFunction func,
        int timeout_ms);

private:
    int timeout_ms_;
    TargetFunction target_function_;

    ExecutionOutput executeForkExec(const std::vector<uint8_t>& input);
};

} // namespace fuzz

#endif // TIMEOUT_EXECUTOR_H
