#ifndef FUZZER_H
#define FUZZER_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <random>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace fuzz {

enum class MutationType {
    BIT_FLIP,
    BYTE_FLIP,
    BYTE_INSERT,
    BYTE_DELETE,
    BYTE_RANDOM,
    BLOCK_SHUFFLE,
    ARITHMETIC_ADD,
    ARITHMETIC_SUB,
    INTERESTING_VALUE,
    OVERWRITE_BLOCK,
    DUPLICATE_BLOCK
};

struct FuzzerStats {
    size_t total_mutations = 0;
    size_t crashes_found = 0;
    size_t hangs_found = 0;
    size_t interesting_inputs = 0;
    size_t unique_paths = 0;
    uint64_t execs_per_second = 0;
    double avg_exec_time_ms = 0.0;
    size_t current_corpus_size = 0;
    size_t max_corpus_size = 0;
};

struct FuzzInput {
    std::vector<uint8_t> data;
    uint64_t seed;
    size_t generation;
    bool caused_crash;
    bool caused_hang;
    bool is_interesting;
    std::string source_file;
    
    FuzzInput() : seed(0), generation(0), caused_crash(false), 
                  caused_hang(false), is_interesting(false) {}
    
    explicit FuzzInput(const std::vector<uint8_t>& input_data)
        : data(input_data), seed(0), generation(0), caused_crash(false),
          caused_hang(false), is_interesting(false) {}
};

using CrashCallback = std::function<void(const FuzzInput&, const std::string&)>;
using HangCallback = std::function<void(const FuzzInput&)>;
using InterestingCallback = std::function<void(const FuzzInput&)>;
using ExecuteCallback = std::function<bool(const std::vector<uint8_t>&)>;

class Fuzzer {
public:
    explicit Fuzzer(uint32_t seed = 0);
    ~Fuzzer();
    
    void setMaxInputSize(size_t size);
    size_t getMaxInputSize() const;
    
    void setMinInputSize(size_t size);
    size_t getMinInputSize() const;
    
    void setMutationRate(double rate);
    double getMutationRate() const;
    
    void addSeedInput(const std::vector<uint8_t>& input);
    void addSeedInputFromFile(const std::string& filepath);
    
    void setExecuteCallback(ExecuteCallback callback);
    void setCrashCallback(CrashCallback callback);
    void setHangCallback(HangCallback callback);
    void setInterestingCallback(InterestingCallback callback);
    
    void setCorpusMaxSize(size_t max_size);
    
    size_t run(size_t iterations);
    
    FuzzInput generateInput();
    FuzzInput mutateInput(const FuzzInput& input);
    
    const FuzzerStats& getStats() const;
    void resetStats();
    
    void saveCorpus(const std::string& directory);
    void loadCorpus(const std::string& directory);
    
    std::vector<uint8_t> generateRandomData(size_t size);
    
    void setVerbose(bool verbose);
    bool isVerbose() const;

private:
    struct MutationStrategy {
        MutationType type;
        double weight;
        std::function<void(std::vector<uint8_t>&, std::mt19937&)> apply;
    };
    
    void initializeMutationStrategies();
    void selectAndApplyMutation(std::vector<uint8_t>& data);
    bool shouldAddToCorpus(const FuzzInput& input);
    void updateStats(const FuzzInput& input, double exec_time_ms);
    uint32_t generateSeed();
    
    std::mt19937 rng_;
    std::uniform_int_distribution<uint32_t> byte_dist_;
    std::uniform_real_distribution<double> rate_dist_;
    std::uniform_real_distribution<double> weight_dist_;
    
    std::vector<FuzzInput> corpus_;
    std::vector<MutationStrategy> strategies_;
    
    size_t max_input_size_;
    size_t min_input_size_;
    double mutation_rate_;
    size_t corpus_max_size_;
    bool verbose_;
    
    FuzzerStats stats_;
    
    ExecuteCallback execute_callback_;
    CrashCallback crash_callback_;
    HangCallback hang_callback_;
    InterestingCallback interesting_callback_;
    
    std::unordered_map<std::string, bool> seen_hashes_;
};

} // namespace fuzz

#endif // FUZZER_H
