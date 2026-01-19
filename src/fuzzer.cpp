#include "fuzzer.h"
#include "timeout_executor.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <sys/stat.h>
#include <dirent.h>

namespace fuzz {

namespace {

const std::vector<uint8_t> INTERESTING_8 = {
    0x00, 0x01, 0x7F, 0x80, 0xFF
};

const std::vector<uint8_t> INTERESTING_16_LE = {
    0x00, 0x00, 0x00, 0x01,
    0xFF, 0x7F, 0x00, 0x80,
    0xFF, 0xFF
};

const std::vector<uint8_t> INTERESTING_32_LE = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0xFF, 0xFF, 0xFF, 0x7F,
    0x00, 0x00, 0x00, 0x80,
    0xFF, 0xFF, 0xFF, 0xFF
};

uint64_t hashData(const std::vector<uint8_t>& data) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (uint8_t byte : data) {
        hash ^= byte;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

std::string hashToString(uint64_t hash) {
    std::ostringstream oss;
    oss << std::hex << hash;
    return oss.str();
}

void ensureDirectoryExists(const std::string& path) {
    mkdir(path.c_str(), 0755);
}

} // anonymous namespace

Fuzzer::Fuzzer(uint32_t seed)
    : byte_dist_(0, 255)
    , rate_dist_(0.0, 1.0)
    , weight_dist_(0.0, 1.0)
    , max_input_size_(65536)
    , min_input_size_(1)
    , mutation_rate_(0.5)
    , corpus_max_size_(1000)
    , verbose_(false)
    , execution_timeout_ms_(1000)
{
    if (seed == 0) {
        seed = generateSeed();
    }
    rng_.seed(seed);
    initializeMutationStrategies();
    executor_.setTimeout(execution_timeout_ms_);
}

Fuzzer::~Fuzzer() = default;

void Fuzzer::initializeMutationStrategies() {
    strategies_.clear();
    
    strategies_.push_back({MutationType::BIT_FLIP, 15.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.empty()) return;
            std::uniform_int_distribution<size_t> bit_pos(0, data.size() * 8 - 1);
            size_t pos = bit_pos(rng);
            data[pos / 8] ^= (1 << (pos % 8));
        }});
    
    strategies_.push_back({MutationType::BYTE_FLIP, 15.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.size() < 2) return;
            std::uniform_int_distribution<size_t> idx(0, data.size() - 2);
            size_t i = idx(rng);
            std::swap(data[i], data[i + 1]);
        }});
    
    strategies_.push_back({MutationType::BYTE_INSERT, 10.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.size() >= max_input_size_) return;
            std::uniform_int_distribution<size_t> idx(0, data.size());
            size_t pos = idx(rng);
            uint8_t val = static_cast<uint8_t>(byte_dist_(rng));
            data.insert(data.begin() + pos, val);
        }});
    
    strategies_.push_back({MutationType::BYTE_DELETE, 10.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.size() <= min_input_size_) return;
            std::uniform_int_distribution<size_t> idx(0, data.size() - 1);
            size_t pos = idx(rng);
            data.erase(data.begin() + pos);
        }});
    
    strategies_.push_back({MutationType::BYTE_RANDOM, 15.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.empty()) return;
            std::uniform_int_distribution<size_t> idx(0, data.size() - 1);
            size_t pos = idx(rng);
            data[pos] = static_cast<uint8_t>(byte_dist_(rng));
        }});
    
    strategies_.push_back({MutationType::BLOCK_SHUFFLE, 8.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.size() < 8) return;
            std::uniform_int_distribution<size_t> block_size(2, 8);
            std::uniform_int_distribution<size_t> start(0, data.size() - 4);
            size_t bs = block_size(rng);
            size_t s1 = start(rng);
            size_t s2 = start(rng);
            if (s1 + bs <= data.size() && s2 + bs <= data.size()) {
                std::vector<uint8_t> temp(data.begin() + s1, data.begin() + s1 + bs);
                std::copy(data.begin() + s2, data.begin() + s2 + bs, data.begin() + s1);
                std::copy(temp.begin(), temp.end(), data.begin() + s2);
            }
        }});
    
    strategies_.push_back({MutationType::ARITHMETIC_ADD, 8.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.empty()) return;
            std::uniform_int_distribution<size_t> idx(0, data.size() - 1);
            std::uniform_int_distribution<int> delta(-35, 35);
            size_t pos = idx(rng);
            data[pos] = static_cast<uint8_t>(data[pos] + delta(rng));
        }});
    
    strategies_.push_back({MutationType::ARITHMETIC_SUB, 8.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.empty()) return;
            std::uniform_int_distribution<size_t> idx(0, data.size() - 1);
            std::uniform_int_distribution<int> delta(-35, 35);
            size_t pos = idx(rng);
            data[pos] = static_cast<uint8_t>(data[pos] - delta(rng));
        }});
    
    strategies_.push_back({MutationType::INTERESTING_VALUE, 8.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.empty()) return;
            std::uniform_int_distribution<int> choice(0, 2);
            std::uniform_int_distribution<size_t> idx(0, data.size() - 1);
            size_t pos = idx(rng);
            int c = choice(rng);
            if (c == 0 && pos < data.size()) {
                data[pos] = INTERESTING_8[byte_dist_(rng) % INTERESTING_8.size()];
            } else if (c == 1 && pos + 1 < data.size()) {
                size_t iidx = (byte_dist_(rng) % (INTERESTING_16_LE.size() / 2)) * 2;
                data[pos] = INTERESTING_16_LE[iidx];
                data[pos + 1] = INTERESTING_16_LE[iidx + 1];
            } else if (pos + 3 < data.size()) {
                size_t iidx = (byte_dist_(rng) % (INTERESTING_32_LE.size() / 4)) * 4;
                std::memcpy(&data[pos], &INTERESTING_32_LE[iidx], 4);
            }
        }});
    
    strategies_.push_back({MutationType::OVERWRITE_BLOCK, 5.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.size() < 4) return;
            std::uniform_int_distribution<size_t> block_size(2, 16);
            std::uniform_int_distribution<size_t> src(0, data.size() - 1);
            std::uniform_int_distribution<size_t> dst(0, data.size() - 1);
            size_t bs = std::min(block_size(rng), data.size());
            size_t s = src(rng);
            size_t d = dst(rng);
            if (s + bs > data.size()) s = data.size() - bs;
            if (d + bs > data.size()) d = data.size() - bs;
            std::copy(data.begin() + s, data.begin() + s + bs, data.begin() + d);
        }});
    
    strategies_.push_back({MutationType::DUPLICATE_BLOCK, 5.0,
        [this](std::vector<uint8_t>& data, std::mt19937& rng) {
            if (data.size() < 2 || data.size() >= max_input_size_ / 2) return;
            std::uniform_int_distribution<size_t> block_size(2, 16);
            std::uniform_int_distribution<size_t> src(0, data.size() - 2);
            size_t bs = std::min(block_size(rng), data.size());
            size_t s = src(rng);
            if (s + bs > data.size()) s = data.size() - bs;
            data.insert(data.begin() + s, data.begin() + s, data.begin() + s + bs);
        }});
}

uint32_t Fuzzer::generateSeed() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return static_cast<uint32_t>(duration.count() & 0xFFFFFFFF);
}

void Fuzzer::setMaxInputSize(size_t size) {
    max_input_size_ = size;
}

size_t Fuzzer::getMaxInputSize() const {
    return max_input_size_;
}

void Fuzzer::setMinInputSize(size_t size) {
    min_input_size_ = size;
}

size_t Fuzzer::getMinInputSize() const {
    return min_input_size_;
}

void Fuzzer::setMutationRate(double rate) {
    mutation_rate_ = std::max(0.0, std::min(1.0, rate));
}

double Fuzzer::getMutationRate() const {
    return mutation_rate_;
}

void Fuzzer::addSeedInput(const std::vector<uint8_t>& input) {
    if (input.empty() || input.size() > max_input_size_) return;
    FuzzInput fi(input);
    fi.seed = hashData(input);
    fi.generation = 0;
    corpus_.push_back(fi);
    stats_.current_corpus_size = corpus_.size();
}

void Fuzzer::addSeedInputFromFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        if (verbose_) {
            std::cerr << "Failed to open seed file: " << filepath << std::endl;
        }
        return;
    }
    
    std::streamsize size = file.tellg();
    if (size <= 0 || static_cast<size_t>(size) > max_input_size_) {
        if (verbose_) {
            std::cerr << "Invalid seed file size: " << filepath << std::endl;
        }
        return;
    }
    
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        addSeedInput(buffer);
        if (verbose_) {
            std::cout << "Loaded seed from " << filepath << " (" << size << " bytes)" << std::endl;
        }
    }
}

void Fuzzer::setExecuteCallback(ExecuteCallback callback) {
    execute_callback_ = std::move(callback);
}

void Fuzzer::setCrashCallback(CrashCallback callback) {
    crash_callback_ = std::move(callback);
}

void Fuzzer::setHangCallback(HangCallback callback) {
    hang_callback_ = std::move(callback);
}

void Fuzzer::setInterestingCallback(InterestingCallback callback) {
    interesting_callback_ = std::move(callback);
}

void Fuzzer::setCorpusMaxSize(size_t max_size) {
    corpus_max_size_ = max_size;
}

void Fuzzer::selectAndApplyMutation(std::vector<uint8_t>& data) {
    double total_weight = 0.0;
    for (const auto& strategy : strategies_) {
        total_weight += strategy.weight;
    }
    
    double r = weight_dist_(rng_) * total_weight;
    double cumulative = 0.0;
    
    for (const auto& strategy : strategies_) {
        cumulative += strategy.weight;
        if (r <= cumulative) {
            strategy.apply(data, rng_);
            break;
        }
    }
}

FuzzInput Fuzzer::generateInput() {
    FuzzInput result;
    
    if (corpus_.empty()) {
        std::uniform_int_distribution<size_t> size_dist(min_input_size_, max_input_size_);
        size_t size = size_dist(rng_);
        result.data = generateRandomData(size);
    } else {
        std::uniform_int_distribution<size_t> corpus_idx(0, corpus_.size() - 1);
        const FuzzInput& base = corpus_[corpus_idx(rng_)];
        result.data = base.data;
        result.generation = base.generation + 1;
    }
    
    return result;
}

FuzzInput Fuzzer::mutateInput(const FuzzInput& input) {
    FuzzInput result = input;
    result.data = input.data;
    
    std::uniform_int_distribution<int> num_mutations(1, 4);
    int mutations = num_mutations(rng_);
    
    for (int i = 0; i < mutations; ++i) {
        if (rate_dist_(rng_) < mutation_rate_) {
            selectAndApplyMutation(result.data);
        }
    }
    
    if (result.data.size() > max_input_size_) {
        result.data.resize(max_input_size_);
    } else if (result.data.size() < min_input_size_) {
        std::uniform_int_distribution<size_t> size_dist(min_input_size_, max_input_size_);
        result.data.resize(size_dist(rng_));
    }
    
    stats_.total_mutations++;
    return result;
}

std::vector<uint8_t> Fuzzer::generateRandomData(size_t size) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(byte_dist_(rng_));
    }
    return data;
}

bool Fuzzer::shouldAddToCorpus(const FuzzInput& input) {
    if (input.caused_crash || input.caused_hang) {
        return false;
    }
    
    uint64_t hash = hashData(input.data);
    std::string hash_str = hashToString(hash);
    
    if (seen_hashes_.find(hash_str) != seen_hashes_.end()) {
        return false;
    }
    
    if (input.is_interesting) {
        return true;
    }
    
    std::uniform_real_distribution<double> chance(0.0, 1.0);
    double add_chance = 1.0 / (1.0 + stats_.unique_paths * 0.01);
    return chance(rng_) < add_chance;
}

void Fuzzer::updateStats(const FuzzInput& input, double exec_time_ms) {
    if (input.caused_crash) {
        stats_.crashes_found++;
    }
    if (input.caused_hang) {
        stats_.hangs_found++;
    }
    if (input.is_interesting) {
        stats_.interesting_inputs++;
    }
    
    stats_.unique_paths++;
    stats_.avg_exec_time_ms = (stats_.avg_exec_time_ms * (stats_.unique_paths - 1) + exec_time_ms) 
                               / stats_.unique_paths;
    stats_.current_corpus_size = corpus_.size();
    stats_.max_corpus_size = std::max(stats_.max_corpus_size, corpus_.size());
}

size_t Fuzzer::run(size_t iterations) {
    if (verbose_) {
        std::cout << "Starting fuzzing run: " << iterations << " iterations" << std::endl;
        std::cout << "Initial corpus size: " << corpus_.size() << std::endl;
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    size_t completed = 0;

    for (size_t i = 0; i < iterations; ++i) {
        FuzzInput input = generateInput();
        FuzzInput mutated = mutateInput(input);

        auto exec_start = std::chrono::high_resolution_clock::now();

        bool executed = false;
        bool caused_timeout = false;
        
        if (execute_callback_) {
            ExecutionOutput output = executor_.executeWithFunction(
                mutated.data,
                [this](const std::vector<uint8_t>& data) -> int {
                    return execute_callback_(data) ? 0 : 1;
                }
            );
            
            executed = (output.result == ExecutionResult::SUCCESS);
            caused_timeout = (output.result == ExecutionResult::TIMEOUT);
            
            if (caused_timeout) {
                mutated.caused_hang = true;
            }
        }

        auto exec_end = std::chrono::high_resolution_clock::now();
        double exec_time_ms = std::chrono::duration<double, std::milli>(exec_end - exec_start).count();

        if (executed || caused_timeout) {
            updateStats(mutated, exec_time_ms);

            if (mutated.caused_crash && crash_callback_) {
                crash_callback_(mutated, "crash_" + std::to_string(stats_.crashes_found));
            }
            if (mutated.caused_hang && hang_callback_) {
                hang_callback_(mutated);
            }
            if (mutated.is_interesting && interesting_callback_) {
                interesting_callback_(mutated);
            }

            if (shouldAddToCorpus(mutated) && corpus_.size() < corpus_max_size_) {
                uint64_t hash = hashData(mutated.data);
                seen_hashes_[hashToString(hash)] = true;
                corpus_.push_back(mutated);
            }
        }

        completed++;

        if (verbose_ && completed % 10000 == 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::high_resolution_clock::now() - start_time).count();
            uint64_t eps = elapsed > 0 ? completed / elapsed : completed;
            std::cout << "Progress: " << completed << "/" << iterations
                      << " | Corpus: " << corpus_.size()
                      << " | Crashes: " << stats_.crashes_found
                      << " | Exec/s: " << eps << std::endl;
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
    stats_.execs_per_second = elapsed > 0 ? completed / elapsed : completed;

    if (verbose_) {
        std::cout << "Fuzzing complete. Total: " << completed << " iterations" << std::endl;
    }

    return completed;
}

const FuzzerStats& Fuzzer::getStats() const {
    return stats_;
}

void Fuzzer::resetStats() {
    stats_ = FuzzerStats();
    stats_.current_corpus_size = corpus_.size();
}

void Fuzzer::saveCorpus(const std::string& directory) {
    ensureDirectoryExists(directory);
    
    for (size_t i = 0; i < corpus_.size(); ++i) {
        std::string filename = directory + "/input_" + std::to_string(i);
        std::ofstream file(filename, std::ios::binary);
        if (file.is_open()) {
            file.write(reinterpret_cast<const char*>(corpus_[i].data.data()), 
                       corpus_[i].data.size());
        }
    }
    
    if (verbose_) {
        std::cout << "Saved " << corpus_.size() << " corpus entries to " << directory << std::endl;
    }
}

void Fuzzer::loadCorpus(const std::string& directory) {
    DIR* dir = opendir(directory.c_str());
    if (!dir) {
        if (verbose_) {
            std::cerr << "Cannot open corpus directory: " << directory << std::endl;
        }
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.find("input_") == 0) {
            std::string filepath = directory + "/" + name;
            addSeedInputFromFile(filepath);
        }
    }
    
    closedir(dir);
    
    if (verbose_) {
        std::cout << "Loaded " << corpus_.size() << " corpus entries from " << directory << std::endl;
    }
}

void Fuzzer::setVerbose(bool verbose) {
    verbose_ = verbose;
}

bool Fuzzer::isVerbose() const {
    return verbose_;
}

void Fuzzer::setExecutionTimeout(int timeout_ms) {
    execution_timeout_ms_ = timeout_ms;
    executor_.setTimeout(timeout_ms);
}

int Fuzzer::getExecutionTimeout() const {
    return execution_timeout_ms_;
}

} // namespace fuzz
