#include "fuzzer.h"
#include "protocol.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <csignal>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

namespace {

volatile bool g_running = true;
volatile size_t g_total_executions = 0;
volatile bool g_crash_detected = false;

void signalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = false;
    }
}

void printBanner() {
    std::cout << "========================================" << std::endl;
    std::cout << "     Binary Fuzz Engine v1.0.0" << std::endl;
    std::cout << "     Low-level Protocol Fuzzer" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
}

void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -m, --mode <mode>       Fuzzing mode: 'raw', 'protocol', 'network'" << std::endl;
    std::cout << "  -i, --iterations <n>    Number of fuzzing iterations" << std::endl;
    std::cout << "  -s, --seed <n>          Random seed (0 for random)" << std::endl;
    std::cout << "  -d, --directory <dir>   Corpus directory" << std::endl;
    std::cout << "  -o, --output <dir>      Output directory for crashes" << std::endl;
    std::cout << "  -f, --file <file>       Seed input file" << std::endl;
    std::cout << "  -p, --port <port>       Target port (network mode)" << std::endl;
    std::cout << "  -h, --host <host>       Target host (network mode)" << std::endl;
    std::cout << "  -t, --timeout <ms>      Execution timeout in milliseconds" << std::endl;
    std::cout << "  -v, --verbose           Enable verbose output" << std::endl;
    std::cout << "  --help                  Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program << " -m raw -i 10000 -v" << std::endl;
    std::cout << "  " << program << " -m protocol -f seed.bin -i 50000" << std::endl;
    std::cout << "  " << program << " -m network -p 8080 -h localhost -i 1000" << std::endl;
    std::cout << std::endl;
}

struct Config {
    std::string mode = "raw";
    size_t iterations = 10000;
    uint32_t seed = 0;
    std::string corpus_dir;
    std::string output_dir = "./crashes";
    std::string seed_file;
    std::string target_host = "127.0.0.1";
    int target_port = 0;
    int timeout_ms = 1000;
    bool verbose = false;
    size_t max_input_size = 65536;
    size_t min_input_size = 1;
    double mutation_rate = 0.5;
};

bool parseArgs(int argc, char* argv[], Config& config) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            return false;
        } else if (arg == "-m" || arg == "--mode") {
            if (i + 1 < argc) {
                config.mode = argv[++i];
            }
        } else if (arg == "-i" || arg == "--iterations") {
            if (i + 1 < argc) {
                config.iterations = std::stoul(argv[++i]);
            }
        } else if (arg == "-s" || arg == "--seed") {
            if (i + 1 < argc) {
                config.seed = std::stoul(argv[++i]);
            }
        } else if (arg == "-d" || arg == "--directory") {
            if (i + 1 < argc) {
                config.corpus_dir = argv[++i];
            }
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                config.output_dir = argv[++i];
            }
        } else if (arg == "-f" || arg == "--file") {
            if (i + 1 < argc) {
                config.seed_file = argv[++i];
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                config.target_port = std::stoi(argv[++i]);
            }
        } else if (arg == "-h" || arg == "--host") {
            if (i + 1 < argc) {
                config.target_host = argv[++i];
            }
        } else if (arg == "-t" || arg == "--timeout") {
            if (i + 1 < argc) {
                config.timeout_ms = std::stoi(argv[++i]);
            }
        } else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        }
    }
    return true;
}

void setupProtocolSpec(fuzz::ProtocolSpec& spec) {
    spec.name = "GenericBinaryProtocol";
    spec.description = "Generic binary protocol with header and payload";
    spec.min_packet_size = 8;
    spec.max_packet_size = 4096;
    spec.has_checksum = true;
    spec.checksum_offset = 2;
    spec.checksum_size = 2;
    
    fuzz::FieldSpec magic;
    magic.name = "magic";
    magic.type = fuzz::FieldType::FIXED;
    magic.offset = 0;
    magic.size = 2;
    magic.fixed_value = {0xBE, 0xEF};
    magic.required = true;
    spec.fields.push_back(magic);
    
    fuzz::FieldSpec checksum;
    checksum.name = "checksum";
    checksum.type = fuzz::FieldType::CRC16;
    checksum.offset = 2;
    checksum.size = 2;
    checksum.required = true;
    spec.fields.push_back(checksum);
    
    fuzz::FieldSpec length;
    length.name = "length";
    length.type = fuzz::FieldType::FIXED;
    length.offset = 4;
    length.size = 2;
    length.byte_order = fuzz::ByteOrder::BYTE_ORDER_LITTLE;
    length.required = true;
    spec.fields.push_back(length);
    
    fuzz::FieldSpec flags;
    flags.name = "flags";
    flags.type = fuzz::FieldType::FIXED;
    flags.offset = 6;
    flags.size = 1;
    flags.required = true;
    spec.fields.push_back(flags);
    
    fuzz::FieldSpec payload;
    payload.name = "payload";
    payload.type = fuzz::FieldType::VARIABLE;
    payload.offset = 7;
    payload.min_size = 0;
    payload.max_size = 4089;
    payload.required = false;
    spec.fields.push_back(payload);
}

bool executeWithTimeout(const std::vector<uint8_t>& data, int timeout_ms) {
    (void)data;
    (void)timeout_ms;
    
    g_total_executions++;
    
    if (g_crash_detected) {
        return false;
    }
    
    return true;
}

bool sendToTarget(const std::vector<uint8_t>& data, const std::string& host, int port) {
    if (port <= 0) {
        return false;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    
    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        close(sock);
        return false;
    }
    
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    bool success = false;
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        ssize_t sent = send(sock, data.data(), data.size(), 0);
        success = (sent == static_cast<ssize_t>(data.size()));
    }
    
    close(sock);
    g_total_executions++;
    return success;
}

void saveCrash(const std::string& output_dir, const fuzz::FuzzInput& input, 
               const std::string& crash_type) {
    DIR* dir = opendir(output_dir.c_str());
    if (!dir) {
        mkdir(output_dir.c_str(), 0755);
    } else {
        closedir(dir);
    }
    
    std::string filename = output_dir + "/" + crash_type + "_" + 
                          std::to_string(time(nullptr)) + "_" +
                          std::to_string(g_total_executions);
    
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(input.data.data()), input.data.size());
        file.close();
    }
}

void runRawFuzzMode(const Config& config) {
    fuzz::Fuzzer fuzzer(config.seed);

    fuzzer.setMaxInputSize(config.max_input_size);
    fuzzer.setMinInputSize(config.min_input_size);
    fuzzer.setMutationRate(config.mutation_rate);
    fuzzer.setVerbose(config.verbose);
    fuzzer.setExecutionTimeout(config.timeout_ms);

    if (!config.seed_file.empty()) {
        fuzzer.addSeedInputFromFile(config.seed_file);
    }

    if (!config.corpus_dir.empty()) {
        fuzzer.loadCorpus(config.corpus_dir);
    }

    fuzzer.setExecuteCallback([&config](const std::vector<uint8_t>& data) -> bool {
        return executeWithTimeout(data, config.timeout_ms);
    });
    
    fuzzer.setCrashCallback([&config](const fuzz::FuzzInput& input, const std::string& id) {
        g_crash_detected = true;
        saveCrash(config.output_dir, input, "crash_" + id);
        std::cout << "\n[CRASH] Found crash! Saved to " << config.output_dir << std::endl;
    });
    
    fuzzer.setInterestingCallback([&config](const fuzz::FuzzInput& input) {
        saveCrash(config.output_dir, input, "interesting");
    });
    
    std::cout << "Starting raw fuzz mode..." << std::endl;
    std::cout << "Iterations: " << config.iterations << std::endl;
    std::cout << "Seed: " << config.seed << std::endl;
    std::cout << "Max input size: " << config.max_input_size << std::endl;
    std::cout << std::endl;
    
    size_t completed = fuzzer.run(config.iterations);
    
    if (!config.output_dir.empty()) {
        fuzzer.saveCorpus(config.output_dir + "/corpus");
    }
    
    const fuzz::FuzzerStats& stats = fuzzer.getStats();
    std::cout << std::endl;
    std::cout << "Fuzzing complete!" << std::endl;
    std::cout << "  Total iterations: " << completed << std::endl;
    std::cout << "  Total mutations: " << stats.total_mutations << std::endl;
    std::cout << "  Crashes found: " << stats.crashes_found << std::endl;
    std::cout << "  Hangs found: " << stats.hangs_found << std::endl;
    std::cout << "  Interesting inputs: " << stats.interesting_inputs << std::endl;
    std::cout << "  Unique paths: " << stats.unique_paths << std::endl;
    std::cout << "  Final corpus size: " << stats.current_corpus_size << std::endl;
    std::cout << "  Exec/s: " << stats.execs_per_second << std::endl;
}

void runProtocolFuzzMode(const Config& config) {
    fuzz::ProtocolSpec spec;
    setupProtocolSpec(spec);
    
    fuzz::ProtocolFuzzer proto_fuzzer(spec);
    fuzz::Fuzzer fuzzer(config.seed);
    
    fuzzer.setMaxInputSize(spec.max_packet_size);
    fuzzer.setMinInputSize(spec.min_packet_size);
    fuzzer.setVerbose(config.verbose);
    
    if (!config.seed_file.empty()) {
        proto_fuzzer.addSeedPacketFromFile(config.seed_file);
        std::cout << "Loaded seed packets from: " << config.seed_file << std::endl;
    }
    
    for (size_t i = 0; i < proto_fuzzer.getSeedPacketCount(); ++i) {
        std::cout << "Seed packet " << i << " loaded" << std::endl;
    }
    
    fuzzer.setExecuteCallback([&config](const std::vector<uint8_t>& data) -> bool {
        return executeWithTimeout(data, config.timeout_ms);
    });

    fuzzer.setCrashCallback([&config](const fuzz::FuzzInput& input, const std::string& id) {
        g_crash_detected = true;
        saveCrash(config.output_dir, input, "proto_crash_" + id);
        std::cout << "\n[CRASH] Protocol crash found!" << std::endl;
    });

    std::cout << "Starting protocol fuzz mode..." << std::endl;
    std::cout << "Protocol: " << spec.name << std::endl;
    std::cout << "Fields: " << spec.fields.size() << std::endl;
    std::cout << "Iterations: " << config.iterations << std::endl;
    std::cout << std::endl;

    size_t completed = 0;
    while (g_running && completed < config.iterations) {
        std::vector<uint8_t> input = proto_fuzzer.generateFuzzInput();

        if (executeWithTimeout(input, config.timeout_ms)) {
            fuzz::FuzzInput fuzz_input(input);
            fuzzer.mutateInput(fuzz_input);
        }

        completed++;

        if (config.verbose && completed % 5000 == 0) {
            std::cout << "Progress: " << completed << "/" << config.iterations << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "Protocol fuzzing complete!" << std::endl;
    std::cout << "  Total iterations: " << completed << std::endl;
    std::cout << "  Crashes found: " << (g_crash_detected ? 1 : 0) << std::endl;
}

void runNetworkFuzzMode(const Config& config) {
    if (config.target_port <= 0) {
        std::cerr << "Error: Network mode requires a target port (-p)" << std::endl;
        return;
    }
    
    fuzz::Fuzzer fuzzer(config.seed);
    
    fuzzer.setMaxInputSize(4096);
    fuzzer.setMinInputSize(1);
    fuzzer.setVerbose(config.verbose);
    
    if (!config.seed_file.empty()) {
        fuzzer.addSeedInputFromFile(config.seed_file);
    }
    
    fuzzer.setExecuteCallback([&config](const std::vector<uint8_t>& data) -> bool {
        return sendToTarget(data, config.target_host, config.target_port);
    });
    
    fuzzer.setCrashCallback([&config](const fuzz::FuzzInput& input, const std::string& id) {
        g_crash_detected = true;
        saveCrash(config.output_dir, input, "net_crash_" + id);
        std::cout << "\n[CRASH] Network crash found!" << std::endl;
    });
    
    std::cout << "Starting network fuzz mode..." << std::endl;
    std::cout << "Target: " << config.target_host << ":" << config.target_port << std::endl;
    std::cout << "Iterations: " << config.iterations << std::endl;
    std::cout << std::endl;
    
    size_t completed = fuzzer.run(config.iterations);
    
    const fuzz::FuzzerStats& stats = fuzzer.getStats();
    std::cout << std::endl;
    std::cout << "Network fuzzing complete!" << std::endl;
    std::cout << "  Total iterations: " << completed << std::endl;
    std::cout << "  Successful sends: " << stats.execs_per_second << std::endl;
    std::cout << "  Crashes found: " << stats.crashes_found << std::endl;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    printBanner();
    
    Config config;
    if (!parseArgs(argc, argv, config)) {
        printUsage(argv[0]);
        return 0;
    }
    
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    if (config.verbose) {
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Mode: " << config.mode << std::endl;
        std::cout << "  Iterations: " << config.iterations << std::endl;
        std::cout << "  Seed: " << config.seed << std::endl;
        std::cout << "  Output dir: " << config.output_dir << std::endl;
        std::cout << "  Verbose: " << (config.verbose ? "yes" : "no") << std::endl;
        std::cout << std::endl;
    }
    
    if (config.mode == "raw") {
        runRawFuzzMode(config);
    } else if (config.mode == "protocol") {
        runProtocolFuzzMode(config);
    } else if (config.mode == "network") {
        runNetworkFuzzMode(config);
    } else {
        std::cerr << "Error: Unknown mode '" << config.mode << "'" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    return 0;
}
