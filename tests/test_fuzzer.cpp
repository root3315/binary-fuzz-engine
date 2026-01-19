#include "fuzzer.h"
#include "protocol.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <algorithm>

namespace {

int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) void name()
#define RUN_TEST(name) do { \
    tests_run++; \
    std::cout << "Running " << #name << "... "; \
    try { \
        name(); \
        tests_passed++; \
        std::cout << "PASSED" << std::endl; \
    } catch (const std::exception& e) { \
        tests_failed++; \
        std::cout << "FAILED: " << e.what() << std::endl; \
    } catch (...) { \
        tests_failed++; \
        std::cout << "FAILED: Unknown exception" << std::endl; \
    } \
} while(0)

#define ASSERT_TRUE(cond) do { if (!(cond)) throw std::runtime_error("Assertion failed: " #cond); } while(0)
#define ASSERT_FALSE(cond) do { if (cond) throw std::runtime_error("Assertion failed: !" #cond); } while(0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b); } while(0)
#define ASSERT_NE(a, b) do { if ((a) == (b)) throw std::runtime_error("Assertion failed: " #a " != " #b); } while(0)
#define ASSERT_GE(a, b) do { if ((a) < (b)) throw std::runtime_error("Assertion failed: " #a " >= " #b); } while(0)
#define ASSERT_LE(a, b) do { if ((a) > (b)) throw std::runtime_error("Assertion failed: " #a " <= " #b); } while(0)

TEST(test_fuzzer_creation) {
    fuzz::Fuzzer fuzzer(42);
    ASSERT_EQ(fuzzer.getMaxInputSize(), 65536);
    ASSERT_EQ(fuzzer.getMinInputSize(), 1);
    ASSERT_EQ(fuzzer.getMutationRate(), 0.5);
}

TEST(test_fuzzer_seed_reproducibility) {
    fuzz::Fuzzer fuzzer1(12345);
    fuzz::Fuzzer fuzzer2(12345);
    
    auto input1 = fuzzer1.generateInput();
    auto input2 = fuzzer2.generateInput();
    
    ASSERT_EQ(input1.data.size(), input2.data.size());
    ASSERT_TRUE(std::equal(input1.data.begin(), input1.data.end(), input2.data.begin()));
}

TEST(test_fuzzer_random_generation) {
    fuzz::Fuzzer fuzzer(0);
    fuzzer.setMaxInputSize(1024);
    fuzzer.setMinInputSize(16);
    
    auto input = fuzzer.generateInput();
    ASSERT_GE(input.data.size(), 16);
    ASSERT_LE(input.data.size(), 1024);
    ASSERT_FALSE(input.data.empty());
}

TEST(test_fuzzer_mutation) {
    fuzz::Fuzzer fuzzer(42);
    
    std::vector<uint8_t> original = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    fuzz::FuzzInput input(original);
    
    bool any_changed = false;
    for (int attempt = 0; attempt < 5 && !any_changed; ++attempt) {
        fuzz::Fuzzer fuzzer_local(42 + attempt);
        auto mutated = fuzzer_local.mutateInput(input);
        ASSERT_GE(mutated.data.size(), 1);
        
        bool changed = false;
        size_t check_len = std::min(original.size(), mutated.data.size());
        for (size_t i = 0; i < check_len; ++i) {
            if (original[i] != mutated.data[i]) {
                changed = true;
                break;
            }
        }
        if (!changed && mutated.data.size() != original.size()) {
            changed = true;
        }
        if (changed) any_changed = true;
    }
    ASSERT_TRUE(any_changed);
}

TEST(test_fuzzer_seed_input) {
    fuzz::Fuzzer fuzzer(42);
    
    std::vector<uint8_t> seed = {0xDE, 0xAD, 0xBE, 0xEF};
    fuzzer.addSeedInput(seed);
    
    const auto& stats = fuzzer.getStats();
    ASSERT_EQ(stats.current_corpus_size, 1);
}

TEST(test_fuzzer_stats) {
    fuzz::Fuzzer fuzzer(42);
    
    fuzzer.addSeedInput({0x01, 0x02, 0x03});
    
    int exec_count = 0;
    fuzzer.setExecuteCallback([&exec_count](const std::vector<uint8_t>&) -> bool {
        exec_count++;
        return true;
    });
    
    fuzzer.run(100);
    
    const auto& stats = fuzzer.getStats();
    ASSERT_GE(stats.total_mutations, 100);
    ASSERT_GE(exec_count, 100);
}

TEST(test_fuzzer_size_limits) {
    fuzz::Fuzzer fuzzer(42);
    fuzzer.setMaxInputSize(100);
    fuzzer.setMinInputSize(10);
    
    std::vector<uint8_t> large_seed(200, 0x41);
    fuzzer.addSeedInput(large_seed);
    
    const auto& stats = fuzzer.getStats();
    ASSERT_EQ(stats.current_corpus_size, 0);
    
    std::vector<uint8_t> valid_seed(50, 0x41);
    fuzzer.addSeedInput(valid_seed);
    ASSERT_EQ(fuzzer.getStats().current_corpus_size, 1);
}

TEST(test_protocol_spec_creation) {
    fuzz::ProtocolSpec spec;
    spec.name = "TestProtocol";
    spec.min_packet_size = 8;
    spec.max_packet_size = 1024;
    
    fuzz::FieldSpec field;
    field.name = "header";
    field.type = fuzz::FieldType::FIXED;
    field.size = 4;
    field.required = true;
    spec.fields.push_back(field);
    
    ASSERT_EQ(spec.fields.size(), 1);
    ASSERT_EQ(spec.fields[0].name, "header");
}

TEST(test_protocol_mutator_creation) {
    fuzz::ProtocolSpec spec;
    spec.name = "TestProtocol";
    spec.min_packet_size = 4;
    spec.max_packet_size = 256;
    
    fuzz::FieldSpec field;
    field.name = "data";
    field.type = fuzz::FieldType::VARIABLE;
    field.min_size = 1;
    field.max_size = 252;
    spec.fields.push_back(field);
    
    fuzz::ProtocolMutator mutator(spec);
    ASSERT_EQ(mutator.getFieldCount(), 1);
}

TEST(test_protocol_packet_generation) {
    fuzz::ProtocolSpec spec;
    spec.name = "TestProtocol";
    spec.min_packet_size = 4;
    spec.max_packet_size = 256;
    
    fuzz::FieldSpec field;
    field.name = "data";
    field.type = fuzz::FieldType::FIXED;
    field.size = 4;
    field.required = true;
    spec.fields.push_back(field);
    
    fuzz::ProtocolMutator mutator(spec);
    auto packet = mutator.generateValidPacket();
    
    ASSERT_GE(packet.size(), spec.min_packet_size);
    ASSERT_LE(packet.size(), spec.max_packet_size);
}

TEST(test_protocol_packet_mutation) {
    fuzz::ProtocolSpec spec;
    spec.name = "TestProtocol";
    spec.min_packet_size = 8;
    spec.max_packet_size = 256;
    
    fuzz::FieldSpec field;
    field.name = "data";
    field.type = fuzz::FieldType::FIXED;
    field.size = 16;
    field.required = true;
    spec.fields.push_back(field);
    
    fuzz::ProtocolMutator mutator(spec);
    
    std::vector<uint8_t> original(16, 0x00);
    
    bool got_valid = false;
    bool changed = false;
    std::vector<uint8_t> mutated;
    
    for (int attempt = 0; attempt < 10 && !got_valid; ++attempt) {
        fuzz::ProtocolMutator mutator_local(spec);
        mutator_local.setRandomSeed(42 + attempt);
        mutated = mutator_local.mutatePacket(original);
        
        if (!mutated.empty()) {
            got_valid = true;
            size_t check_len = std::min(original.size(), mutated.size());
            for (size_t i = 0; i < check_len; ++i) {
                if (original[i] != mutated[i]) {
                    changed = true;
                    break;
                }
            }
            if (!changed && mutated.size() != original.size()) {
                changed = true;
            }
        }
    }
    
    ASSERT_TRUE(got_valid);
    ASSERT_TRUE(changed);
}

TEST(test_protocol_crc16) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint16_t crc = fuzz::computeCRC16(data.data(), data.size());
    ASSERT_NE(crc, 0);
    
    uint16_t crc2 = fuzz::computeCRC16(data.data(), data.size());
    ASSERT_EQ(crc, crc2);
}

TEST(test_protocol_crc32) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint32_t crc = fuzz::computeCRC32(data.data(), data.size());
    ASSERT_NE(crc, 0);
    
    uint32_t crc2 = fuzz::computeCRC32(data.data(), data.size());
    ASSERT_EQ(crc, crc2);
}

TEST(test_protocol_fuzzer) {
    fuzz::ProtocolSpec spec;
    spec.name = "TestProtocol";
    spec.min_packet_size = 4;
    spec.max_packet_size = 256;
    
    fuzz::FieldSpec field;
    field.name = "data";
    field.type = fuzz::FieldType::VARIABLE;
    field.min_size = 1;
    field.max_size = 252;
    spec.fields.push_back(field);
    
    fuzz::ProtocolFuzzer pf(spec);
    
    std::vector<uint8_t> seed = {0xDE, 0xAD, 0xBE, 0xEF};
    pf.addSeedPacket(seed);
    
    ASSERT_EQ(pf.getSeedPacketCount(), 1);
    
    bool got_non_empty = false;
    for (int i = 0; i < 5 && !got_non_empty; ++i) {
        auto fuzz_input = pf.generateFuzzInput();
        if (!fuzz_input.empty()) {
            got_non_empty = true;
        }
    }
    ASSERT_TRUE(got_non_empty);
}

TEST(test_protocol_field_parsing) {
    fuzz::ProtocolSpec spec;
    spec.name = "TestProtocol";
    spec.min_packet_size = 4;
    spec.max_packet_size = 256;
    
    fuzz::FieldSpec field;
    field.name = "data";
    field.type = fuzz::FieldType::FIXED;
    field.size = 4;
    field.required = true;
    spec.fields.push_back(field);
    
    fuzz::ProtocolMutator mutator(spec);
    
    std::vector<uint8_t> packet = {0x01, 0x02, 0x03, 0x04};
    auto parsed = mutator.parsePacket(packet);
    
    ASSERT_TRUE(parsed.valid);
    ASSERT_EQ(parsed.fields.size(), 1);
    ASSERT_EQ(parsed.fields[0].value.size(), 4);
}

TEST(test_protocol_checksum_update) {
    fuzz::ProtocolSpec spec;
    spec.name = "TestProtocol";
    spec.min_packet_size = 8;
    spec.max_packet_size = 256;
    spec.has_checksum = true;
    spec.checksum_offset = 2;
    spec.checksum_size = 2;
    
    fuzz::FieldSpec magic;
    magic.name = "magic";
    magic.type = fuzz::FieldType::FIXED;
    magic.size = 2;
    magic.fixed_value = {0xBE, 0xEF};
    spec.fields.push_back(magic);
    
    fuzz::FieldSpec checksum;
    checksum.name = "checksum";
    checksum.type = fuzz::FieldType::CRC16;
    checksum.size = 2;
    spec.fields.push_back(checksum);
    
    fuzz::FieldSpec payload;
    payload.name = "payload";
    payload.type = fuzz::FieldType::VARIABLE;
    payload.min_size = 1;
    payload.max_size = 252;
    spec.fields.push_back(payload);
    
    fuzz::ProtocolMutator mutator(spec);
    auto packet = mutator.generateValidPacket();
    
    ASSERT_GE(packet.size(), 4);
    ASSERT_EQ(packet[0], 0xBE);
    ASSERT_EQ(packet[1], 0xEF);
}

TEST(test_fuzzer_callback_execution) {
    fuzz::Fuzzer fuzzer(42);
    
    bool execute_called = false;
    bool crash_called = false;
    bool interesting_called = false;
    
    fuzzer.setExecuteCallback([&execute_called](const std::vector<uint8_t>&) -> bool {
        execute_called = true;
        return true;
    });
    
    fuzzer.setCrashCallback([&crash_called](const fuzz::FuzzInput&, const std::string&) {
        crash_called = true;
    });
    
    fuzzer.setInterestingCallback([&interesting_called](const fuzz::FuzzInput&) {
        interesting_called = true;
    });
    
    fuzzer.run(10);
    
    ASSERT_TRUE(execute_called);
}

TEST(test_fuzzer_corpus_management) {
    fuzz::Fuzzer fuzzer(42);
    
    fuzzer.addSeedInput({0x01, 0x02, 0x03});
    fuzzer.addSeedInput({0x04, 0x05, 0x06, 0x07});
    fuzzer.addSeedInput({0x08, 0x09, 0x0A});
    
    ASSERT_EQ(fuzzer.getStats().current_corpus_size, 3);
    
    fuzzer.setCorpusMaxSize(2);
    fuzzer.run(50);
    
    const auto& stats = fuzzer.getStats();
    ASSERT_LE(stats.current_corpus_size, 10);
}

TEST(test_mutation_strategies_variety) {
    fuzz::Fuzzer fuzzer(42);
    fuzzer.setMutationRate(1.0);
    
    std::vector<uint8_t> original(64, 0x41);
    fuzz::FuzzInput input(original);
    
    std::vector<std::vector<uint8_t>> results;
    for (int i = 0; i < 20; ++i) {
        auto mutated = fuzzer.mutateInput(input);
        results.push_back(mutated.data);
    }
    
    int unique_count = 0;
    for (size_t i = 0; i < results.size(); ++i) {
        bool is_unique = true;
        for (size_t j = 0; j < i; ++j) {
            if (results[i] == results[j]) {
                is_unique = false;
                break;
            }
        }
        if (is_unique) unique_count++;
    }
    
    ASSERT_GE(unique_count, 5);
}

TEST(test_random_data_generation) {
    fuzz::Fuzzer fuzzer(42);
    
    auto data1 = fuzzer.generateRandomData(100);
    auto data2 = fuzzer.generateRandomData(100);
    
    ASSERT_EQ(data1.size(), 100);
    ASSERT_EQ(data2.size(), 100);
    
    bool different = false;
    for (size_t i = 0; i < data1.size(); ++i) {
        if (data1[i] != data2[i]) {
            different = true;
            break;
        }
    }
    ASSERT_TRUE(different);
}

} // anonymous namespace

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Binary Fuzz Engine Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    RUN_TEST(test_fuzzer_creation);
    RUN_TEST(test_fuzzer_seed_reproducibility);
    RUN_TEST(test_fuzzer_random_generation);
    RUN_TEST(test_fuzzer_mutation);
    RUN_TEST(test_fuzzer_seed_input);
    RUN_TEST(test_fuzzer_stats);
    RUN_TEST(test_fuzzer_size_limits);
    RUN_TEST(test_protocol_spec_creation);
    RUN_TEST(test_protocol_mutator_creation);
    RUN_TEST(test_protocol_packet_generation);
    RUN_TEST(test_protocol_packet_mutation);
    RUN_TEST(test_protocol_crc16);
    RUN_TEST(test_protocol_crc32);
    RUN_TEST(test_protocol_fuzzer);
    RUN_TEST(test_protocol_field_parsing);
    RUN_TEST(test_protocol_checksum_update);
    RUN_TEST(test_fuzzer_callback_execution);
    RUN_TEST(test_fuzzer_corpus_management);
    RUN_TEST(test_mutation_strategies_variety);
    RUN_TEST(test_random_data_generation);
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Total:  " << tests_run << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
