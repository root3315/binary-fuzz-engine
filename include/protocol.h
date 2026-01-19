#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <random>

namespace fuzz {

enum class FieldType {
    FIXED,
    VARIABLE,
    LENGTH_PREFIXED,
    DELIMITER_TERMINATED,
    CHECKSUM,
    CRC16,
    CRC32
};

enum class ByteOrder {
    BYTE_ORDER_LITTLE,
    BYTE_ORDER_BIG
};

struct FieldSpec {
    std::string name;
    FieldType type;
    size_t offset;
    size_t size;
    size_t min_size;
    size_t max_size;
    ByteOrder byte_order;
    uint8_t delimiter;
    bool required;
    std::vector<uint8_t> fixed_value;
    
    FieldSpec()
        : type(FieldType::FIXED)
        , offset(0)
        , size(0)
        , min_size(0)
        , max_size(0)
        , byte_order(ByteOrder::BYTE_ORDER_LITTLE)
        , delimiter(0)
        , required(true) {}
};

struct ProtocolSpec {
    std::string name;
    std::string description;
    std::vector<FieldSpec> fields;
    size_t min_packet_size;
    size_t max_packet_size;
    bool has_checksum;
    size_t checksum_offset;
    size_t checksum_size;
    
    ProtocolSpec()
        : min_packet_size(0)
        , max_packet_size(65535)
        , has_checksum(false)
        , checksum_offset(0)
        , checksum_size(0) {}
};

struct ParsedField {
    FieldSpec spec;
    std::vector<uint8_t> value;
    bool valid;
    std::string error_message;
    
    ParsedField() : valid(true) {}
};

struct ParsedPacket {
    std::vector<ParsedField> fields;
    bool valid;
    std::string error_message;
    std::vector<uint8_t> raw_data;
    
    ParsedPacket() : valid(true) {}
};

class ProtocolMutator {
public:
    explicit ProtocolMutator(const ProtocolSpec& spec);
    ~ProtocolMutator();
    
    void setRandomSeed(uint32_t seed);
    
    std::vector<uint8_t> generateValidPacket();
    std::vector<uint8_t> mutatePacket(const std::vector<uint8_t>& packet);
    std::vector<uint8_t> mutateField(const std::vector<uint8_t>& packet, size_t field_index);
    
    ParsedPacket parsePacket(const std::vector<uint8_t>& data);
    
    void setFieldMutationRate(double rate);
    void setStructuralMutationRate(double rate);
    
    size_t getFieldCount() const;
    const FieldSpec& getFieldSpec(size_t index) const;
    
    std::vector<uint8_t> createPacketFromFields(const std::vector<std::vector<uint8_t>>& field_values);
    
    void updateChecksum(std::vector<uint8_t>& packet);
    bool verifyChecksum(const std::vector<uint8_t>& packet);
    
    uint16_t calculateCRC16(const uint8_t* data, size_t length);
    uint32_t calculateCRC32(const uint8_t* data, size_t length);

private:
    enum class MutationStrategy {
        FIELD_VALUE,
        FIELD_SIZE,
        FIELD_DELETE,
        FIELD_DUPLICATE,
        FIELD_REORDER,
        STRUCTURAL_INSERT,
        STRUCTURAL_DELETE,
        CHECKSUM_CORRUPT,
        BOUNDARY_TEST
    };
    
    std::vector<uint8_t> generateFieldValue(const FieldSpec& spec);
    std::vector<uint8_t> mutateFieldValue(const std::vector<uint8_t>& value, const FieldSpec& spec);
    void applyStructuralMutation(std::vector<uint8_t>& packet);
    void selectMutationStrategy();
    
    std::mt19937 rng_;
    std::uniform_int_distribution<uint32_t> byte_dist_;
    std::uniform_real_distribution<double> rate_dist_;
    std::uniform_real_distribution<double> strategy_dist_;
    
    ProtocolSpec spec_;
    double field_mutation_rate_;
    double structural_mutation_rate_;
    MutationStrategy current_strategy_;
    
    static const uint16_t CRC16_POLY = 0x8005;
    static const uint32_t CRC32_POLY = 0xEDB88320;
};

class ProtocolFuzzer {
public:
    explicit ProtocolFuzzer(const ProtocolSpec& spec);
    ~ProtocolFuzzer();
    
    void addSeedPacket(const std::vector<uint8_t>& packet);
    void addSeedPacketFromFile(const std::string& filepath);
    
    std::vector<uint8_t> generateFuzzInput();
    
    void setTargetField(size_t field_index);
    void setFuzzMode(size_t field_index, bool enabled);
    
    const ProtocolSpec& getProtocolSpec() const;
    
    size_t getSeedPacketCount() const;

private:
    ProtocolSpec spec_;
    ProtocolMutator mutator_;
    std::vector<std::vector<uint8_t>> seed_packets_;
    std::mt19937 rng_;
    std::uniform_int_distribution<size_t> seed_selector_;
    size_t target_field_;
    std::vector<bool> field_fuzz_enabled_;
};

uint16_t computeCRC16(const uint8_t* data, size_t length);
uint32_t computeCRC32(const uint8_t* data, size_t length);

} // namespace fuzz

#endif // PROTOCOL_H
