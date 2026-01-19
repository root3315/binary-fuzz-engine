#include "protocol.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <chrono>

namespace fuzz {

namespace {

const std::vector<uint8_t> INTERESTING_BYTES = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x7F, 0x80, 0xFF, 0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF,
    0x0A, 0x0D, 0x20, 0x7E, 0x5C, 0x2F, 0x3A, 0x2C, 0x3B
};

const std::vector<int32_t> INTERESTING_INTS = {
    0, 1, -1, 127, -128, 255, 256, -256,
    32767, -32768, 65535, 65536, -65536,
    2147483647, -2147483648
};

uint16_t crc16_update(uint16_t crc, uint8_t data) {
    crc ^= data;
    for (int i = 0; i < 8; ++i) {
        if (crc & 0x0001) {
            crc = (crc >> 1) ^ 0xA001;
        } else {
            crc >>= 1;
        }
    }
    return crc;
}

uint32_t crc32_update(uint32_t crc, uint8_t data) {
    crc ^= data;
    for (int i = 0; i < 8; ++i) {
        if (crc & 1) {
            crc = (crc >> 1) ^ 0xEDB88320;
        } else {
            crc >>= 1;
        }
    }
    return crc;
}

} // anonymous namespace

uint16_t computeCRC16(const uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc = crc16_update(crc, data[i]);
    }
    return crc;
}

uint32_t computeCRC32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc = crc32_update(crc, data[i]);
    }
    return crc ^ 0xFFFFFFFF;
}

ProtocolMutator::ProtocolMutator(const ProtocolSpec& spec)
    : byte_dist_(0, 255)
    , rate_dist_(0.0, 1.0)
    , strategy_dist_(0.0, 1.0)
    , spec_(spec)
    , field_mutation_rate_(0.7)
    , structural_mutation_rate_(0.3)
    , current_strategy_(MutationStrategy::FIELD_VALUE)
{
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    rng_.seed(static_cast<uint32_t>(duration.count() & 0xFFFFFFFF));
}

ProtocolMutator::~ProtocolMutator() = default;

void ProtocolMutator::setRandomSeed(uint32_t seed) {
    rng_.seed(seed);
}

void ProtocolMutator::setFieldMutationRate(double rate) {
    field_mutation_rate_ = std::max(0.0, std::min(1.0, rate));
}

void ProtocolMutator::setStructuralMutationRate(double rate) {
    structural_mutation_rate_ = std::max(0.0, std::min(1.0, rate));
}

size_t ProtocolMutator::getFieldCount() const {
    return spec_.fields.size();
}

const FieldSpec& ProtocolMutator::getFieldSpec(size_t index) const {
    return spec_.fields.at(index);
}

void ProtocolMutator::selectMutationStrategy() {
    double r = strategy_dist_(rng_);
    double threshold = field_mutation_rate_ / (field_mutation_rate_ + structural_mutation_rate_);
    
    if (r < threshold) {
        std::uniform_int_distribution<int> field_strat(0, 4);
        int strat = field_strat(rng_);
        switch (strat) {
            case 0: current_strategy_ = MutationStrategy::FIELD_VALUE; break;
            case 1: current_strategy_ = MutationStrategy::FIELD_SIZE; break;
            case 2: current_strategy_ = MutationStrategy::FIELD_DELETE; break;
            case 3: current_strategy_ = MutationStrategy::FIELD_DUPLICATE; break;
            case 4: current_strategy_ = MutationStrategy::FIELD_REORDER; break;
        }
    } else {
        std::uniform_int_distribution<int> struct_strat(0, 3);
        int strat = struct_strat(rng_);
        switch (strat) {
            case 0: current_strategy_ = MutationStrategy::STRUCTURAL_INSERT; break;
            case 1: current_strategy_ = MutationStrategy::STRUCTURAL_DELETE; break;
            case 2: current_strategy_ = MutationStrategy::CHECKSUM_CORRUPT; break;
            case 3: current_strategy_ = MutationStrategy::BOUNDARY_TEST; break;
        }
    }
}

std::vector<uint8_t> ProtocolMutator::generateFieldValue(const FieldSpec& spec) {
    std::vector<uint8_t> result;
    
    switch (spec.type) {
        case FieldType::FIXED:
            if (!spec.fixed_value.empty()) {
                result = spec.fixed_value;
            } else {
                result.resize(spec.size);
                for (size_t i = 0; i < spec.size; ++i) {
                    result[i] = static_cast<uint8_t>(byte_dist_(rng_));
                }
            }
            break;
            
        case FieldType::VARIABLE: {
            std::uniform_int_distribution<size_t> size_dist(spec.min_size, spec.max_size);
            size_t size = size_dist(rng_);
            result.resize(size);
            for (size_t i = 0; i < size; ++i) {
                result[i] = static_cast<uint8_t>(byte_dist_(rng_));
            }
            break;
        }
            
        case FieldType::LENGTH_PREFIXED: {
            std::uniform_int_distribution<size_t> size_dist(spec.min_size, spec.max_size);
            size_t content_size = size_dist(rng_);
            
            if (spec.byte_order == ByteOrder::BYTE_ORDER_BIG) {
                result.push_back(static_cast<uint8_t>((content_size >> 8) & 0xFF));
                result.push_back(static_cast<uint8_t>(content_size & 0xFF));
            } else {
                result.push_back(static_cast<uint8_t>(content_size & 0xFF));
                result.push_back(static_cast<uint8_t>((content_size >> 8) & 0xFF));
            }
            
            for (size_t i = 0; i < content_size; ++i) {
                result.push_back(static_cast<uint8_t>(byte_dist_(rng_)));
            }
            break;
        }
            
        case FieldType::DELIMITER_TERMINATED: {
            std::uniform_int_distribution<size_t> size_dist(spec.min_size, spec.max_size - 1);
            size_t content_size = size_dist(rng_);
            for (size_t i = 0; i < content_size; ++i) {
                uint8_t b = static_cast<uint8_t>(byte_dist_(rng_));
                if (b == spec.delimiter) {
                    b = static_cast<uint8_t>((b + 1) % 256);
                }
                result.push_back(b);
            }
            result.push_back(spec.delimiter);
            break;
        }
            
        case FieldType::CHECKSUM:
        case FieldType::CRC16:
            result.resize(spec.size, 0);
            break;
            
        case FieldType::CRC32:
            result.resize(4, 0);
            break;
    }
    
    return result;
}

std::vector<uint8_t> ProtocolMutator::mutateFieldValue(const std::vector<uint8_t>& value, 
                                                        const FieldSpec& spec) {
    std::vector<uint8_t> result = value;
    
    if (result.empty()) {
        return generateFieldValue(spec);
    }
    
    std::uniform_int_distribution<int> mutation_type(0, 8);
    int mt = mutation_type(rng_);
    
    switch (mt) {
        case 0: {
            if (!result.empty()) {
                std::uniform_int_distribution<size_t> idx(0, result.size() - 1);
                result[idx(rng_)] = INTERESTING_BYTES[byte_dist_(rng_) % INTERESTING_BYTES.size()];
            }
            break;
        }
            
        case 1: {
            if (result.size() >= 2) {
                std::uniform_int_distribution<size_t> idx(0, result.size() - 2);
                size_t i = idx(rng_);
                std::swap(result[i], result[i + 1]);
            }
            break;
        }
            
        case 2: {
            std::uniform_int_distribution<int32_t> int_val(0, INTERESTING_INTS.size() - 1);
            int32_t interesting = INTERESTING_INTS[int_val(rng_)];
            
            if (result.size() >= 4) {
                if (spec.byte_order == ByteOrder::BYTE_ORDER_BIG) {
                    result[0] = (interesting >> 24) & 0xFF;
                    result[1] = (interesting >> 16) & 0xFF;
                    result[2] = (interesting >> 8) & 0xFF;
                    result[3] = interesting & 0xFF;
                } else {
                    result[0] = interesting & 0xFF;
                    result[1] = (interesting >> 8) & 0xFF;
                    result[2] = (interesting >> 16) & 0xFF;
                    result[3] = (interesting >> 24) & 0xFF;
                }
            } else if (result.size() >= 2) {
                if (spec.byte_order == ByteOrder::BYTE_ORDER_BIG) {
                    result[0] = (interesting >> 8) & 0xFF;
                    result[1] = interesting & 0xFF;
                } else {
                    result[0] = interesting & 0xFF;
                    result[1] = (interesting >> 8) & 0xFF;
                }
            }
            break;
        }
            
        case 3: {
            std::uniform_int_distribution<int> delta(-50, 50);
            if (!result.empty()) {
                size_t idx = byte_dist_(rng_) % result.size();
                result[idx] = static_cast<uint8_t>(result[idx] + delta(rng_));
            }
            break;
        }
            
        case 4: {
            if (result.size() >= 4 && result.size() <= spec.max_size - 4) {
                size_t insert_pos = byte_dist_(rng_) % result.size();
                for (int i = 0; i < 4; ++i) {
                    result.insert(result.begin() + insert_pos, static_cast<uint8_t>(byte_dist_(rng_)));
                }
            }
            break;
        }
            
        case 5: {
            if (result.size() > spec.min_size + 4) {
                size_t del_pos = byte_dist_(rng_) % (result.size() - 4);
                result.erase(result.begin() + del_pos, result.begin() + del_pos + 4);
            }
            break;
        }
            
        case 6: {
            if (result.size() >= 2) {
                std::uniform_int_distribution<size_t> start(0, result.size() - 2);
                std::uniform_int_distribution<size_t> len(2, std::min<size_t>(8, result.size()));
                size_t s = start(rng_);
                size_t l = std::min(len(rng_), result.size() - s);
                std::reverse(result.begin() + s, result.begin() + s + l);
            }
            break;
        }
            
        case 7: {
            std::fill(result.begin(), result.end(), 0x00);
            break;
        }
            
        case 8: {
            std::fill(result.begin(), result.end(), 0xFF);
            break;
        }
    }
    
    if (result.size() > spec.max_size) {
        result.resize(spec.max_size);
    } else if (result.size() < spec.min_size) {
        result.resize(spec.min_size);
    }
    
    return result;
}

std::vector<uint8_t> ProtocolMutator::generateValidPacket() {
    std::vector<uint8_t> packet;
    
    for (const auto& field : spec_.fields) {
        std::vector<uint8_t> field_data = generateFieldValue(field);
        packet.insert(packet.end(), field_data.begin(), field_data.end());
    }
    
    if (spec_.has_checksum) {
        updateChecksum(packet);
    }
    
    if (packet.size() < spec_.min_packet_size) {
        packet.resize(spec_.min_packet_size, 0x00);
    }
    
    if (packet.size() > spec_.max_packet_size) {
        packet.resize(spec_.max_packet_size);
    }
    
    return packet;
}

std::vector<uint8_t> ProtocolMutator::mutatePacket(const std::vector<uint8_t>& packet) {
    if (packet.empty()) {
        return generateValidPacket();
    }
    
    std::vector<uint8_t> result = packet;
    selectMutationStrategy();
    
    switch (current_strategy_) {
        case MutationStrategy::FIELD_VALUE:
        case MutationStrategy::FIELD_SIZE:
        case MutationStrategy::FIELD_DELETE:
        case MutationStrategy::FIELD_DUPLICATE:
        case MutationStrategy::FIELD_REORDER: {
            if (!spec_.fields.empty()) {
                std::uniform_int_distribution<size_t> field_idx(0, spec_.fields.size() - 1);
                size_t idx = field_idx(rng_);
                result = mutateField(packet, idx);
            }
            break;
        }
            
        case MutationStrategy::STRUCTURAL_INSERT: {
            std::uniform_int_distribution<size_t> pos(0, result.size());
            std::uniform_int_distribution<size_t> len(1, 16);
            size_t p = pos(rng_);
            size_t l = len(rng_);
            for (size_t i = 0; i < l; ++i) {
                result.insert(result.begin() + p, static_cast<uint8_t>(byte_dist_(rng_)));
            }
            break;
        }
            
        case MutationStrategy::STRUCTURAL_DELETE: {
            if (result.size() > spec_.min_packet_size + 4) {
                std::uniform_int_distribution<size_t> pos(0, result.size() - 4);
                std::uniform_int_distribution<size_t> len(1, 4);
                size_t p = pos(rng_);
                size_t l = std::min(len(rng_), result.size() - p);
                result.erase(result.begin() + p, result.begin() + p + l);
            }
            break;
        }
            
        case MutationStrategy::CHECKSUM_CORRUPT: {
            if (spec_.has_checksum && result.size() >= spec_.checksum_offset + spec_.checksum_size) {
                std::uniform_int_distribution<size_t> pos(spec_.checksum_offset, 
                    spec_.checksum_offset + spec_.checksum_size - 1);
                result[pos(rng_)] ^= 0xFF;
            }
            break;
        }
            
        case MutationStrategy::BOUNDARY_TEST: {
            std::uniform_int_distribution<int> boundary(0, 4);
            switch (boundary(rng_)) {
                case 0:
                    result.resize(spec_.min_packet_size);
                    break;
                case 1:
                    result.resize(spec_.max_packet_size);
                    break;
                case 2:
                    result.resize(1);
                    break;
                case 3:
                    result.resize(65535);
                    break;
                case 4:
                    result.clear();
                    break;
            }
            break;
        }
    }
    
    if (spec_.has_checksum) {
        updateChecksum(result);
    }
    
    return result;
}

std::vector<uint8_t> ProtocolMutator::mutateField(const std::vector<uint8_t>& packet, 
                                                   size_t field_index) {
    if (field_index >= spec_.fields.size()) {
        return packet;
    }
    
    std::vector<uint8_t> result = packet;
    const FieldSpec& field = spec_.fields[field_index];
    
    ParsedPacket parsed = parsePacket(packet);
    if (!parsed.valid || field_index >= parsed.fields.size()) {
        return mutatePacket(packet);
    }
    
    std::vector<uint8_t> mutated_value = mutateFieldValue(parsed.fields[field_index].value, field);
    
    std::vector<uint8_t> new_packet;
    for (size_t i = 0; i < parsed.fields.size(); ++i) {
        if (i == field_index) {
            new_packet.insert(new_packet.end(), mutated_value.begin(), mutated_value.end());
        } else {
            new_packet.insert(new_packet.end(), 
                              parsed.fields[i].value.begin(), 
                              parsed.fields[i].value.end());
        }
    }
    
    return new_packet;
}

ParsedPacket ProtocolMutator::parsePacket(const std::vector<uint8_t>& data) {
    ParsedPacket result;
    result.raw_data = data;
    
    size_t offset = 0;
    for (const auto& field_spec : spec_.fields) {
        ParsedField pf;
        pf.spec = field_spec;
        
        if (offset >= data.size() && field_spec.required) {
            pf.valid = false;
            pf.error_message = "Unexpected end of packet";
            result.valid = false;
            result.error_message = pf.error_message;
            result.fields.push_back(pf);
            continue;
        }
        
        switch (field_spec.type) {
            case FieldType::FIXED: {
                size_t end = std::min(offset + field_spec.size, data.size());
                pf.value.assign(data.begin() + offset, data.begin() + end);
                offset += field_spec.size;
                break;
            }
                
            case FieldType::VARIABLE: {
                size_t remaining = data.size() - offset;
                size_t to_read = std::min(remaining, field_spec.max_size);
                pf.value.assign(data.begin() + offset, data.begin() + offset + to_read);
                offset += to_read;
                break;
            }
                
            case FieldType::LENGTH_PREFIXED: {
                if (offset + 2 > data.size()) {
                    pf.valid = false;
                    pf.error_message = "Cannot read length prefix";
                    result.valid = false;
                } else {
                    uint16_t length;
                    if (field_spec.byte_order == ByteOrder::BYTE_ORDER_BIG) {
                        length = (data[offset] << 8) | data[offset + 1];
                    } else {
                        length = data[offset] | (data[offset + 1] << 8);
                    }
                    offset += 2;
                    size_t end = std::min(offset + length, data.size());
                    pf.value.assign(data.begin() + offset, data.begin() + end);
                    offset += length;
                }
                break;
            }
                
            case FieldType::DELIMITER_TERMINATED: {
                auto it = std::find(data.begin() + offset, data.end(), field_spec.delimiter);
                if (it != data.end()) {
                    pf.value.assign(data.begin() + offset, it);
                    offset = (it - data.begin()) + 1;
                } else {
                    pf.value.assign(data.begin() + offset, data.end());
                    offset = data.size();
                }
                break;
            }
                
            case FieldType::CHECKSUM:
            case FieldType::CRC16: {
                size_t end = std::min(offset + field_spec.size, data.size());
                pf.value.assign(data.begin() + offset, data.begin() + end);
                offset += field_spec.size;
                break;
            }
                
            case FieldType::CRC32: {
                size_t end = std::min(offset + 4, data.size());
                pf.value.assign(data.begin() + offset, data.begin() + end);
                offset += 4;
                break;
            }
        }
        
        result.fields.push_back(pf);
    }
    
    return result;
}

std::vector<uint8_t> ProtocolMutator::createPacketFromFields(
        const std::vector<std::vector<uint8_t>>& field_values) {
    std::vector<uint8_t> packet;
    
    for (const auto& value : field_values) {
        packet.insert(packet.end(), value.begin(), value.end());
    }
    
    if (spec_.has_checksum) {
        updateChecksum(packet);
    }
    
    return packet;
}

void ProtocolMutator::updateChecksum(std::vector<uint8_t>& packet) {
    if (!spec_.has_checksum) return;
    if (packet.size() < spec_.checksum_offset + spec_.checksum_size) return;
    
    std::vector<uint8_t> checksum_data;
    if (spec_.checksum_offset > 0) {
        checksum_data.assign(packet.begin(), packet.begin() + spec_.checksum_offset);
    }
    size_t data_end = spec_.checksum_offset + spec_.checksum_size;
    if (data_end < packet.size()) {
        checksum_data.insert(checksum_data.end(), 
                            packet.begin() + data_end, 
                            packet.end());
    }
    
    std::vector<uint8_t> checksum;
    if (spec_.checksum_size == 2) {
        uint16_t crc = calculateCRC16(checksum_data.data(), checksum_data.size());
        checksum.push_back(crc & 0xFF);
        checksum.push_back((crc >> 8) & 0xFF);
    } else if (spec_.checksum_size == 4) {
        uint32_t crc = calculateCRC32(checksum_data.data(), checksum_data.size());
        checksum.push_back(crc & 0xFF);
        checksum.push_back((crc >> 8) & 0xFF);
        checksum.push_back((crc >> 16) & 0xFF);
        checksum.push_back((crc >> 24) & 0xFF);
    }
    
    if (checksum.size() == spec_.checksum_size) {
        std::copy(checksum.begin(), checksum.end(), 
                  packet.begin() + spec_.checksum_offset);
    }
}

bool ProtocolMutator::verifyChecksum(const std::vector<uint8_t>& packet) {
    if (!spec_.has_checksum) return true;
    if (packet.size() < spec_.checksum_offset + spec_.checksum_size) return false;
    
    std::vector<uint8_t> checksum_data;
    if (spec_.checksum_offset > 0) {
        checksum_data.assign(packet.begin(), packet.begin() + spec_.checksum_offset);
    }
    size_t data_end = spec_.checksum_offset + spec_.checksum_size;
    if (data_end < packet.size()) {
        checksum_data.insert(checksum_data.end(), 
                            packet.begin() + data_end, 
                            packet.end());
    }
    
    if (spec_.checksum_size == 2) {
        uint16_t expected = calculateCRC16(checksum_data.data(), checksum_data.size());
        uint16_t actual = packet[spec_.checksum_offset] | 
                         (packet[spec_.checksum_offset + 1] << 8);
        return expected == actual;
    } else if (spec_.checksum_size == 4) {
        uint32_t expected = calculateCRC32(checksum_data.data(), checksum_data.size());
        uint32_t actual = packet[spec_.checksum_offset] | 
                         (packet[spec_.checksum_offset + 1] << 8) |
                         (packet[spec_.checksum_offset + 2] << 16) |
                         (packet[spec_.checksum_offset + 3] << 24);
        return expected == actual;
    }
    
    return true;
}

uint16_t ProtocolMutator::calculateCRC16(const uint8_t* data, size_t length) {
    return computeCRC16(data, length);
}

uint32_t ProtocolMutator::calculateCRC32(const uint8_t* data, size_t length) {
    return computeCRC32(data, length);
}

ProtocolFuzzer::ProtocolFuzzer(const ProtocolSpec& spec)
    : spec_(spec)
    , mutator_(spec)
    , seed_selector_(0, 0)
    , target_field_(0)
{
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    rng_.seed(static_cast<uint32_t>(duration.count() & 0xFFFFFFFF));
    
    field_fuzz_enabled_.resize(spec.fields.size(), true);
}

ProtocolFuzzer::~ProtocolFuzzer() = default;

void ProtocolFuzzer::addSeedPacket(const std::vector<uint8_t>& packet) {
    if (!packet.empty()) {
        seed_packets_.push_back(packet);
        seed_selector_ = std::uniform_int_distribution<size_t>(0, seed_packets_.size() - 1);
    }
}

void ProtocolFuzzer::addSeedPacketFromFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return;
    
    std::streamsize size = file.tellg();
    if (size <= 0) return;
    
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        addSeedPacket(buffer);
    }
}

std::vector<uint8_t> ProtocolFuzzer::generateFuzzInput() {
    std::uniform_real_distribution<double> rate_dist_(0.0, 1.0);
    if (seed_packets_.empty() || rate_dist_(rng_) < 0.3) {
        return mutator_.generateValidPacket();
    }
    
    const std::vector<uint8_t>& seed = seed_packets_[seed_selector_(rng_)];
    return mutator_.mutatePacket(seed);
}

void ProtocolFuzzer::setTargetField(size_t field_index) {
    if (field_index < field_fuzz_enabled_.size()) {
        target_field_ = field_index;
    }
}

void ProtocolFuzzer::setFuzzMode(size_t field_index, bool enabled) {
    if (field_index < field_fuzz_enabled_.size()) {
        field_fuzz_enabled_[field_index] = enabled;
    }
}

const ProtocolSpec& ProtocolFuzzer::getProtocolSpec() const {
    return spec_;
}

size_t ProtocolFuzzer::getSeedPacketCount() const {
    return seed_packets_.size();
}

} // namespace fuzz
