# Binary Fuzz Engine

A low-level binary protocol fuzzing engine written in C++ for discovering vulnerabilities in binary parsers, network protocols, and file format handlers.

## Features

- **Multiple Fuzzing Modes**: Raw binary, protocol-aware, and network fuzzing
- **Advanced Mutation Strategies**: 12 different mutation types including bit flips, arithmetic operations, and block manipulations
- **Protocol Definition System**: Define custom binary protocols with field specifications
- **Corpus Management**: Seed-based fuzzing with automatic corpus expansion
- **Checksum Support**: Built-in CRC16 and CRC32 calculation for protocol-aware fuzzing
- **Reproducible Results**: Seed-based random number generation for reproducible test cases
- **Callback System**: Extensible callbacks for crash detection, hang detection, and interesting input discovery

## Requirements

- CMake 3.10 or higher
- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- POSIX-compatible system (Linux, macOS)

## Installation

### Build from Source

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### Install

```bash
sudo make install
```

### Build with Tests

```bash
mkdir build
cd build
cmake -DBUILD_TESTS=ON ..
make -j$(nproc)
ctest
```

## Usage

### Basic Usage

```bash
# Raw binary fuzzing
./binary-fuzz-engine -m raw -i 10000 -v

# Protocol-aware fuzzing with seed file
./binary-fuzz-engine -m protocol -f seed.bin -i 50000

# Network fuzzing against a target
./binary-fuzz-engine -m network -p 8080 -h 127.0.0.1 -i 1000
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-m, --mode <mode>` | Fuzzing mode: `raw`, `protocol`, `network` |
| `-i, --iterations <n>` | Number of fuzzing iterations |
| `-s, --seed <n>` | Random seed (0 for random) |
| `-d, --directory <dir>` | Corpus directory |
| `-o, --output <dir>` | Output directory for crashes |
| `-f, --file <file>` | Seed input file |
| `-p, --port <port>` | Target port (network mode) |
| `-h, --host <host>` | Target host (network mode) |
| `-t, --timeout <ms>` | Execution timeout in milliseconds |
| `-v, --verbose` | Enable verbose output |

## How It Works

### Architecture

```
+------------------+     +-------------------+     +------------------+
|   Fuzzer Core    |---->|  Protocol Layer   |---->|  Target System   |
+------------------+     +-------------------+     +------------------+
        |                        |
        v                        v
+------------------+     +-------------------+
| Mutation Engine  |     |  Protocol Spec    |
+------------------+     +-------------------+
```

### Mutation Strategies

The engine implements 12 mutation strategies:

1. **BIT_FLIP**: Flip individual bits
2. **BYTE_FLIP**: Swap adjacent bytes
3. **BYTE_INSERT**: Insert random bytes
4. **BYTE_DELETE**: Remove bytes
5. **BYTE_RANDOM**: Replace with random values
6. **BLOCK_SHUFFLE**: Rearrange byte blocks
7. **ARITHMETIC_ADD**: Add small deltas
8. **ARITHMETIC_SUB**: Subtract small deltas
9. **INTERESTING_VALUE**: Insert boundary values (0, 1, 127, 255, etc.)
10. **OVERWRITE_BLOCK**: Copy blocks within the input
11. **DUPLICATE_BLOCK**: Duplicate sections of input
12. **BOUNDARY_TEST**: Test size boundaries

### Protocol Definition

Define custom protocols using the `ProtocolSpec` structure:

```cpp
fuzz::ProtocolSpec spec;
spec.name = "MyProtocol";
spec.min_packet_size = 8;
spec.max_packet_size = 4096;
spec.has_checksum = true;
spec.checksum_offset = 2;
spec.checksum_size = 2;

// Add fields
fuzz::FieldSpec magic;
magic.name = "magic";
magic.type = fuzz::FieldType::FIXED;
magic.size = 2;
magic.fixed_value = {0xBE, 0xEF};
spec.fields.push_back(magic);

fuzz::FieldSpec payload;
payload.name = "payload";
payload.type = fuzz::FieldType::VARIABLE;
payload.min_size = 0;
payload.max_size = 4089;
spec.fields.push_back(payload);
```

### Field Types

- `FIXED`: Fixed-size field
- `VARIABLE`: Variable-size field within bounds
- `LENGTH_PREFIXED`: Length-prefixed field
- `DELIMITER_TERMINATED`: Delimiter-terminated string
- `CHECKSUM`: Checksum field
- `CRC16`: 16-bit CRC field
- `CRC32`: 32-bit CRC field

## Library Usage

### Basic Fuzzer

```cpp
#include "fuzzer.h"

fuzz::Fuzzer fuzzer(42);  // Seed = 42
fuzzer.setMaxInputSize(1024);
fuzzer.setMinInputSize(16);

// Add seed inputs
fuzzer.addSeedInput({0xDE, 0xAD, 0xBE, 0xEF});

// Set execution callback
fuzzer.setExecuteCallback([](const std::vector<uint8_t>& data) -> bool {
    // Send data to target, return true if executed successfully
    return send_to_target(data);
});

// Set crash callback
fuzzer.setCrashCallback([](const fuzz::FuzzInput& input, const std::string& id) {
    save_crash(input.data, id);
});

// Run fuzzing
fuzzer.run(100000);
```

### Protocol Fuzzer

```cpp
#include "protocol.h"

fuzz::ProtocolSpec spec = define_protocol();
fuzz::ProtocolFuzzer pf(spec);

pf.addSeedPacket(seed_data);

for (size_t i = 0; i < iterations; ++i) {
    std::vector<uint8_t> input = pf.generateFuzzInput();
    send_to_target(input);
}
```

## Project Structure

```
binary-fuzz-engine/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── include/
│   ├── fuzzer.h           # Core fuzzer API
│   └── protocol.h         # Protocol definition API
├── src/
│   ├── fuzzer.cpp         # Fuzzer implementation
│   ├── protocol.cpp       # Protocol mutator implementation
│   └── main.cpp           # CLI entry point
└── tests/
    └── test_fuzzer.cpp    # Unit tests
```

## Examples

### Fuzzing a File Parser

```cpp
fuzz::Fuzzer fuzzer;
fuzzer.addSeedInputFromFile("valid_input.bin");

fuzzer.setExecuteCallback([](const std::vector<uint8_t>& data) -> bool {
    // Write to temp file and parse
    std::ofstream tmp("/tmp/fuzz_input", std::ios::binary);
    tmp.write(reinterpret_cast<const char*>(data.data()), data.size());
    tmp.close();
    
    // Call parser, catch crashes
    try {
        parse_file("/tmp/fuzz_input");
        return true;
    } catch (...) {
        return false;
    }
});

fuzzer.setCrashCallback([](const fuzz::FuzzInput& input, const std::string&) {
    std::ofstream crash("crash.bin", std::ios::binary);
    crash.write(reinterpret_cast<const char*>(input.data.data()), input.data.size());
});

fuzzer.run(1000000);
```

### Network Service Fuzzing

```bash
# Start target service
./vulnerable_server &

# Run fuzzer
./binary-fuzz-engine -m network -p 12345 -i 100000 -o crashes -v
```

## Output

The fuzzer saves interesting inputs and crashes to the output directory:

- `crash_<id>`: Inputs that caused crashes
- `interesting_<id>`: Inputs that triggered interesting behavior
- `corpus/`: Expanded corpus of unique inputs

## Statistics

During execution, the fuzzer tracks:

- Total mutations performed
- Crashes found
- Hangs detected
- Interesting inputs discovered
- Unique execution paths
- Corpus size
- Executions per second

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `ctest`
5. Submit a pull request
