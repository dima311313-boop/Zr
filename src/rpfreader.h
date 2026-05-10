#pragma once
#include <cstdint>

constexpr uint32_t RPF7_MAGIC    = 0x52504637;
constexpr uint32_t RPF_DIR_MARKER = 0x7FFFFF00;

#pragma pack(push, 1)
struct RpfHeader {
    uint32_t magic;
    uint32_t entryCount;
    uint32_t namesLength;
    uint32_t encryptionType; // 4 байта! не uint8_t
};

struct RpfDirectoryEntry {
    uint32_t nameOffset;
    uint32_t marker;
    uint32_t entryIndex;
    uint32_t entryCount;
};

struct RpfFileEntry {
    uint32_t nameOffset;
    uint32_t dataOffset;
    uint32_t dataSize;
    uint32_t flags;
};

struct RpfEntry {
    uint32_t a, b, c, d;
    bool isDirectory() const { return b == RPF_DIR_MARKER; }
};
#pragma pack(pop)

enum class RpfEncryption : uint32_t {
    None = 0x00,
    AES  = 0xFF,
    Open = 0xFE,
};
