#include "kmipcore/serialization_buffer.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace kmipcore;

void testWriteByte() {
    SerializationBuffer buf(100);

    buf.writeByte(0xAB);
    buf.writeByte(0xCD);
    buf.writeByte(0xEF);

    assert(buf.size() == 3);
    assert(buf.data()[0] == 0xAB);
    assert(buf.data()[1] == 0xCD);
    assert(buf.data()[2] == 0xEF);

    std::cout << "✓ testWriteByte passed" << std::endl;
}

void testWriteBytes() {
    SerializationBuffer buf(100);

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    buf.writeBytes(data, 5);

    assert(buf.size() == 5);
    assert(std::memcmp(buf.data(), data, 5) == 0);

    std::cout << "✓ testWriteBytes passed" << std::endl;
}

void testWritePadded() {
    SerializationBuffer buf(100);

    // Write 3 bytes (should add 5 bytes of padding to reach 8)
    uint8_t data[] = {0x01, 0x02, 0x03};
    buf.writePadded(data, 3);

    assert(buf.size() == 8);
    assert(buf.data()[0] == 0x01);
    assert(buf.data()[1] == 0x02);
    assert(buf.data()[2] == 0x03);
    assert(buf.data()[3] == 0x00);  // Padding
    assert(buf.data()[4] == 0x00);  // Padding
    assert(buf.data()[5] == 0x00);  // Padding
    assert(buf.data()[6] == 0x00);  // Padding
    assert(buf.data()[7] == 0x00);  // Padding

    std::cout << "✓ testWritePadded passed" << std::endl;
}

void testMultiplePaddedWrites() {
    SerializationBuffer buf(100);

    // 3 bytes -> 8 bytes padded
    uint8_t data1[] = {0x01, 0x02, 0x03};
    buf.writePadded(data1, 3);

    // 2 bytes -> 8 bytes padded
    uint8_t data2[] = {0x04, 0x05};
    buf.writePadded(data2, 2);

    assert(buf.size() == 16);  // 8 + 8

    // First block (8 bytes)
    assert(buf.data()[0] == 0x01);
    assert(buf.data()[1] == 0x02);
    assert(buf.data()[2] == 0x03);
    assert(buf.data()[7] == 0x00);

    // Second block (8 bytes)
    assert(buf.data()[8] == 0x04);
    assert(buf.data()[9] == 0x05);
    assert(buf.data()[15] == 0x00);

    std::cout << "✓ testMultiplePaddedWrites passed" << std::endl;
}

void testAutoExpansion() {
    SerializationBuffer buf(10);  // Small initial size

    assert(buf.capacity() >= 10);

    // Write more than initial capacity
    for (int i = 0; i < 50; ++i) {
        buf.writeByte(static_cast<uint8_t>(i & 0xFF));
    }

    assert(buf.size() == 50);
    assert(buf.capacity() >= 50);

    // Verify data is correct
    for (int i = 0; i < 50; ++i) {
        assert(buf.data()[i] == (i & 0xFF));
    }

    std::cout << "✓ testAutoExpansion passed" << std::endl;
}

void testReset() {
    SerializationBuffer buf(100);

    buf.writeByte(0xFF);
    buf.writeByte(0xFF);
    buf.writeByte(0xFF);

    assert(buf.size() == 3);

    buf.reset();

    assert(buf.size() == 0);
    assert(buf.capacity() >= 100);  // Capacity preserved

    // Can reuse the buffer
    buf.writeByte(0xAA);
    assert(buf.size() == 1);
    assert(buf.data()[0] == 0xAA);

    std::cout << "✓ testReset passed" << std::endl;
}

void testRelease() {
    SerializationBuffer buf(100);

    uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    buf.writeBytes(data, 5);

    assert(buf.size() == 5);

    std::vector<uint8_t> result = buf.release();

    assert(result.size() == 5);
    assert(result[0] == 0x11);
    assert(result[1] == 0x22);
    assert(result[2] == 0x33);
    assert(result[3] == 0x44);
    assert(result[4] == 0x55);

    // Original buffer should be reset
    assert(buf.size() == 0);

    std::cout << "✓ testRelease passed" << std::endl;
}

void testRemaining() {
    SerializationBuffer buf(100);

    assert(buf.remaining() == 100);

    buf.writeByte(0xFF);
    assert(buf.remaining() == 99);

    for (int i = 0; i < 99; ++i) {
        buf.writeByte(0xFF);
    }

    assert(buf.size() == 100);
    assert(buf.remaining() == 0);

    // Should auto-expand
    buf.writeByte(0xFF);
    assert(buf.size() == 101);
    assert(buf.remaining() > 0);

    std::cout << "✓ testRemaining passed" << std::endl;
}

void testLargeMessage() {
    SerializationBuffer buf(8192);  // Default KMIP buffer size

    // Simulate writing a large message
    for (int i = 0; i < 1000; ++i) {
        uint8_t data[] = {
            static_cast<uint8_t>((i >> 24) & 0xFF),
            static_cast<uint8_t>((i >> 16) & 0xFF),
            static_cast<uint8_t>((i >> 8) & 0xFF),
            static_cast<uint8_t>(i & 0xFF),
        };
        buf.writePadded(data, 4);
    }

    // Each write is 4 bytes + 4 bytes padding = 8 bytes
    // 1000 writes = 8000 bytes
    assert(buf.size() == 8000);

    std::cout << "✓ testLargeMessage passed" << std::endl;
}

void testConsecutiveAllocation() {
    // Test 10 sequential buffers
    for (int iteration = 0; iteration < 10; ++iteration) {
        SerializationBuffer buf(512);

        for (int i = 0; i < 64; ++i) {
            uint8_t byte = static_cast<uint8_t>((iteration * 64 + i) & 0xFF);
            buf.writeByte(byte);
        }

        assert(buf.size() == 64);

        auto result = buf.release();
        assert(result.size() == 64);
    }

    std::cout << "✓ testConsecutiveAllocation passed" << std::endl;
}

int main() {
    std::cout << "Running SerializationBuffer tests...\n" << std::endl;

    try {
        testWriteByte();
        testWriteBytes();
        testWritePadded();
        testMultiplePaddedWrites();
        testAutoExpansion();
        testReset();
        testRelease();
        testRemaining();
        testLargeMessage();
        testConsecutiveAllocation();

        std::cout << "\n✅ All SerializationBuffer tests passed!" << std::endl;
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "❌ Test failed: " << e.what() << std::endl;
        return 1;
    }
}

