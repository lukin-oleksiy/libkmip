#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kmipcore {

/**
 * SerializationBuffer provides efficient buffering for KMIP TTLV serialization.
 *
 * Instead of creating many small std::vector allocations during recursive
 * Element serialization, all data is written to a single pre-allocated buffer.
 * This significantly reduces heap fragmentation and improves performance.
 *
 * Key features:
 * - Single pre-allocated buffer (default 8KB)
 * - Auto-expansion if message exceeds capacity
 * - TTLV-aware padding (8-byte alignment)
 * - RAII-based automatic cleanup
 * - Non-copyable, movable for transfer of ownership
 */
class SerializationBuffer {
public:
    // ==================== CONSTANTS ====================

    /// KMIP TTLV requires all values to be padded to a multiple of 8 bytes
    static constexpr size_t TTLV_ALIGNMENT = 8;

    /// Default initial buffer capacity (covers the vast majority of KMIP messages)
    static constexpr size_t DEFAULT_CAPACITY = 8192;

    /// Minimum capacity used as the starting point when the buffer is empty
    static constexpr size_t MIN_CAPACITY = 1024;

    /// Hard upper limit on buffer growth to catch runaway allocations
    static constexpr size_t MAX_CAPACITY = 100 * 1024 * 1024;  // 100 MB

    // ==================== CONSTRUCTION ====================

    /**
     * Construct a SerializationBuffer with specified capacity.
     * @param initial_capacity Initial buffer size (default: DEFAULT_CAPACITY)
     */
    explicit SerializationBuffer(size_t initial_capacity = DEFAULT_CAPACITY);

    // Non-copyable (unique ownership of buffer)
    SerializationBuffer(const SerializationBuffer&) = delete;
    SerializationBuffer& operator=(const SerializationBuffer&) = delete;

    // Movable (transfer buffer ownership)
    SerializationBuffer(SerializationBuffer&&) = default;
    SerializationBuffer& operator=(SerializationBuffer&&) = default;

    /**
     * Destructor - cleans up buffer automatically (RAII)
     */
    ~SerializationBuffer() = default;

    // ==================== WRITE OPERATIONS ====================

    /**
     * Write a single byte to the buffer.
     * @param value Byte value to write
     */
    void writeByte(uint8_t value);

    /**
     * Write raw bytes (unpadded) to the buffer.
     * @param data Pointer to data
     * @param length Number of bytes to write
     */
    void writeBytes(const uint8_t* data, size_t length);
    void writeBytes(const void* data, size_t length) {
        writeBytes(static_cast<const uint8_t*>(data), length);
    }

    /**
     * Write raw bytes with KMIP padding (8-byte aligned).
     * Adds zero-fill padding to align to 8-byte boundary.
     * @param data Pointer to data
     * @param length Number of bytes to write
     */
    void writePadded(const uint8_t* data, size_t length);
    void writePadded(const void* data, size_t length) {
        writePadded(static_cast<const uint8_t*>(data), length);
    }

    // ==================== QUERY OPERATIONS ====================

    /**
     * Get current write position / serialized data size.
     * @return Number of bytes of valid data in buffer
     */
    [[nodiscard]] size_t size() const { return current_offset_; }

    /**
     * Get total allocated capacity.
     * @return Total capacity in bytes
     */
    [[nodiscard]] size_t capacity() const { return buffer_.capacity(); }

    /**
     * Get remaining space before reallocation needed.
     * @return Number of free bytes
     */
    [[nodiscard]] size_t remaining() const {
        return current_offset_ < buffer_.capacity()
            ? buffer_.capacity() - current_offset_
            : 0;
    }

    // ==================== UTILITY OPERATIONS ====================

    /**
     * Reset buffer to empty state (reuse for next message).
     * Keeps capacity for reuse, only clears write position.
     */
    void reset() { current_offset_ = 0; }

    /**
     * Ensure sufficient space is available for the specified bytes.
     * Auto-expands if necessary.
     * @param required_bytes Number of bytes needed
     */
    void ensureSpace(size_t required_bytes);

    // ==================== ACCESS OPERATIONS ====================

    /**
     * Get const pointer to buffer data.
     * @return Pointer to serialized data (only first size() bytes are valid)
     */
    [[nodiscard]] const uint8_t* data() const { return buffer_.data(); }

    /**
     * Get mutable pointer to buffer data (use with caution).
     * @return Pointer to buffer
     */
    uint8_t* mutableData() { return buffer_.data(); }

    /**
     * Get const reference to underlying vector.
     * @return Reference to internal vector
     */
    [[nodiscard]] const std::vector<uint8_t>& getBuffer() const { return buffer_; }

    // ==================== TRANSFER OWNERSHIP ====================

    /**
     * Move buffer content to vector and destroy this buffer.
     * The returned vector contains only the serialized data (size() bytes).
     * This buffer is cleared and cannot be used afterward.
     * @return Vector containing serialized data
     */
    std::vector<uint8_t> release();

private:
    std::vector<uint8_t> buffer_;
    size_t current_offset_ = 0;

    /**
     * Internal helper to expand buffer capacity.
     * Uses exponential growth strategy.
     * @param required Minimum required capacity
     */
    void expandCapacity(size_t required);
};

}  // namespace kmipcore

