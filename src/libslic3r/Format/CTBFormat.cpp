#include "CTBFormat.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace Slic3r::Ctb {

namespace {

// The format "protection" uses a fixed, publicly known key. It is obfuscation of the
// file layout, not a security measure.
constexpr std::array<uint8_t, 32> aes_key{
    0xD0, 0x5B, 0x8E, 0x33, 0x71, 0xDE, 0x3D, 0x1A, 0xE5, 0x4F, 0x22, 0xDD, 0xDF, 0x5B, 0xFD, 0x94,
    0xAB, 0x5D, 0x64, 0x3A, 0x9D, 0x7E, 0xBF, 0xAF, 0x42, 0x03, 0xF3, 0x10, 0xD8, 0x52, 0x2A, 0xEA};
constexpr std::array<uint8_t, 16> aes_iv{
    0x0F, 0x01, 0x0A, 0x05, 0x05, 0x0B, 0x06, 0x07, 0x08, 0x06, 0x0A, 0x0C, 0x0C, 0x0D, 0x09, 0x0F};

// Stored in every file written by Chitubox, 320 bytes without the terminating zero.
constexpr char disclaimer_text[] =
    "Layout and record format for the ctb and cbddlp file types are the copyrighted programs or codes of "
    "CBD Technology (China) Inc..The Customer or User shall not in any manner reproduce, distribute, modify, "
    "decompile, disassemble, decrypt, extract, reverse engineer, lease, assign, or sublicense the said "
    "programs or codes.";
constexpr std::string_view disclaimer{disclaimer_text, sizeof(disclaimer_text) - 1};
static_assert(disclaimer.size() == 320);

// Values observed in files written by Chitubox, meaning unknown.
constexpr uint32_t projector_type   = 1;
constexpr uint8_t  anti_alias_flag  = 7;

/////////////////////////////// AES-256 (encryption only) ///////////////////////////////

constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

constexpr int aes_rounds = 14;
using RoundKeys = std::array<uint8_t, 16 * (aes_rounds + 1)>;

uint8_t xtime(uint8_t x) { return uint8_t((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

RoundKeys expand_key(const std::array<uint8_t, 32>& key)
{
    RoundKeys w{};
    std::copy(key.begin(), key.end(), w.begin());
    uint8_t rcon = 1;
    for (size_t i = 8; i < 4 * (aes_rounds + 1); ++i) {
        uint8_t t[4];
        std::memcpy(t, &w[4 * (i - 1)], 4);
        if (i % 8 == 0) {
            const uint8_t first = t[0];
            t[0] = uint8_t(sbox[t[1]] ^ rcon);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[first];
            rcon = xtime(rcon);
        } else if (i % 8 == 4) {
            for (uint8_t& b : t)
                b = sbox[b];
        }
        for (size_t k = 0; k < 4; ++k)
            w[4 * i + k] = uint8_t(w[4 * (i - 8) + k] ^ t[k]);
    }
    return w;
}

void encrypt_block(uint8_t* s, const RoundKeys& w)
{
    auto add_round_key = [&](int round) {
        for (size_t k = 0; k < 16; ++k)
            s[k] ^= w[16 * round + k];
    };

    add_round_key(0);
    for (int round = 1; round <= aes_rounds; ++round) {
        // SubBytes + ShiftRows, state is column major (s[row + 4 * column]).
        uint8_t t[16];
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r)
                t[r + 4 * c] = sbox[s[r + 4 * ((c + r) % 4)]];

        if (round != aes_rounds) {
            // MixColumns
            for (int c = 0; c < 4; ++c) {
                uint8_t* col = &t[4 * c];
                const uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                const uint8_t all = uint8_t(a0 ^ a1 ^ a2 ^ a3);
                col[0] = uint8_t(a0 ^ all ^ xtime(uint8_t(a0 ^ a1)));
                col[1] = uint8_t(a1 ^ all ^ xtime(uint8_t(a1 ^ a2)));
                col[2] = uint8_t(a2 ^ all ^ xtime(uint8_t(a2 ^ a3)));
                col[3] = uint8_t(a3 ^ all ^ xtime(uint8_t(a3 ^ a0)));
            }
        }
        std::memcpy(s, t, 16);
        add_round_key(round);
    }
}

/////////////////////////////// SHA-256 ///////////////////////////////

constexpr uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256_block(std::array<uint32_t, 8>& h, const uint8_t* block)
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = uint32_t(block[4 * i]) << 24 | uint32_t(block[4 * i + 1]) << 16 |
               uint32_t(block[4 * i + 2]) << 8 | uint32_t(block[4 * i + 3]);
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + sha256_k[i] + w[i];
        const uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

/////////////////////////////// CTB run length encoding ///////////////////////////////

// Longest run representable by the 4 byte run length.
constexpr size_t max_run_length = 0x0fffffff;

void add_run(std::vector<uint8_t>& out, uint8_t gray7, size_t length)
{
    while (length > max_run_length) {
        add_run(out, gray7, max_run_length);
        length -= max_run_length;
    }

    if (length == 0)
        return;

    if (length == 1) {
        out.push_back(gray7);
        return;
    }

    out.push_back(gray7 | 0x80);
    if (length <= 0x7f) {
        out.push_back(uint8_t(length));
    } else if (length <= 0x3fff) {
        out.push_back(uint8_t((length >> 8) | 0x80));
        out.push_back(uint8_t(length));
    } else if (length <= 0x1fffff) {
        out.push_back(uint8_t((length >> 16) | 0xc0));
        out.push_back(uint8_t(length >> 8));
        out.push_back(uint8_t(length));
    } else {
        out.push_back(uint8_t((length >> 24) | 0xe0));
        out.push_back(uint8_t(length >> 16));
        out.push_back(uint8_t(length >> 8));
        out.push_back(uint8_t(length));
    }
}


/////////////////////////////// Serialization helpers ///////////////////////////////

class ByteWriter
{
public:
    explicit ByteWriter(std::vector<uint8_t>& buf) : m_buf(buf) {}

    void u8(uint8_t v) { m_buf.push_back(v); }
    void u16(uint16_t v)
    {
        for (int i = 0; i < 2; ++i)
            m_buf.push_back(uint8_t(v >> (8 * i)));
    }
    void u32(uint32_t v)
    {
        for (int i = 0; i < 4; ++i)
            m_buf.push_back(uint8_t(v >> (8 * i)));
    }
    void u64(uint64_t v)
    {
        for (int i = 0; i < 8; ++i)
            m_buf.push_back(uint8_t(v >> (8 * i)));
    }
    void f32(float v)
    {
        uint32_t u;
        static_assert(sizeof(u) == sizeof(v));
        std::memcpy(&u, &v, sizeof(u));
        u32(u);
    }
    void bytes(const void* data, size_t size)
    {
        const auto* p = static_cast<const uint8_t*>(data);
        m_buf.insert(m_buf.end(), p, p + size);
    }

private:
    std::vector<uint8_t>& m_buf;
};

// Stream writer tracking the position and the CRC of everything written.
class FileWriter
{
public:
    explicit FileWriter(std::ostream& out) : m_out(out) {}

    void write(const std::vector<uint8_t>& data) { write(data.data(), data.size()); }
    void write(const uint8_t* data, size_t size)
    {
        m_out.write(reinterpret_cast<const char*>(data), std::streamsize(size));
        if (!m_out)
            throw std::runtime_error("CTB: failed to write the file");
        m_crc = crc32(data, size, m_crc);
        m_pos += size;
    }

    uint64_t position() const { return m_pos; }
    uint32_t crc() const { return m_crc; }

private:
    std::ostream& m_out;
    uint64_t m_pos{0};
    uint32_t m_crc{0};
};

uint32_t low32(uint64_t v) { return uint32_t(v & 0xffffffffu); }
uint32_t page(uint64_t v) { return uint32_t(v >> 32); }

struct SettingsOffsets
{
    uint32_t layer_pointers  = 0;
    uint32_t large_preview   = 0;
    uint32_t small_preview   = 0;
    uint32_t machine_name    = 0;
    uint32_t disclaimer      = 0;
    uint32_t resin_params    = 0;
    uint32_t max_layer_data  = 0;
};

std::vector<uint8_t> build_settings(const PrintParams& p, size_t layer_count, const SettingsOffsets& o)
{
    const uint32_t count = uint32_t(layer_count);
    std::vector<uint8_t> buf;
    buf.reserve(settings_size);
    ByteWriter w{buf};
    w.u64(0);                         // checksum value
    w.u32(o.layer_pointers);
    w.f32(p.display_width);
    w.f32(p.display_height);
    w.f32(p.machine_z);
    w.u32(0);
    w.u32(0);
    w.f32(count == 0 ? 0.f : layer_position_z(p, count - 1)); // total height
    w.f32(p.layer_height);
    w.f32(p.exposure_time);
    w.f32(p.bottom_exposure_time);
    w.f32(0.f);                       // light off delay
    w.u32(p.bottom_layers);
    w.u32(p.resolution_x);
    w.u32(p.resolution_y);
    w.u32(count);
    w.u32(o.large_preview);
    w.u32(o.small_preview);
    w.u32(uint32_t(estimate_print_time(p, layer_count) + 0.5f));
    w.u32(projector_type);
    w.f32(p.bottom_lift_height);
    w.f32(p.bottom_lift_speed);
    w.f32(p.lift_height);
    w.f32(p.lift_speed);
    w.f32(p.retract_speed);
    w.f32(p.material_ml);
    w.f32(p.material_g);
    w.f32(p.material_cost);
    w.f32(0.f);                       // bottom light off delay
    w.u32(1);
    w.u16(p.light_pwm);
    w.u16(p.bottom_light_pwm);
    w.u32(p.layer_xor_key);
    w.f32(0.f);                       // bottom lift height, second stage
    w.f32(0.f);                       // bottom lift speed, second stage
    w.f32(0.f);                       // lift height, second stage
    w.f32(0.f);                       // lift speed, second stage
    w.f32(0.f);                       // retract height, second stage
    w.f32(0.f);                       // retract speed, second stage
    w.f32(p.wait_after_lift);
    w.u32(o.machine_name);
    w.u32(uint32_t(p.machine_name.size()));
    w.u8(anti_alias_flag);
    w.u16(0);
    w.u8(0);                          // per layer settings not used
    w.u32(p.timestamp_minutes);
    w.u32(p.anti_alias_level);
    w.f32(p.wait_before_cure);
    w.f32(p.wait_after_lift);
    w.u32(p.transition_layers);
    w.f32(p.bottom_retract_speed);
    w.f32(0.f);                       // bottom retract speed, second stage
    w.u32(0);
    w.f32(4.f);
    w.u32(0);
    w.f32(4.f);
    w.f32(p.wait_before_cure);
    w.f32(p.wait_after_lift);
    w.f32(p.wait_after_cure);
    w.f32(0.f);                       // bottom retract height, second stage
    w.u32(0);
    w.u32(o.max_layer_data);
    w.u32(4);
    w.u32(count);                     // "last layer index", Chitubox writes the layer count
    for (int i = 0; i < 4; ++i)
        w.u32(0);
    w.u32(o.disclaimer);
    w.u32(uint32_t(disclaimer.size()));
    w.u32(1);
    w.u32(o.resin_params);
    w.u32(0);
    w.u32(0);
    if (buf.size() != settings_size)
        throw std::logic_error("CTB: wrong size of the settings block");
    return buf;
}

std::vector<uint8_t> serialize_layer_def(const PrintParams& p, size_t idx, uint64_t data_pos, uint32_t data_size)
{
    const bool bottom = idx < p.bottom_layers;
    std::vector<uint8_t> buf;
    buf.reserve(layer_def_size);
    ByteWriter w{buf};
    w.u32(uint32_t(layer_def_size));
    w.f32(layer_position_z(p, idx));
    w.f32(layer_exposure_time(p, idx));
    w.f32(0.f);                       // light off delay
    w.u32(low32(data_pos));
    w.u32(page(data_pos));
    w.u32(data_size);
    w.u32(0);
    w.u32(0);                         // encrypted part offset
    w.u32(0);                         // encrypted part length, no part of the layer is encrypted
    w.f32(bottom ? p.bottom_lift_height : p.lift_height);
    w.f32(bottom ? p.bottom_lift_speed : p.lift_speed);
    w.f32(0.f);                       // lift height, second stage
    w.f32(0.f);                       // lift speed, second stage
    w.f32(bottom ? p.bottom_retract_speed : p.retract_speed);
    w.f32(0.f);                       // retract height, second stage
    w.f32(0.f);                       // retract speed, second stage
    w.f32(p.wait_after_cure);
    w.f32(p.wait_after_lift);
    w.f32(p.wait_before_cure);
    w.f32(float(bottom ? p.bottom_light_pwm : p.light_pwm));
    w.u32(0);
    return buf;
}

// Call fn(first_pixel, count) for each run of exposed (non black) pixels of a layer encoded by the CTB RLE.
template<class Fn> void for_each_exposed_run(const std::vector<uint8_t>& rle, Fn&& fn)
{
    uint64_t pixel = 0;
    for (size_t n = 0; n < rle.size(); ++n) {
        uint8_t code = rle[n];
        uint64_t stride = 1;
        if ((code & 0x80) && n + 1 < rle.size()) {
            code &= 0x7f;
            const uint8_t slen = rle[++n];
            const size_t extra = (slen & 0x80) == 0 ? 0 : (slen & 0xc0) == 0x80 ? 1 : (slen & 0xe0) == 0xc0 ? 2 : 3;
            stride = slen & (0x7f >> extra);
            for (size_t k = 0; k < extra && n + 1 < rle.size(); ++k)
                stride = (stride << 8) | rle[++n];
        }
        if (code != 0)
            fn(pixel, stride);
        pixel += stride;
    }
}

uint64_t count_exposed_pixels(const std::vector<uint8_t>& rle)
{
    uint64_t count = 0;
    for_each_exposed_run(rle, [&count](uint64_t, uint64_t length) { count += length; });
    return count;
}

std::vector<uint8_t> serialize_preview(const PreviewImage& image, uint64_t pos, std::vector<uint8_t>& encoded)
{
    encoded = encode_preview(image);
    std::vector<uint8_t> buf;
    ByteWriter w{buf};
    w.u32(image.width);
    w.u32(image.height);
    w.u32(low32(pos + preview_hdr_size));
    w.u32(uint32_t(encoded.size()));
    return buf;
}

} // namespace

Sha256 sha256(const uint8_t* data, size_t size)
{
    std::array<uint32_t, 8> h{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t full = size / 64 * 64;
    for (size_t i = 0; i < full; i += 64)
        sha256_block(h, data + i);

    // Padding: 0x80, zeros, message length in bits (big endian).
    uint8_t tail[128] = {};
    const size_t rest = size - full;
    std::memcpy(tail, data + full, rest);
    tail[rest] = 0x80;
    const size_t tail_size = rest + 9 <= 64 ? 64 : 128;
    const uint64_t bits = uint64_t(size) * 8;
    for (int i = 0; i < 8; ++i)
        tail[tail_size - 1 - i] = uint8_t(bits >> (8 * i));
    for (size_t i = 0; i < tail_size; i += 64)
        sha256_block(h, tail + i);

    Sha256 out;
    for (int i = 0; i < 8; ++i)
        for (int k = 0; k < 4; ++k)
            out[4 * i + k] = uint8_t(h[i] >> (24 - 8 * k));
    return out;
}

GrayscaleLut grayscale_lut(const GrayscaleSettings& settings)
{
    const unsigned levels = std::clamp(settings.level, 1u, 8u);
    const double   min_gray = std::min(settings.min_gray, settings.max_gray);
    const double   max_gray = std::max(settings.min_gray, settings.max_gray);
    const double   picture  = settings.picture_gray / 255.;

    GrayscaleLut lut{};
    for (unsigned coverage = 1; coverage < 256; ++coverage) {
        double gray = 0.;
        if (coverage == 255)
            gray = 255.;
        else if (!settings.antialiasing)
            gray = coverage >= 128 ? 255. : 0.;
        else {
            // Edge pixel: the nearest of the levels spread evenly above min_gray up to max_gray, level 0 is black.
            const unsigned level = unsigned(std::lround(coverage * double(levels) / 255.));
            if (level > 0)
                gray = min_gray + (max_gray - min_gray) * double(level) / double(levels);
        }
        lut[coverage] = uint8_t(std::lround(gray * picture));
    }
    return lut;
}

std::vector<uint8_t> rle_encode(const uint8_t* pixels, size_t count, const GrayscaleLut* lut)
{
    std::vector<uint8_t> out;
    // Layers are mostly black, a few bytes per row is a good first guess.
    out.reserve(count / 256 + 16);

    auto gray7_at = [pixels, lut](size_t idx) { return uint8_t((lut ? (*lut)[pixels[idx]] : pixels[idx]) >> 1); };
    size_t i = 0;
    while (i < count) {
        const uint8_t gray7 = gray7_at(i);
        size_t j = i + 1;
        while (j < count && gray7_at(j) == gray7)
            ++j;
        add_run(out, gray7, j - i);
        i = j;
    }
    return out;
}

std::vector<uint8_t> rle_decode(const std::vector<uint8_t>& rle, size_t count)
{
    std::vector<uint8_t> pixels(count, 0);
    size_t pixel = 0;
    for (size_t n = 0; n < rle.size(); ++n) {
        uint8_t code = rle[n];
        size_t stride = 1;
        if (code & 0x80) {
            code &= 0x7f;
            if (++n >= rle.size())
                throw std::runtime_error("CTB RLE: truncated run");
            const uint8_t slen = rle[n];
            size_t extra = 0;
            if ((slen & 0x80) == 0) {
                stride = slen;
            } else if ((slen & 0xc0) == 0x80) {
                extra = 1;
                stride = slen & 0x3f;
            } else if ((slen & 0xe0) == 0xc0) {
                extra = 2;
                stride = slen & 0x1f;
            } else if ((slen & 0xf0) == 0xe0) {
                extra = 3;
                stride = slen & 0x0f;
            } else {
                throw std::runtime_error("CTB RLE: invalid run length");
            }
            if (n + extra >= rle.size())
                throw std::runtime_error("CTB RLE: truncated run");
            for (size_t k = 0; k < extra; ++k)
                stride = (stride << 8) | rle[++n];
        }

        if (code != 0) {
            if (stride > count - pixel)
                throw std::runtime_error("CTB RLE: data exceed the image");
            // Extend the 7-bit gray back to 8 bits.
            std::fill_n(pixels.begin() + pixel, stride, uint8_t((code << 1) | 1));
        }
        pixel += stride;
    }
    return pixels;
}

float layer_exposure_time(const PrintParams& p, size_t idx)
{
    if (idx < p.bottom_layers)
        return p.bottom_exposure_time;
    const size_t transition_idx = idx - p.bottom_layers;
    if (transition_idx < p.transition_layers) {
        const float step = (p.bottom_exposure_time - p.exposure_time) / float(p.transition_layers + 1);
        return p.bottom_exposure_time - step * float(transition_idx + 1);
    }
    return p.exposure_time;
}

float layer_position_z(const PrintParams& p, size_t idx)
{
    return p.initial_layer_height + p.layer_height * float(idx);
}

float estimate_print_time(const PrintParams& p, size_t layer_count)
{
    auto move_time = [](float height, float speed) {
        return speed > 0.f ? height / speed * 60.f : 0.f;
    };

    double time = 0.;
    for (size_t idx = 0; idx < layer_count; ++idx) {
        const bool bottom = idx < p.bottom_layers;
        const float lift = bottom ? p.bottom_lift_height : p.lift_height;
        time += layer_exposure_time(p, idx);
        time += move_time(lift, bottom ? p.bottom_lift_speed : p.lift_speed);
        time += move_time(lift, bottom ? p.bottom_retract_speed : p.retract_speed);
        time += p.wait_before_cure + p.wait_after_cure + p.wait_after_lift;
    }
    return float(time);
}

void aes_encrypt(uint8_t* data, size_t size)
{
    if (size % 16 != 0)
        throw std::invalid_argument("CTB: AES data have to be aligned to 16 bytes");

    static const RoundKeys round_keys = expand_key(aes_key);
    const uint8_t* prev = aes_iv.data();
    for (size_t offset = 0; offset < size; offset += 16) {
        uint8_t* block = data + offset;
        for (size_t k = 0; k < 16; ++k)
            block[k] ^= prev[k];
        encrypt_block(block, round_keys);
        prev = block;
    }
}

uint32_t crc32(const uint8_t* data, size_t size, uint32_t crc)
{
    static const std::array<uint32_t, 256> table = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }();

    crc = ~crc;
    for (size_t i = 0; i < size; ++i)
        crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return ~crc;
}

void xor_layer(uint32_t key, uint32_t layer_idx, uint8_t* data, size_t size)
{
    if (key == 0)
        return;
    const uint32_t init = key * 0x2d83cdacu + 0xd8a83423u;
    uint32_t xor_key = (layer_idx * 0x1e1530cdu + 0xec3d47cdu) * init;
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= uint8_t(xor_key >> (8 * (i % 4)));
        if (i % 4 == 3)
            xor_key += init;
    }
}

PreviewImage silhouette_preview(
    const std::vector<std::vector<uint8_t>>& layers,
    uint32_t resolution_x,
    uint32_t resolution_y,
    uint32_t width,
    uint32_t height
)
{
    PreviewImage image;
    image.width  = width;
    image.height = height;
    image.rgba.assign(size_t(width) * height * 4, 0);
    for (size_t i = 3; i < image.rgba.size(); i += 4)
        image.rgba[i] = 255;
    if (resolution_x == 0 || resolution_y == 0 || width == 0 || height == 0)
        return image;

    // Keep the aspect ratio of the display, centered in the preview.
    const double scale = std::min(double(width) / resolution_x, double(height) / resolution_y);
    const double offset_x = (width - resolution_x * scale) / 2.;
    const double offset_y = (height - resolution_y * scale) / 2.;
    auto to_preview = [](uint64_t px, double s, double offset, uint32_t size) {
        return std::min<uint32_t>(uint32_t(offset + double(px) * s), size - 1);
    };

    std::vector<uint8_t> covered(size_t(width) * height, 0);
    for (const std::vector<uint8_t>& layer : layers) {
        for_each_exposed_run(layer, [&](uint64_t first, uint64_t length) {
            const uint64_t last = first + length - 1;
            for (uint64_t row = first / resolution_x; row <= last / resolution_x && row < resolution_y; ++row) {
                const uint64_t col_from = row == first / resolution_x ? first % resolution_x : 0;
                const uint64_t col_to   = row == last / resolution_x ? last % resolution_x : resolution_x - 1;
                const uint32_t y  = to_preview(row, scale, offset_y, height);
                const uint32_t x0 = to_preview(col_from, scale, offset_x, width);
                const uint32_t x1 = to_preview(col_to, scale, offset_x, width);
                std::fill(covered.begin() + size_t(y) * width + x0, covered.begin() + size_t(y) * width + x1 + 1, 1);
            }
        });
    }

    for (size_t i = 0; i < covered.size(); ++i)
        if (covered[i])
            std::fill_n(image.rgba.begin() + i * 4, 3, uint8_t(200));
    return image;
}

std::vector<uint8_t> encode_preview(const PreviewImage& image)
{
    if (image.rgba.size() != size_t(image.width) * image.height * 4)
        throw std::invalid_argument("CTB: wrong preview image size");

    constexpr uint16_t repeat_flag = 0x20;
    constexpr uint32_t max_repeat = 0xfff;

    std::vector<uint8_t> out;
    ByteWriter w{out};
    auto flush = [&w](uint16_t color, uint32_t repeat) {
        if (repeat == 0)
            return;
        if (repeat == 1) {
            w.u16(uint16_t(color & ~repeat_flag));
        } else {
            w.u16(uint16_t(color | repeat_flag));
            w.u16(uint16_t((repeat - 1) | 0x3000));
        }
    };

    uint16_t color = 0;
    uint32_t repeat = 0;
    for (size_t i = 0; i < image.rgba.size(); i += 4) {
        const unsigned a = image.rgba[i + 3];
        const auto blend = [a](uint8_t c) { return uint8_t((unsigned(c) * a + 127) / 255); };
        const uint8_t r = blend(image.rgba[i]);
        const uint8_t g = blend(image.rgba[i + 1]);
        const uint8_t b = blend(image.rgba[i + 2]);
        // RGB565, the lowest green bit is used as the repeat flag.
        const uint16_t c = uint16_t((b >> 3) | ((g >> 2) << 5) | ((r >> 3) << 11));
        if (c == color && repeat > 0) {
            if (++repeat == max_repeat) {
                flush(color, repeat);
                repeat = 0;
            }
        } else {
            flush(color, repeat);
            color = c;
            repeat = 1;
        }
    }
    flush(color, repeat);
    return out;
}

void write_ctb(
    std::ostream& out,
    const PrintParams& params,
    const std::vector<std::vector<uint8_t>>& layers,
    const std::optional<PreviewImage>& large_preview,
    const std::optional<PreviewImage>& small_preview
)
{
    // All sizes are known beforehand, so the offsets can be computed and the file written
    // sequentially, which allows computing the CRC on the fly.
    SettingsOffsets offsets;
    uint64_t pos = header_size + settings_size;

    std::vector<uint8_t> large_hdr, large_data, small_hdr, small_data;
    if (large_preview) {
        offsets.large_preview = low32(pos);
        large_hdr = serialize_preview(*large_preview, pos, large_data);
        pos += large_hdr.size() + large_data.size();
    }
    if (small_preview) {
        offsets.small_preview = low32(pos);
        small_hdr = serialize_preview(*small_preview, pos, small_data);
        pos += small_hdr.size() + small_data.size();
    }

    offsets.machine_name = low32(pos);
    pos += params.machine_name.size();
    offsets.disclaimer = low32(pos);
    pos += disclaimer.size();

    offsets.resin_params = low32(pos);
    std::vector<uint8_t> resin;
    {
        ByteWriter w{resin};
        uint64_t str_pos = pos + resin_hdr_size;
        w.u32(0);
        w.u32(0);                     // resin color BGRA
        for (const std::string* str : {&params.resin_type, &params.resin_name, &params.resin_profile_name}) {
            w.u32(low32(str_pos));
            w.u32(uint32_t(str->size()));
            str_pos += str->size();
        }
        w.f32(params.resin_density);
        w.u32(0);
        for (const std::string* str : {&params.resin_type, &params.resin_name, &params.resin_profile_name})
            w.bytes(str->data(), str->size());
    }
    pos += resin.size();

    offsets.layer_pointers = low32(pos);
    pos += layer_ptr_size * layers.size();

    std::vector<uint8_t> layer_ptrs;
    std::vector<uint64_t> layer_def_pos(layers.size());
    {
        ByteWriter w{layer_ptrs};
        for (size_t i = 0; i < layers.size(); ++i) {
            layer_def_pos[i] = pos;
            w.u32(low32(pos));
            w.u32(page(pos));
            w.u32(uint32_t(layer_def_size));
            w.u32(0);
            pos += layer_def_size + layers[i].size() + layer_trailer_size;
            offsets.max_layer_data = std::max(offsets.max_layer_data, uint32_t(layers[i].size()));
        }
    }
    const uint64_t signature_pos = pos;

    std::vector<uint8_t> settings = build_settings(params, layers.size(), offsets);
    aes_encrypt(settings.data(), settings.size());

    std::vector<uint8_t> header;
    {
        ByteWriter w{header};
        w.u32(magic);
        w.u32(uint32_t(settings_size));
        w.u32(uint32_t(header_size));
        w.u32(0);
        w.u32(version);
        w.u32(uint32_t(signature_size));
        w.u32(low32(signature_pos));
        w.u32(0);
        w.u16(1);
        w.u16(1);
        w.u32(0);
        w.u32(42);
        w.u32(0);
    }

    FileWriter file{out};
    file.write(header);
    file.write(settings);
    file.write(large_hdr);
    file.write(large_data);
    file.write(small_hdr);
    file.write(small_data);
    file.write(reinterpret_cast<const uint8_t*>(params.machine_name.data()), params.machine_name.size());
    file.write(reinterpret_cast<const uint8_t*>(disclaimer.data()), disclaimer.size());
    file.write(resin);
    file.write(layer_ptrs);

    const double pixel_area = params.resolution_x == 0 || params.resolution_y == 0 ? 0. :
        double(params.display_width) / params.resolution_x * double(params.display_height) / params.resolution_y;
    std::vector<uint8_t> layer_data;
    for (size_t i = 0; i < layers.size(); ++i) {
        const uint64_t data_pos = layer_def_pos[i] + layer_def_size;
        file.write(serialize_layer_def(params, i, data_pos, uint32_t(layers[i].size())));
        layer_data = layers[i];
        xor_layer(params.layer_xor_key, uint32_t(i), layer_data.data(), layer_data.size());
        file.write(layer_data);

        // Exposed area of the layer in mm^2 followed by 4 zero bytes.
        std::vector<uint8_t> trailer;
        ByteWriter w{trailer};
        w.f32(float(double(count_exposed_pixels(layers[i])) * pixel_area));
        w.u32(0);
        file.write(trailer);
    }

    if (file.position() != signature_pos)
        throw std::logic_error("CTB: wrong computation of the offsets");

    const std::array<uint8_t, 8> checksum{}; // checksum value from the settings block, zero
    Sha256 signature = sha256(checksum.data(), checksum.size());
    aes_encrypt(signature.data(), signature.size());
    file.write(signature.data(), signature.size());

    std::vector<uint8_t> crc;
    ByteWriter{crc}.u32(file.crc());
    file.write(crc);
}

} // namespace Slic3r::Ctb
