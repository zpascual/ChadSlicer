#ifndef SLIC3R_FORMAT_CTBFORMAT_HPP
#define SLIC3R_FORMAT_CTBFORMAT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

/// Binary layout of the Chitubox encrypted '.ctb' file format (version 5), as written by
/// Chitubox for e.g. Phrozen printers. Independent of the slicer data structures, so it can be
/// unit tested against reference files.
///
/// File layout (all values little endian):
///   header (48 B) | settings (288 B, AES-256-CBC encrypted) | large preview | small preview |
///   machine name | disclaimer | resin parameters | layer pointer table |
///   { layer definition (88 B) + RLE data + exposed area (float) + 4 zero bytes } * layer count |
///   signature (32 B, encrypted SHA-256 of the settings checksum) | CRC32 of all preceding bytes
namespace Slic3r::Ctb {

constexpr uint32_t magic           = 0x12FD0107;
constexpr uint32_t version         = 5;
constexpr size_t   header_size     = 48;
constexpr size_t   settings_size   = 288;
constexpr size_t   layer_def_size  = 88;
constexpr size_t   layer_ptr_size  = 16;
constexpr size_t   preview_hdr_size = 16;
constexpr size_t   resin_hdr_size  = 40;
constexpr size_t   signature_size  = 32;
constexpr size_t   layer_trailer_size = 8;

/// Print parameters stored in the settings block and in the layer definitions.
/// Speeds are in mm/min, heights in mm, times in s.
struct PrintParams
{
    float display_width  = 0.f; // mm
    float display_height = 0.f; // mm
    float machine_z      = 0.f; // mm
    uint32_t resolution_x = 0;
    uint32_t resolution_y = 0;

    float initial_layer_height = 0.f;
    float layer_height         = 0.f;

    float exposure_time        = 0.f;
    float bottom_exposure_time = 0.f;
    uint32_t bottom_layers     = 0;
    uint32_t transition_layers = 0;

    float bottom_lift_height    = 0.f;
    float bottom_lift_speed     = 0.f;
    float bottom_retract_speed  = 0.f;
    float lift_height           = 0.f;
    float lift_speed            = 0.f;
    float retract_speed         = 0.f;

    float wait_before_cure = 0.f; // rest after retract
    float wait_after_cure  = 0.f; // rest before lift
    float wait_after_lift  = 0.f;

    uint16_t light_pwm        = 255;
    uint16_t bottom_light_pwm = 255;

    uint32_t anti_alias_level = 1;

    float material_ml   = 0.f;
    float material_g    = 0.f;
    float material_cost = 0.f;
    float resin_density = 1.1f; // g/ml

    std::string machine_name;
    std::string resin_type{"normal"};
    std::string resin_name{"normal"};
    std::string resin_profile_name;

    uint32_t layer_xor_key     = 0xEFBEADDE;
    uint32_t timestamp_minutes = 0; // minutes since unix epoch
};

/// RGBA 8-bit image, rows stored from top to bottom.
struct PreviewImage
{
    uint32_t width  = 0;
    uint32_t height = 0;
    std::vector<uint8_t> rgba;
};

using Sha256 = std::array<uint8_t, 32>;

/// Anti-aliasing of the layer images, same as the "Advance" settings of Chitubox.
struct GrayscaleSettings
{
    bool     antialiasing = true; // false: black and white pixels only ("None")
    unsigned level        = 8;    // count of the gray levels of the anti-aliased edges, 1 - 8
    uint8_t  min_gray     = 0;    // the edge levels are spread evenly above this gray ...
    uint8_t  max_gray     = 255;  // ... up to this gray
    uint8_t  picture_gray = 255;  // gray of the fully exposed pixels, scales all the pixels ("Picture Grayscale")
};

using GrayscaleLut = std::array<uint8_t, 256>;

/// <summary>
/// Lookup table mapping the pixel coverage drawn by the rasterizer (0 - 255) to the gray stored in the layer.
/// Fully covered pixels get picture_gray. With anti-aliasing, partially covered (edge) pixels are rounded
/// to the nearest of the gray levels spread evenly above min_gray up to max_gray, or to black when covered
/// less than half of the first level. Without anti-aliasing, pixels covered at least half are fully exposed.
/// All the grays are scaled by picture_gray / 255.
/// </summary>
GrayscaleLut grayscale_lut(const GrayscaleSettings& settings);

/// SHA-256 digest of the data.
Sha256 sha256(const uint8_t* data, size_t size);

/// <summary>
/// Encode 8-bit grayscale pixels with the CTB run length encoding.
/// Pixels are stored as 7-bit gray values (the lowest bit is dropped). A run is marked by the
/// highest bit of the gray value byte followed by a 1 to 4 bytes long run length.
/// </summary>
/// <param name="pixels">Row major 8-bit grayscale pixels</param>
/// <param name="count">Count of the pixels</param>
/// <param name="lut">Optional mapping of the pixels applied before encoding, see grayscale_lut</param>
/// <returns>Encoded data</returns>
std::vector<uint8_t> rle_encode(const uint8_t* pixels, size_t count, const GrayscaleLut* lut = nullptr);

/// <summary>
/// Decode the CTB run length encoding, inverse to rle_encode.
/// NOTE: Throw exception on corrupted data.
/// </summary>
/// <param name="rle">Encoded data</param>
/// <param name="count">Count of the pixels of the image</param>
/// <returns>Row major 8-bit grayscale pixels</returns>
std::vector<uint8_t> rle_decode(const std::vector<uint8_t>& rle, size_t count);

/// Exposure of the layer, with the linear transition from the bottom to the normal exposure.
float layer_exposure_time(const PrintParams& params, size_t layer_idx);

/// Height of the top of the layer above the build platform.
float layer_position_z(const PrintParams& params, size_t layer_idx);

/// Estimated print time in seconds: exposures, lift and retract moves and rest times.
float estimate_print_time(const PrintParams& params, size_t layer_count);

/// Encrypt the data in place by AES-256-CBC with the fixed CTB key, size has to be multiple of 16.
void aes_encrypt(uint8_t* data, size_t size);

/// CRC-32 (ISO-HDLC, as zlib), continue by passing the previous value as crc.
uint32_t crc32(const uint8_t* data, size_t size, uint32_t crc = 0);

/// XOR scrambling of the layer RLE data, symmetric (also descrambles).
void xor_layer(uint32_t key, uint32_t layer_idx, uint8_t* data, size_t size);

/// <summary>
/// Top view silhouette of the print (all layers combined), for files without rendered thumbnails.
/// Exposed areas are light gray on black background.
/// </summary>
/// <param name="layers">Layers encoded by the CTB RLE (not scrambled)</param>
/// <param name="resolution_x">Width of the layers in pixels</param>
/// <param name="resolution_y">Height of the layers in pixels</param>
/// <param name="width">Width of the preview</param>
/// <param name="height">Height of the preview</param>
PreviewImage silhouette_preview(
    const std::vector<std::vector<uint8_t>>& layers,
    uint32_t resolution_x,
    uint32_t resolution_y,
    uint32_t width,
    uint32_t height
);

/// RGB565 run length encoding of the preview image used by Chitubox.
/// Alpha is blended onto black.
std::vector<uint8_t> encode_preview(const PreviewImage& image);

/// <summary>
/// Write the whole '.ctb' file into the stream.
/// NOTE: Throw exception in case of a stream failure.
/// </summary>
/// <param name="out">Binary output stream</param>
/// <param name="params">Print parameters</param>
/// <param name="layers">Layers encoded by the CTB RLE (not scrambled)</param>
/// <param name="large_preview">Optional preview shown on the printer</param>
/// <param name="small_preview">Optional small preview</param>
void write_ctb(
    std::ostream& out,
    const PrintParams& params,
    const std::vector<std::vector<uint8_t>>& layers,
    const std::optional<PreviewImage>& large_preview,
    const std::optional<PreviewImage>& small_preview
);

} // namespace Slic3r::Ctb

#endif // SLIC3R_FORMAT_CTBFORMAT_HPP
