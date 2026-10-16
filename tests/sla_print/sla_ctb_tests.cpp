#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include <cstring>
#include <random>
#include <set>
#include <sstream>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/nowide/fstream.hpp>

#include <test_utils.hpp>

#include "libslic3r/Format/CTBFormat.hpp"
#include "libslic3r/FileReader.hpp"
#include "libslic3r/SLAPrint.hpp"

// Expected values were taken from files written by Chitubox for the Phrozen Sonic Mighty 8K
// and from `openssl enc -aes-256-cbc -nopad`.

using namespace Slic3r;
using Catch::Approx;

namespace {

std::string hex(const uint8_t* data, size_t size)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0x0f];
    }
    return out;
}

uint32_t u32(const std::string& s, size_t pos)
{
    uint32_t v;
    std::memcpy(&v, s.data() + pos, 4);
    return v;
}

float f32(const std::string& s, size_t pos)
{
    float v;
    std::memcpy(&v, s.data() + pos, 4);
    return v;
}

// CTB stores 7-bit gray, black stays black and other values get the lowest bit set.
uint8_t to_ctb_gray(uint8_t px) { return (px >> 1) == 0 ? 0 : uint8_t(((px >> 1) << 1) | 1); }

// Print parameters of the reference file "Phrozen XP Finder.ctb" (20 layers).
Ctb::PrintParams reference_params()
{
    Ctb::PrintParams p;
    p.display_width = 218.88f;
    p.display_height = 123.12f;
    p.machine_z = 235.f;
    p.resolution_x = 7680;
    p.resolution_y = 4320;
    p.initial_layer_height = 0.15f;
    p.layer_height = 0.15f;
    p.exposure_time = 3.f;
    p.bottom_exposure_time = 20.f;
    p.bottom_layers = 6;
    p.transition_layers = 6;
    p.bottom_lift_height = p.lift_height = 3.f;
    p.bottom_lift_speed = p.lift_speed = 100.f;
    p.bottom_retract_speed = p.retract_speed = 150.f;
    p.wait_before_cure = 1.f;
    p.machine_name = "Phrozen Sonic Mighty 8K";
    return p;
}

} // namespace

TEST_CASE("CTB RLE round trip", "[CTB]") {
    std::mt19937 rng(42);
    for (int t = 0; t < 100; ++t) {
        const size_t count = rng() % 20000 + 1;
        std::vector<uint8_t> pixels(count);
        for (size_t i = 0; i < count;) {
            const size_t run = rng() % (t % 2 ? 5000 : 50) + 1;
            const uint8_t value = rng() % 3 == 0 ? uint8_t(rng()) : (rng() % 2 ? 255 : 0);
            for (size_t k = 0; k < run && i < count; ++k)
                pixels[i++] = value;
        }

        const std::vector<uint8_t> decoded = Ctb::rle_decode(Ctb::rle_encode(pixels.data(), count), count);
        REQUIRE(decoded.size() == count);
        for (size_t i = 0; i < count; ++i)
            REQUIRE(decoded[i] == to_ctb_gray(pixels[i]));
    }
}

TEST_CASE("CTB RLE of an empty 8K layer", "[CTB]") {
    // Chitubox stores the empty layer as a single 4 byte long black run.
    const std::vector<uint8_t> empty(7680 * 4320, 0);
    const std::vector<uint8_t> rle = Ctb::rle_encode(empty.data(), empty.size());
    REQUIRE(rle == std::vector<uint8_t>{0x80, 0xe1, 0xfa, 0x40, 0x00});
}

TEST_CASE("CTB RLE rejects corrupted data", "[CTB]") {
    REQUIRE_THROWS(Ctb::rle_decode({0xff}, 10));                // run without length
    REQUIRE_THROWS(Ctb::rle_decode({0xff, 0x0b}, 10));          // run longer than the image
    REQUIRE_THROWS(Ctb::rle_decode({0xff, 0xf0, 0, 0, 0}, 10)); // invalid length prefix
}

TEST_CASE("CTB SHA-256", "[CTB]")
{
    auto digest = [](const std::string& s) {
        const Ctb::Sha256 d = Ctb::sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        return hex(d.data(), d.size());
    };
    CHECK(digest("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(digest("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("CTB AES encryption", "[CTB]")
{
    std::vector<uint8_t> data(48);
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = uint8_t(i);
    Ctb::aes_encrypt(data.data(), data.size());
    CHECK(hex(data.data(), data.size()) ==
          "6430178537df791aaa1cc6806a1dba7c505dc26259849a55824e0911f26cf5ec"
          "2aa9db263db2e0c103f04b697f765edb");

    std::vector<uint8_t> unaligned(17);
    CHECK_THROWS(Ctb::aes_encrypt(unaligned.data(), unaligned.size()));
}

TEST_CASE("CTB signature of the zero checksum", "[CTB]")
{
    const uint8_t checksum[8] = {};
    Ctb::Sha256 signature = Ctb::sha256(checksum, sizeof(checksum));
    Ctb::aes_encrypt(signature.data(), signature.size());
    CHECK(hex(signature.data(), signature.size()) ==
          "1e9c9a1e7689201ecf60bbe265f7e84087e9cfb56565023913d35ee71acf87dc");
}

TEST_CASE("CTB CRC32", "[CTB]")
{
    const std::string check{"123456789"};
    CHECK(Ctb::crc32(reinterpret_cast<const uint8_t*>(check.data()), check.size()) == 0xCBF43926u);
    const uint32_t first = Ctb::crc32(reinterpret_cast<const uint8_t*>(check.data()), 4);
    CHECK(Ctb::crc32(reinterpret_cast<const uint8_t*>(check.data()) + 4, 5, first) == 0xCBF43926u);
}

TEST_CASE("CTB layer scrambling", "[CTB]")
{
    // Empty layer 19 of the reference file.
    std::vector<uint8_t> data{0x80, 0xe1, 0xfa, 0x40, 0x00};
    Ctb::xor_layer(1096595302u, 19, data.data(), data.size());
    CHECK(hex(data.data(), data.size()) == "2c56a7e757");
    Ctb::xor_layer(1096595302u, 19, data.data(), data.size());
    CHECK(hex(data.data(), data.size()) == "80e1fa4000");
    Ctb::xor_layer(0, 19, data.data(), data.size());
    CHECK(hex(data.data(), data.size()) == "80e1fa4000");
}

TEST_CASE("CTB exposure, position and print time", "[CTB]")
{
    const Ctb::PrintParams p = reference_params();
    CHECK(Ctb::layer_exposure_time(p, 0) == 20.f);
    CHECK(Ctb::layer_exposure_time(p, 5) == 20.f);
    CHECK(Ctb::layer_exposure_time(p, 6) == Approx(17.571428));
    CHECK(Ctb::layer_exposure_time(p, 11) == Approx(5.428571));
    CHECK(Ctb::layer_exposure_time(p, 12) == 3.f);
    CHECK(Ctb::layer_position_z(p, 0) == Approx(0.15));
    CHECK(Ctb::layer_position_z(p, 19) == Approx(3.0));
    // Same as computed by Chitubox for the reference files.
    CHECK(Ctb::estimate_print_time(p, 20) == Approx(293.).margin(0.5));
    CHECK(Ctb::estimate_print_time(p, 644) == Approx(4661.).margin(0.5));
}

TEST_CASE("CTB preview encoding", "[CTB]")
{
    Ctb::PreviewImage image;
    image.width = 4;
    image.height = 1;
    image.rgba = {
        255, 0, 0, 255, // red
        255, 0, 0, 255, // red
        255, 0, 0, 255, // red
        255, 255, 255, 0 // transparent, blended onto black
    };
    const std::vector<uint8_t> rle = Ctb::encode_preview(image);
    // Red as RGB565 with the repeat flag, 3 repeats, then a single black pixel.
    CHECK(hex(rle.data(), rle.size()) == "20f802300000");

    image.rgba.pop_back();
    CHECK_THROWS(Ctb::encode_preview(image));
}

TEST_CASE("CTB silhouette preview", "[CTB]")
{
    // 4x2 px layers: first layer exposes the top row left 3 px, second the bottom right pixel.
    const std::vector<std::vector<uint8_t>> layers{{0xff, 0x03, 0x80, 0x05}, {0x80, 0x07, 0x7f}};
    const Ctb::PreviewImage preview = Ctb::silhouette_preview(layers, 4, 2, 4, 2);
    REQUIRE(preview.rgba.size() == 4 * 2 * 4);
    auto lit = [&preview](size_t x, size_t y) { return preview.rgba[(y * 4 + x) * 4] != 0; };
    CHECK(lit(0, 0));
    CHECK(lit(2, 0));
    CHECK_FALSE(lit(3, 0));
    CHECK_FALSE(lit(0, 1));
    CHECK(lit(3, 1));
    CHECK(preview.rgba[3] == 255);
}

TEST_CASE("CTB file layout", "[CTB]")
{
    Ctb::PrintParams p = reference_params();
    p.resolution_x = 4;
    p.resolution_y = 2;
    p.display_width = 4.f;
    p.display_height = 2.f;
    p.machine_name = "Test";
    p.resin_profile_name = "Resin";

    // Layer 0: 3 white pixels, layer 1: empty.
    const std::vector<std::vector<uint8_t>> layers{{0xff, 0x03, 0x80, 0x05}, {0x80, 0x08}};

    std::stringstream stream;
    Ctb::write_ctb(stream, p, layers, std::nullopt, std::nullopt);
    const std::string file = stream.str();

    REQUIRE(file.size() > Ctb::header_size + Ctb::settings_size);
    CHECK(u32(file, 0) == Ctb::magic);
    CHECK(u32(file, 4) == Ctb::settings_size);
    CHECK(u32(file, 8) == Ctb::header_size);
    CHECK(u32(file, 16) == Ctb::version);
    CHECK(u32(file, 20) == Ctb::signature_size);
    const uint32_t signature_pos = u32(file, 24);
    CHECK(signature_pos == file.size() - Ctb::signature_size - 4);

    // Machine name and disclaimer follow the settings when there are no previews.
    size_t pos = Ctb::header_size + Ctb::settings_size;
    CHECK(file.substr(pos, 4) == "Test");
    pos += 4;
    CHECK(file.substr(pos, 10) == "Layout and");
    pos += 320;

    // Resin parameters: address and length pairs of resin type, name and profile name.
    const size_t strings_pos = pos + Ctb::resin_hdr_size;
    CHECK(u32(file, pos + 8) == strings_pos);
    CHECK(u32(file, pos + 12) == p.resin_type.size());
    CHECK(f32(file, pos + 32) == Approx(1.1));
    CHECK(file.substr(strings_pos, 17) == "normalnormalResin");
    pos = strings_pos + 17;

    // Layer pointers and layers.
    const size_t first_layer = pos + 2 * Ctb::layer_ptr_size;
    CHECK(u32(file, pos) == first_layer);
    CHECK(u32(file, pos + 8) == Ctb::layer_def_size);
    const size_t second_layer = first_layer + Ctb::layer_def_size + layers[0].size() + Ctb::layer_trailer_size;
    CHECK(u32(file, pos + Ctb::layer_ptr_size) == second_layer);

    CHECK(u32(file, first_layer) == Ctb::layer_def_size);
    CHECK(f32(file, first_layer + 4) == Approx(0.15));
    CHECK(f32(file, first_layer + 8) == Approx(20.));
    CHECK(u32(file, first_layer + 16) == first_layer + Ctb::layer_def_size);
    CHECK(u32(file, first_layer + 24) == layers[0].size());

    std::vector<uint8_t> data(file.begin() + first_layer + Ctb::layer_def_size,
                              file.begin() + first_layer + Ctb::layer_def_size + layers[0].size());
    Ctb::xor_layer(p.layer_xor_key, 0, data.data(), data.size());
    CHECK(data == layers[0]);
    // Exposed area: 3 pixels of 1 mm^2.
    CHECK(f32(file, first_layer + Ctb::layer_def_size + layers[0].size()) == Approx(3.));
    CHECK(f32(file, second_layer + Ctb::layer_def_size + layers[1].size()) == 0.f);
    CHECK(second_layer + Ctb::layer_def_size + layers[1].size() + Ctb::layer_trailer_size == signature_pos);

    CHECK(hex(reinterpret_cast<const uint8_t*>(file.data()) + signature_pos, Ctb::signature_size) ==
          "1e9c9a1e7689201ecf60bbe265f7e84087e9cfb56565023913d35ee71acf87dc");
    CHECK(u32(file, file.size() - 4) ==
          Ctb::crc32(reinterpret_cast<const uint8_t*>(file.data()), file.size() - 4));
}

TEST_CASE("CTB export of a sliced model", "[CTB][sla_archives]")
{
    SLAPrint print;
    SLAFullPrintConfig fullcfg;
    auto m = FileReader::load_model(TEST_DATA_DIR PATH_SEPARATOR + std::string("20mm_cube") + ".obj");

    fullcfg.printer_technology.setInt(ptSLA);
    fullcfg.set("sla_archive_format", "CTB");
    fullcfg.set("supports_enable", false);
    fullcfg.set("pad_enable", false);
    fullcfg.set("printer_model", "Phrozen Sonic Mighty 8K");
    fullcfg.set("bottom_layers", 4);

    DynamicPrintConfig cfg;
    cfg.apply(fullcfg);
    print.set_status_callback([](const PrintBase::SlicingStatus&) {});
    print.apply(m, cfg);
    print.process();

    const boost::filesystem::path path = boost::filesystem::temp_directory_path() /
                                         boost::filesystem::unique_path("ctb_export_test_%%%%-%%%%.ctb");
    print.export_print(path.string(), ThumbnailsList{}, "20mm_cube");
    REQUIRE(boost::filesystem::exists(path));

    std::string file;
    {
        boost::nowide::ifstream in(path.string(), std::ios::binary);
        file.assign(std::istreambuf_iterator<char>(in), {});
    }
    boost::filesystem::remove(path);
    REQUIRE(file.size() > Ctb::header_size + Ctb::settings_size);
    CHECK(u32(file, 0) == Ctb::magic);
    CHECK(u32(file, 16) == Ctb::version);
    const uint32_t signature_pos = u32(file, 24);
    CHECK(signature_pos == file.size() - Ctb::signature_size - 4);
    CHECK(hex(reinterpret_cast<const uint8_t*>(file.data()) + signature_pos, Ctb::signature_size) ==
          "1e9c9a1e7689201ecf60bbe265f7e84087e9cfb56565023913d35ee71acf87dc");
    CHECK(u32(file, file.size() - 4) ==
          Ctb::crc32(reinterpret_cast<const uint8_t*>(file.data()), file.size() - 4));
    // Previews are generated from the layers when no thumbnails are rendered,
    // they start right after the settings block.
    CHECK(u32(file, Ctb::header_size + Ctb::settings_size) == 400);
}

namespace {

// Slice the model for the archive format, without supports to keep the test fast.
std::unique_ptr<SLAPrint> slice_for_format(const char *format, const std::string &model_name, Model &model)
{
    auto print = std::make_unique<SLAPrint>();
    SLAFullPrintConfig fullcfg;
    model = FileReader::load_model(TEST_DATA_DIR PATH_SEPARATOR + model_name + ".obj");

    fullcfg.printer_technology.setInt(ptSLA);
    fullcfg.set("sla_archive_format", format);
    fullcfg.set("supports_enable", false);
    fullcfg.set("pad_enable", false);

    DynamicPrintConfig cfg;
    cfg.apply(fullcfg);
    print->set_status_callback([](const PrintBase::SlicingStatus&) {});
    print->apply(model, cfg);
    print->process();
    return print;
}

} // namespace

TEST_CASE("SLA exposure images of the layers", "[CTB][sla_archives]")
{
    Model ctb_model, sl1_model;
    const auto ctb = slice_for_format("CTB", "20mm_cube", ctb_model);
    const auto sl1 = slice_for_format("SL1", "20mm_cube", sl1_model);
    REQUIRE(ctb->finished());
    REQUIRE(sl1->finished());

    const size_t layer_count = ctb->print_layers().size();
    REQUIRE(layer_count > 10);
    REQUIRE(sl1->print_layers().size() == layer_count);

    const SLAPrinterConfig &pcfg = ctb->printer_config();
    const double pixel_area = pcfg.display_width.getFloat() / pcfg.display_pixels_x.getInt() *
                              pcfg.display_height.getFloat() / pcfg.display_pixels_y.getInt();

    for (size_t idx : {size_t(0), layer_count / 2, layer_count - 1}) {
        const SLAArchiveWriter::LayerImage ctb_img = ctb->layer_exposure_image(idx);
        const SLAArchiveWriter::LayerImage sl1_img = sl1->layer_exposure_image(idx);
        REQUIRE(!ctb_img.empty());
        REQUIRE(!sl1_img.empty());
        REQUIRE(ctb_img.width == sl1_img.width);
        REQUIRE(ctb_img.height == sl1_img.height);
        REQUIRE(ctb_img.pixels.size() == ctb_img.width * ctb_img.height);

        // Both archives store the same raster, CTB mapped by the anti-aliasing settings and with 7-bit gray levels.
        const Ctb::GrayscaleLut lut = Ctb::grayscale_lut(Ctb::GrayscaleSettings{});
        size_t mismatches = 0;
        double exposed = 0.;
        for (size_t i = 0; i < ctb_img.pixels.size(); ++i) {
            if (ctb_img.pixels[i] != to_ctb_gray(lut[sl1_img.pixels[i]]))
                ++mismatches;
            exposed += sl1_img.pixels[i] / 255.;
        }
        CHECK(mismatches == 0);

        // The exposed area matches the area of the layer computed from the slices.
        const double area = sl1->print_statistics().layers_areas[idx];
        CHECK(exposed * pixel_area == Approx(area).epsilon(0.01));
    }

    // Out of range layers have no image.
    CHECK(ctb->layer_exposure_image(layer_count).empty());
}

TEST_CASE("SLA layer index at the height of the preview slider", "[CTB][sla_archives]")
{
    Model model;
    const auto print = slice_for_format("CTB", "20mm_cube", model);
    const auto &layers = print->print_layers();
    REQUIRE(layers.size() > 2);

    for (size_t idx = 0; idx < layers.size(); ++idx) {
        const double z = unscaled(layers[idx].level());
        REQUIRE(print->layer_index_at_height(z) == idx);
    }

    // Heights between the layers map to the nearest one, heights out of the print to the end layers.
    const double z0 = unscaled(layers[0].level());
    const double z1 = unscaled(layers[1].level());
    CHECK(print->layer_index_at_height(z0 + (z1 - z0) * 0.4) == size_t(0));
    CHECK(print->layer_index_at_height(z0 + (z1 - z0) * 0.6) == size_t(1));
    CHECK(print->layer_index_at_height(-1.) == size_t(0));
    CHECK(print->layer_index_at_height(1000.) == layers.size() - 1);

    // Formats without a decoder don't provide images, but don't fail either.
    Model svg_model;
    const auto svg = slice_for_format("SL1SVG", "20mm_cube", svg_model);
    CHECK(svg->layer_exposure_image(0).empty());
}

TEST_CASE("CTB anti-aliasing gray levels", "[CTB]")
{
    SECTION("default: 8 levels between 0 and 255") {
        const Ctb::GrayscaleLut lut = Ctb::grayscale_lut(Ctb::GrayscaleSettings{});
        CHECK(lut[0] == 0);
        CHECK(lut[255] == 255);
        std::set<uint8_t> grays(lut.begin(), lut.end());
        // Black, 8 edge levels (the last one is 255, same as the fully exposed pixels).
        CHECK(grays.size() == 9);
        CHECK(grays.count(0) == 1);
        CHECK(grays.count(255) == 1);
        // Monotonic: more coverage never gives less light.
        for (size_t i = 1; i < lut.size(); ++i)
            CHECK(lut[i] >= lut[i - 1]);
    }

    SECTION("none: black and white only") {
        Ctb::GrayscaleSettings s;
        s.antialiasing = false;
        const Ctb::GrayscaleLut lut = Ctb::grayscale_lut(s);
        CHECK(lut[0] == 0);
        CHECK(lut[127] == 0);
        CHECK(lut[128] == 255);
        CHECK(lut[255] == 255);
        CHECK(std::set<uint8_t>(lut.begin(), lut.end()) == std::set<uint8_t>{0, 255});
    }

    SECTION("edge grays are limited to min and max") {
        Ctb::GrayscaleSettings s;
        s.level = 4;
        s.min_gray = 100;
        s.max_gray = 200;
        const Ctb::GrayscaleLut lut = Ctb::grayscale_lut(s);
        CHECK(lut[255] == 255);
        CHECK(lut[10] == 0);       // covered less than half of the first level stays black
        CHECK(lut[64] == 125);     // first level, the levels are 125, 150, 175, 200
        CHECK(lut[254] == 200);    // last level
        for (size_t i = 1; i < 255; ++i)
            CHECK((lut[i] == 0 || (lut[i] > 100 && lut[i] <= 200)));
        CHECK(std::set<uint8_t>(lut.begin(), lut.end()).size() == 6); // black, 4 levels, fully exposed
    }

    SECTION("one level: no gray") {
        Ctb::GrayscaleSettings s;
        s.level = 1;
        const Ctb::GrayscaleLut lut = Ctb::grayscale_lut(s);
        CHECK(std::set<uint8_t>(lut.begin(), lut.end()) == std::set<uint8_t>{0, 255});
    }

    SECTION("picture grayscale scales all the pixels") {
        Ctb::GrayscaleSettings s;
        s.antialiasing = false;
        s.picture_gray = 200;
        const Ctb::GrayscaleLut lut = Ctb::grayscale_lut(s);
        CHECK(lut[255] == 200);
        CHECK(lut[0] == 0);
    }

    SECTION("encoding applies the mapping") {
        Ctb::GrayscaleSettings s;
        s.antialiasing = false;
        const Ctb::GrayscaleLut lut = Ctb::grayscale_lut(s);
        const std::vector<uint8_t> pixels{0, 100, 200, 255};
        const std::vector<uint8_t> decoded = Ctb::rle_decode(Ctb::rle_encode(pixels.data(), pixels.size(), &lut), pixels.size());
        CHECK(decoded == std::vector<uint8_t>{0, 0, 255, 255});
    }
}

TEST_CASE("CTB export without anti-aliasing", "[CTB][sla_archives]")
{
    SLAPrint print;
    SLAFullPrintConfig fullcfg;
    Model m = FileReader::load_model(TEST_DATA_DIR PATH_SEPARATOR + std::string("20mm_cube") + ".obj");
    fullcfg.printer_technology.setInt(ptSLA);
    fullcfg.set("sla_archive_format", "CTB");
    fullcfg.set("supports_enable", false);
    fullcfg.set("pad_enable", false);
    fullcfg.set("antialiasing", false);
    fullcfg.set("picture_grayscale", 200);

    DynamicPrintConfig cfg;
    cfg.apply(fullcfg);
    print.set_status_callback([](const PrintBase::SlicingStatus&) {});
    print.apply(m, cfg);
    print.process();

    const SLAArchiveWriter::LayerImage img = print.layer_exposure_image(print.print_layers().size() / 2);
    REQUIRE(!img.empty());
    // Only black and the picture grayscale (stored as 7-bit gray).
    std::set<uint8_t> grays(img.pixels.begin(), img.pixels.end());
    CHECK(grays == std::set<uint8_t>{0, 201});
}
