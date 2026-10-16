#include "CTB.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <boost/log/trivial.hpp>
#include <boost/nowide/fstream.hpp>

#include "CTBFormat.hpp"
#include "libslic3r/Exception.hpp"
#include "libslic3r/SLAPrint.hpp"

namespace Slic3r {

namespace {

Ctb::GrayscaleSettings grayscale_settings(const SLAPrinterConfig &cfg)
{
    Ctb::GrayscaleSettings settings;
    settings.antialiasing = cfg.antialiasing.getBool();
    settings.level        = unsigned(std::clamp(cfg.grayscale_level.getInt(), 1, 8));
    settings.min_gray     = uint8_t(std::clamp(cfg.grayscale_min.getInt(), 0, 255));
    settings.max_gray     = uint8_t(std::clamp(cfg.grayscale_max.getInt(), 0, 255));
    settings.picture_gray = uint8_t(std::clamp(cfg.picture_grayscale.getInt(), 0, 255));
    return settings;
}

// Thumbnails are rendered bottom up, CTB previews are stored top down.
Ctb::PreviewImage to_preview(const ThumbnailData &thumbnail)
{
    Ctb::PreviewImage preview;
    preview.width  = thumbnail.width;
    preview.height = thumbnail.height;
    const size_t row_size = size_t(preview.width) * 4;
    preview.rgba.reserve(row_size * preview.height);
    for (size_t row = preview.height; row-- > 0;) {
        const auto begin = thumbnail.pixels.begin() + row * row_size;
        preview.rgba.insert(preview.rgba.end(), begin, begin + row_size);
    }
    return preview;
}

} // namespace

std::unique_ptr<sla::RasterBase> CTBArchive::create_raster() const
{
    double w  = m_cfg.display_width.getFloat();
    double h  = m_cfg.display_height.getFloat();
    auto   pw = size_t(m_cfg.display_pixels_x.getInt());
    auto   ph = size_t(m_cfg.display_pixels_y.getInt());

    std::array<bool, 2> mirror;
    mirror[X] = m_cfg.display_mirror_x.getBool();
    mirror[Y] = m_cfg.display_mirror_y.getBool();

    auto ro = m_cfg.display_orientation.getInt();
    sla::RasterBase::Orientation orientation = ro == sla::RasterBase::roPortrait ?
                                                   sla::RasterBase::roPortrait :
                                                   sla::RasterBase::roLandscape;

    if (orientation == sla::RasterBase::roPortrait) {
        std::swap(w, h);
        std::swap(pw, ph);
    }

    sla::Resolution res{pw, ph};
    sla::PixelDim   pxdim{w / pw, h / ph};
    sla::RasterBase::Trafo tr{orientation, mirror};

    // Anti-aliased edges need the coverage of the edge pixels, zero gamma means thresholding.
    const double gamma = m_cfg.gamma_correction.getFloat();
    return sla::create_raster_grayscale_aa(res, pxdim, m_cfg.antialiasing.getBool() && gamma <= 0. ? 1. : gamma, tr);
}

sla::RasterEncoder CTBArchive::get_encoder() const
{
    // The anti-aliasing settings map the pixel coverage to the stored gray.
    return [lut = Ctb::grayscale_lut(grayscale_settings(m_cfg))](const void *ptr, size_t w, size_t h, size_t num_components) {
        if (num_components != 1)
            throw std::invalid_argument("CTB layers have to be grayscale");
        return sla::EncodedRaster(Ctb::rle_encode(static_cast<const uint8_t *>(ptr), w * h, &lut), "ctb");
    };
}

SLAArchiveWriter::LayerImage CTBArchive::decode_layer(size_t layer_idx) const
{
    LayerImage image;
    if (layer_idx >= m_layers.size())
        return image;

    // Same dimensions as used by the rasterizer, portrait displays are drawn rotated.
    size_t w = size_t(m_cfg.display_pixels_x.getInt());
    size_t h = size_t(m_cfg.display_pixels_y.getInt());
    if (m_cfg.display_orientation.getInt() == sla::RasterBase::roPortrait)
        std::swap(w, h);

    const sla::EncodedRaster &rst  = m_layers[layer_idx];
    const auto               *data = static_cast<const uint8_t *>(rst.data());
    try {
        image.pixels = Ctb::rle_decode(std::vector<uint8_t>(data, data + rst.size()), w * h);
        image.width  = w;
        image.height = h;
    } catch (const std::exception &e) {
        BOOST_LOG_TRIVIAL(error) << "CTB: failed to decode layer " << layer_idx << ": " << e.what();
        image = {};
    }
    return image;
}

void CTBArchive::export_print(const std::string     fname,
                              const SLAPrint       &print,
                              const ThumbnailsList &thumbnails,
                              const std::string    &/*projectname*/)
{
    const DynamicPrintConfig &cfg = print.full_print_config();
    const SLAMaterialConfig  &mat = print.material_config();

    Ctb::PrintParams p;

    // Same dimensions as used by the rasterizer, portrait displays are drawn rotated.
    float w  = float(m_cfg.display_width.getFloat());
    float h  = float(m_cfg.display_height.getFloat());
    auto  pw = uint32_t(m_cfg.display_pixels_x.getInt());
    auto  ph = uint32_t(m_cfg.display_pixels_y.getInt());
    if (m_cfg.display_orientation.getInt() == sla::RasterBase::roPortrait) {
        std::swap(w, h);
        std::swap(pw, ph);
    }
    p.display_width  = w;
    p.display_height = h;
    p.resolution_x   = pw;
    p.resolution_y   = ph;
    p.machine_z      = float(m_cfg.max_print_height.getFloat());

    p.initial_layer_height = float(mat.initial_layer_height.getFloat());
    p.layer_height         = float(cfg.opt_float("layer_height"));

    p.exposure_time        = float(mat.exposure_time.getFloat());
    p.bottom_exposure_time = float(mat.initial_exposure_time.getFloat());
    p.bottom_layers        = uint32_t(std::max(0, mat.bottom_layers.getInt()));
    p.transition_layers    = uint32_t(std::max(0, mat.transition_layers.getInt()));

    p.bottom_lift_height   = float(mat.tower_bottom_lift_height.getFloat());
    p.bottom_lift_speed    = float(mat.tower_bottom_lift_speed.getFloat());
    p.bottom_retract_speed = float(mat.tower_bottom_retract_speed.getFloat());
    p.lift_height          = float(mat.tower_lift_height.getFloat());
    p.lift_speed           = float(mat.tower_lift_speed.getFloat());
    p.retract_speed        = float(mat.tower_retract_speed.getFloat());

    p.wait_before_cure = float(mat.wait_before_cure.getFloat());
    p.wait_after_cure  = float(mat.wait_after_cure.getFloat());
    p.wait_after_lift  = float(mat.wait_after_lift.getFloat());

    p.light_pwm        = uint16_t(std::clamp(mat.light_pwm.getInt(), 1, 255));
    p.bottom_light_pwm = uint16_t(std::clamp(mat.bottom_light_pwm.getInt(), 1, 255));

    const Ctb::GrayscaleSettings grayscale = grayscale_settings(m_cfg);
    p.anti_alias_level = grayscale.antialiasing ? grayscale.level : 1;

    const SLAPrintStatistics stats = print.print_statistics();
    const double ml = (stats.objects_used_material + stats.support_used_material) / 1000.;
    const double bottle_volume = mat.bottle_volume.getFloat();
    double density = mat.material_density.getFloat();
    if (density <= 0. && bottle_volume > 0.)
        density = mat.bottle_weight.getFloat() * 1000. / bottle_volume;
    p.material_ml   = float(ml);
    p.material_g    = float(ml * density);
    p.material_cost = bottle_volume > 0. ? float(ml * mat.bottle_cost.getFloat() / bottle_volume) : 0.f;
    if (density > 0.)
        p.resin_density = float(density);

    p.machine_name = m_cfg.printer_model.value;
    // Name of the material preset, shown by the printer.
    for (const char *key : {"sla_material_settings_id", "material_type"}) {
        const auto *name = cfg.option<ConfigOptionString>(key);
        if (name && !name->value.empty()) {
            p.resin_profile_name = name->value;
            break;
        }
    }

    using namespace std::chrono;
    p.timestamp_minutes = uint32_t(duration_cast<minutes>(system_clock::now().time_since_epoch()).count());

    std::vector<std::vector<uint8_t>> layers;
    layers.reserve(m_layers.size());
    for (const sla::EncodedRaster &rst : m_layers) {
        const auto *data = static_cast<const uint8_t *>(rst.data());
        layers.emplace_back(data, data + rst.size());
    }

    // Chitubox stores the largest thumbnail as the large preview and the smallest one as the small preview.
    std::optional<Ctb::PreviewImage> large_preview, small_preview;
    const ThumbnailData *largest  = nullptr;
    const ThumbnailData *smallest = nullptr;
    for (const ThumbnailData &thumbnail : thumbnails) {
        if (!thumbnail.is_valid() || thumbnail.pixels.size() != size_t(thumbnail.width) * thumbnail.height * 4)
            continue;
        const auto area = [](const ThumbnailData *t) { return size_t(t->width) * t->height; };
        if (!largest || area(&thumbnail) > area(largest))
            largest = &thumbnail;
        if (!smallest || area(&thumbnail) < area(smallest))
            smallest = &thumbnail;
    }
    if (largest) {
        large_preview = to_preview(*largest);
        small_preview = to_preview(*smallest);
    } else {
        // No thumbnails rendered (e.g. command line export), the printer shows the previews in its file list.
        large_preview = Ctb::silhouette_preview(layers, p.resolution_x, p.resolution_y, 400, 300);
        small_preview = Ctb::silhouette_preview(layers, p.resolution_x, p.resolution_y, 200, 125);
    }

    try {
        boost::nowide::ofstream out(fname, std::ios::binary | std::ios::trunc);
        if (!out)
            throw RuntimeError("CTB: can't open file " + fname);
        Ctb::write_ctb(out, p, layers, large_preview, small_preview);
        out.close();
        if (!out)
            throw RuntimeError("CTB: failed to write file " + fname);
    } catch (std::exception &e) {
        BOOST_LOG_TRIVIAL(error) << e.what();
        throw;
    }
}

} // namespace Slic3r
