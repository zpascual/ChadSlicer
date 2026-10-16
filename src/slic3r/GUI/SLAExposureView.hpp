#ifndef slic3r_SLAExposureView_hpp_
#define slic3r_SLAExposureView_hpp_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace Slic3r {

class SLAPrint;

namespace GUI {

// Top view of the exposure of the selected SLA layer: the image of the layer as written to the
// output archive (what the printer shows on its display), drawn as an ImGui pane next to the
// 3D scene of the preview.
class SLAExposureView
{
public:
    SLAExposureView() = default;
    SLAExposureView(const SLAExposureView &) = delete;
    SLAExposureView &operator=(const SLAExposureView &) = delete;

    // Forget the cached layer, e.g. when the print was sliced again.
    void invalidate() { m_layer_idx.reset(); m_has_image = false; }

    // Render the pane into the given rectangle of the canvas. z is the height of the selected layer (mm).
    // Has to be called from the render loop with the OpenGL context current.
    // The texture is reused for all the layers and released together with the OpenGL context.
    void render(const SLAPrint &print, double z, float x, float y, float width, float height);

    // Downscale a grayscale image to fit into max_width x max_height by averaging the covered pixels,
    // keeping the aspect ratio. Output is RGBA with the exposure shown white on black.
    static std::vector<uint8_t> downscale_to_rgba(const std::vector<uint8_t> &gray, size_t width, size_t height,
                                                  size_t max_width, size_t max_height, size_t &out_width, size_t &out_height);

private:
    void update_texture(const SLAPrint &print, size_t layer_idx);

    std::optional<size_t> m_layer_idx;
    bool                  m_has_image{false};
    unsigned int          m_texture_id{0};
    size_t                m_texture_width{0};
    size_t                m_texture_height{0};
    size_t                m_image_width{0};
    size_t                m_image_height{0};
};

} // namespace GUI
} // namespace Slic3r

#endif // slic3r_SLAExposureView_hpp_
