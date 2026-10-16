#include "SLAExposureView.hpp"

#include <algorithm>
#include <cmath>

#include <GL/glew.h>
#include <imgui/imgui.h>

#include "libslic3r/SLAPrint.hpp"
#include "slic3r/GUI/3DScene.hpp"
#include "slic3r/GUI/I18N.hpp"
#include "slic3r/GUI/ImGuiPureWrap.hpp"
#include "slic3r/GUI/format.hpp"

namespace Slic3r {
namespace GUI {

// Longest side of the texture. The display has up to 12K pixels, the pane shows a scaled down image.
static constexpr size_t MaxTextureSize = 2048;

std::vector<uint8_t> SLAExposureView::downscale_to_rgba(const std::vector<uint8_t> &gray, size_t width, size_t height,
                                                        size_t max_width, size_t max_height, size_t &out_width, size_t &out_height)
{
    out_width = out_height = 0;
    if (width == 0 || height == 0 || max_width == 0 || max_height == 0 || gray.size() != width * height)
        return {};

    const double scale = std::min({1., double(max_width) / width, double(max_height) / height});
    out_width  = std::max<size_t>(1, size_t(std::lround(width * scale)));
    out_height = std::max<size_t>(1, size_t(std::lround(height * scale)));

    // Box filter: each source pixel contributes to the destination pixel it falls into.
    std::vector<uint32_t> sum(out_width * out_height, 0);
    std::vector<uint32_t> count(out_width * out_height, 0);
    std::vector<size_t>   col_to_x(width);
    for (size_t col = 0; col < width; ++col)
        col_to_x[col] = std::min(out_width - 1, col * out_width / width);
    for (size_t row = 0; row < height; ++row) {
        const size_t   y   = std::min(out_height - 1, row * out_height / height);
        const uint8_t *src = gray.data() + row * width;
        uint32_t      *dst_sum   = sum.data() + y * out_width;
        uint32_t      *dst_count = count.data() + y * out_width;
        for (size_t col = 0; col < width; ++col) {
            dst_sum[col_to_x[col]] += src[col];
            ++dst_count[col_to_x[col]];
        }
    }

    std::vector<uint8_t> rgba(out_width * out_height * 4);
    for (size_t i = 0; i < sum.size(); ++i) {
        const uint8_t v = count[i] == 0 ? 0 : uint8_t((sum[i] + count[i] / 2) / count[i]);
        rgba[4 * i]     = v;
        rgba[4 * i + 1] = v;
        rgba[4 * i + 2] = v;
        rgba[4 * i + 3] = 255;
    }
    return rgba;
}

void SLAExposureView::update_texture(const SLAPrint &print, size_t layer_idx)
{
    m_layer_idx = layer_idx;
    m_has_image = false;

    const SLAArchiveWriter::LayerImage image = print.layer_exposure_image(layer_idx);
    if (image.empty())
        return;

    size_t w = 0, h = 0;
    const std::vector<uint8_t> rgba = downscale_to_rgba(image.pixels, image.width, image.height,
                                                        MaxTextureSize, MaxTextureSize, w, h);
    if (rgba.empty())
        return;

    if (m_texture_id == 0)
        glsafe(::glGenTextures(1, &m_texture_id));
    glsafe(::glPixelStorei(GL_UNPACK_ALIGNMENT, 1));
    glsafe(::glBindTexture(GL_TEXTURE_2D, m_texture_id));
    glsafe(::glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, GLsizei(w), GLsizei(h), 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba.data()));
    glsafe(::glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR));
    glsafe(::glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR));
    glsafe(::glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0));
    glsafe(::glBindTexture(GL_TEXTURE_2D, 0));

    m_texture_width  = w;
    m_texture_height = h;
    m_image_width    = image.width;
    m_image_height   = image.height;
    m_has_image      = true;
}

void SLAExposureView::render(const SLAPrint &print, double z, float x, float y, float width, float height)
{
    std::optional<size_t> layer_idx;
    if (print.finished()) {
        layer_idx = print.layer_index_at_height(z);
        if (layer_idx && layer_idx != m_layer_idx)
            update_texture(print, *layer_idx);
    } else
        // The layers are being rasterized, the cached image may not match the print anymore.
        invalidate();

    ImGuiPureWrap::set_next_window_pos(x, y, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(width, height), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(1.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
    ImGuiPureWrap::begin(_u8L("Exposure (printer screen)"),
                         ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                         ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoFocusOnAppearing |
                         ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
                         ImGuiWindowFlags_NoSavedSettings);

    if (!layer_idx) {
        ImGui::TextUnformatted(_u8L("The exposure image is shown when slicing is finished.").c_str());
    } else {
        ImGui::Text("%s", GUI::format(_u8L("Layer %1% of %2%"), *layer_idx + 1, print.print_layers().size()).c_str());
        if (m_has_image && m_texture_width > 0 && m_texture_height > 0) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", GUI::format("%1% x %2% px", m_image_width, m_image_height).c_str());

            // Fit the image into the rest of the pane, keeping the aspect ratio of the display, centered.
            const ImVec2 avail = ImGui::GetContentRegionAvail();
            if (avail.x > 1.f && avail.y > 1.f) {
                const float  scale = std::min(avail.x / float(m_texture_width), avail.y / float(m_texture_height));
                const ImVec2 size(float(m_texture_width) * scale, float(m_texture_height) * scale);
                const ImVec2 cursor = ImGui::GetCursorPos();
                ImGui::SetCursorPos(ImVec2(cursor.x + 0.5f * (avail.x - size.x), cursor.y + 0.5f * (avail.y - size.y)));
                // The border shows the extent of the display.
                ImGui::Image((ImTextureID)(intptr_t)m_texture_id, size, ImVec2(0, 0), ImVec2(1, 1),
                             ImVec4(1.f, 1.f, 1.f, 1.f), ImVec4(0.5f, 0.5f, 0.5f, 1.f));
            }
        } else {
            ImGui::TextUnformatted(_u8L("The exposure image is not available for this output format.").c_str());
        }
    }

    ImGuiPureWrap::end();
    ImGui::PopStyleVar();
}

} // namespace GUI
} // namespace Slic3r
