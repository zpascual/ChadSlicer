#include <catch2/catch_test_macros.hpp>

#include "slic3r/GUI/SLAExposureView.hpp"

using Slic3r::GUI::SLAExposureView;

TEST_CASE("SLA exposure view downscaling", "[SLAExposureView]")
{
    size_t w = 0, h = 0;

    SECTION("aspect ratio is kept and the image fits") {
        const std::vector<uint8_t> gray(7680 * 4320, 0);
        const std::vector<uint8_t> rgba = SLAExposureView::downscale_to_rgba(gray, 7680, 4320, 1024, 1024, w, h);
        CHECK(w == 1024);
        CHECK(h == 576);
        CHECK(rgba.size() == w * h * 4);
    }

    SECTION("small images are not upscaled") {
        const std::vector<uint8_t> gray(4 * 2, 255);
        const std::vector<uint8_t> rgba = SLAExposureView::downscale_to_rgba(gray, 4, 2, 1024, 1024, w, h);
        CHECK(w == 4);
        CHECK(h == 2);
        CHECK(rgba == std::vector<uint8_t>(4 * 2 * 4, 255));
    }

    SECTION("pixels are averaged") {
        // 4x2 px: left half exposed, right half dark -> 2x1 px: white, black.
        const std::vector<uint8_t> gray{255, 255, 0, 0,
                                        255, 255, 0, 0};
        const std::vector<uint8_t> rgba = SLAExposureView::downscale_to_rgba(gray, 4, 2, 2, 2, w, h);
        REQUIRE(w == 2);
        REQUIRE(h == 1);
        CHECK(rgba == std::vector<uint8_t>{255, 255, 255, 255, 0, 0, 0, 255});

        // Partially exposed block gives gray.
        const std::vector<uint8_t> half{255, 0, 0, 0};
        const std::vector<uint8_t> avg = SLAExposureView::downscale_to_rgba(half, 2, 2, 1, 1, w, h);
        REQUIRE(avg.size() == 4);
        CHECK(int(avg[0]) == 64);
    }

    SECTION("invalid input gives an empty image") {
        CHECK(SLAExposureView::downscale_to_rgba({}, 0, 0, 10, 10, w, h).empty());
        CHECK(SLAExposureView::downscale_to_rgba(std::vector<uint8_t>(3), 2, 2, 10, 10, w, h).empty());
    }
}
