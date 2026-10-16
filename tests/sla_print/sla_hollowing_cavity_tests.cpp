#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include <libslic3r/SLA/Hollowing.hpp>
#include <libslic3r/TriangleMesh.hpp>

using namespace Slic3r;
using Catch::Approx;

namespace {

indexed_triangle_set cube_at(double size, double x)
{
    indexed_triangle_set cube = its_make_cube(size, size, size);
    its_translate(cube, Vec3f(float(x), 0.f, 0.f));
    return cube;
}

} // namespace

TEST_CASE("Keep the largest cavity of an interior mesh", "[Hollowing]")
{
    indexed_triangle_set mesh = cube_at(20., 0.);
    its_merge(mesh, cube_at(10., 50.));
    its_merge(mesh, cube_at(5., 100.));
    REQUIRE(its_split(mesh).size() == 3);

    CHECK(sla::keep_largest_cavity(mesh) == 2);
    CHECK(its_split(mesh).size() == 1);
    CHECK(std::abs(its_volume(mesh)) == Approx(20. * 20. * 20.));

    // A single cavity is not changed.
    CHECK(sla::keep_largest_cavity(mesh) == 0);
    CHECK(std::abs(its_volume(mesh)) == Approx(20. * 20. * 20.));

    indexed_triangle_set empty;
    CHECK(sla::keep_largest_cavity(empty) == 0);
}

TEST_CASE("Hollowing two separate bodies keeps the main cavity only", "[Hollowing]")
{
    // An object made of two separate cubes is hollowed into two cavities.
    indexed_triangle_set mesh = cube_at(20., 0.);
    its_merge(mesh, cube_at(10., 40.));

    sla::HollowingConfig cfg;
    cfg.min_thickness    = 2.;
    cfg.closing_distance = 0.;
    sla::InteriorPtr interior = sla::generate_interior(mesh, cfg);
    REQUIRE(interior);
    indexed_triangle_set &cavities = sla::get_mesh(*interior);
    REQUIRE(its_split(cavities).size() == 2);

    sla::keep_largest_cavity(cavities);
    REQUIRE(its_split(cavities).size() == 1);
    // The cavity of the large cube, its walls are 2 mm thick.
    CHECK(std::abs(its_volume(cavities)) == Approx(16. * 16. * 16.).epsilon(0.05));
}
