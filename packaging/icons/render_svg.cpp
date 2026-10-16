// Render an SVG to an RGBA PNG with NanoSVG, the SVG renderer used by the application itself.
// Build: c++ -std=c++17 -O2 -I <deps>/usr/local/include render_svg.cpp -lz -o render_svg
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <zlib.h>
#define NANOSVG_IMPLEMENTATION
#include <nanosvg/nanosvg.h>
#define NANOSVGRAST_IMPLEMENTATION
#include <nanosvg/nanosvgrast.h>

static void put32(std::vector<unsigned char>& v, unsigned x) { for (int i = 3; i >= 0; --i) v.push_back((x >> (8 * i)) & 255); }
static void chunk(FILE* f, const char* type, const std::vector<unsigned char>& data) {
    std::vector<unsigned char> buf; put32(buf, (unsigned)data.size());
    buf.insert(buf.end(), type, type + 4); buf.insert(buf.end(), data.begin(), data.end());
    unsigned crc = crc32(0, buf.data() + 4, (uInt)(buf.size() - 4)); put32(buf, crc);
    fwrite(buf.data(), 1, buf.size(), f);
}
int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: render in.svg out.png size\n"); return 1; }
    const int size = atoi(argv[3]);
    NSVGimage* img = nsvgParseFromFile(argv[1], "px", 96.f);
    if (!img) return 2;
    std::vector<unsigned char> rgba(size * size * 4);
    NSVGrasterizer* r = nsvgCreateRasterizer();
    nsvgRasterize(r, img, 0, 0, size / img->width, rgba.data(), size, size, size * 4);
    std::vector<unsigned char> raw;
    for (int y = 0; y < size; ++y) { raw.push_back(0); raw.insert(raw.end(), rgba.begin() + y * size * 4, rgba.begin() + (y + 1) * size * 4); }
    uLongf len = compressBound(raw.size()); std::vector<unsigned char> z(len);
    compress2(z.data(), &len, raw.data(), raw.size(), 9); z.resize(len);
    FILE* f = fopen(argv[2], "wb"); const unsigned char sig[8] = {137, 80, 78, 71, 13, 10, 26, 10}; fwrite(sig, 1, 8, f);
    std::vector<unsigned char> ihdr; put32(ihdr, size); put32(ihdr, size); ihdr.insert(ihdr.end(), {8, 6, 0, 0, 0});
    chunk(f, "IHDR", ihdr); chunk(f, "IDAT", z); chunk(f, "IEND", {}); fclose(f);
    return 0;
}
