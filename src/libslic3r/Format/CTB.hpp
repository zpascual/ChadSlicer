#ifndef SLIC3R_FORMAT_CTB_HPP
#define SLIC3R_FORMAT_CTB_HPP

#include <memory>
#include <string>

#include "SLAArchiveWriter.hpp"
#include "SLAArchiveFormatRegistry.hpp"
#include "libslic3r/PrintConfig.hpp"

namespace Slic3r {

// Writer of the Chitubox '.ctb' file format (encrypted, version 5) used by e.g. the Phrozen
// MSLA printers. The binary layout is implemented in CTBFormat.hpp.
class CTBArchive : public SLAArchiveWriter
{
    SLAPrinterConfig m_cfg;

protected:
    std::unique_ptr<sla::RasterBase> create_raster() const override;
    sla::RasterEncoder get_encoder() const override;

public:
    CTBArchive() = default;
    explicit CTBArchive(const SLAPrinterConfig &cfg) : m_cfg(cfg) {}
    explicit CTBArchive(SLAPrinterConfig &&cfg) : m_cfg(std::move(cfg)) {}

    void export_print(const std::string     fname,
                      const SLAPrint       &print,
                      const ThumbnailsList &thumbnails,
                      const std::string    &projectname = "") override;

    LayerImage decode_layer(size_t layer_idx) const override;
};

inline ArchiveEntry ctb_format()
{
    ArchiveEntry entry("CTB");
    entry.desc        = "Chitubox CTB";
    entry.ext         = "ctb";
    entry.wrfactoryfn = [](const auto &cfg) { return std::make_unique<CTBArchive>(cfg); };
    return entry;
}

} // namespace Slic3r

#endif // SLIC3R_FORMAT_CTB_HPP
