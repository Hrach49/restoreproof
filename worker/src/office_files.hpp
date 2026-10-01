#pragma once

// The one rule for the Office files SharePoint rewrites (docs/decisions.md
// 2026-10-01, W3.1 point 5, and the W3.1 code review's live check): their
// stored bytes and size may differ from what was uploaded or backed up. The
// Graph reader reads them up to the download limit (graph_targets.cpp), the
// expected set takes no size for them (expected_set.cpp), and a canary of
// such a name must use office-v1 (canary_manifest.cpp).

#include "text_util.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace rp {

// The Office Open XML family (Word, Excel and PowerPoint documents, macro
// documents, templates and shows), the binary Excel workbook (.xlsb) and the
// legacy Word, Excel and PowerPoint files (.doc, .xls, .ppt). The live check of
// 2026-10-01 saw SharePoint rewrite docx, docm, xlsx, xlsm, pptx, pptm, xlsb,
// doc, xls and ppt, and leave Visio (vsdx, vsdm, vssx, vstx), the add-ins
// (xlam, ppam), ODF, pdf, rtf and txt as uploaded; OneDrive rewrote none.
inline constexpr std::array<std::string_view, 18> kRewrittenOfficeExtensions{
    ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb",
    ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".doc",  ".xls",  ".ppt"};

// Whether `file_name` ends in one of them, ASCII case-insensitive, with
// something before it: a name that is only an extension (".docx") isn't one.
inline bool is_rewritten_office_file(std::string_view file_name)
{
    return std::ranges::any_of(kRewrittenOfficeExtensions, [file_name](std::string_view extension) {
        return ascii_ends_with_i(file_name, extension);
    });
}

} // namespace rp
