#pragma once

// "The same name" as SharePoint and OneDrive see it (W2.6 review): they
// compare file names case-insensitively across Unicode, not only A-Z, and
// restoreTo and copyTo drop the source path (restore-flow §12), so two files
// whose names share a key land on one file in the restore target. The
// sampler's same-name skip and restore_sample's same-name refusal both use
// this key, so the two always agree.

#include <string>
#include <string_view>

namespace rp {

// `text` (UTF-8) upper-cased as Windows' invariant locale does it
// (LCMapStringEx, LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE), in UTF-8. Text
// that isn't valid UTF-8 has A-Z upper-cased and every other byte kept, so
// its key stays invalid UTF-8 and never equals a valid name's.
std::string name_key(std::string_view text);

// name_key(a) == name_key(b).
bool same_name(std::string_view a, std::string_view b);

} // namespace rp
