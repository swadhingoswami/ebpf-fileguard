#include "fileguard/path_resolver.hpp"

namespace fileguard {

void PathResolver::add(FileId id, std::string path) {
    map_[id] = std::move(path);
}

std::string PathResolver::resolve(FileId id) const {
    const auto it = map_.find(id);
    if (it != map_.end()) {
        return it->second;
    }
    return id.to_string();
}

}  // namespace fileguard
