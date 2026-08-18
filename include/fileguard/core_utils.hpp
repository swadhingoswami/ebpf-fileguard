#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace fileguard {

// Result<T> is the error channel used across the project. Errors are always
// human-readable messages; callers must handle them explicitly.
template <typename T>
using Result = std::expected<T, std::string>;

using ResultVoid = Result<std::monostate>;

template <typename T>
Result<T> ok(T value) {
    return std::expected<T, std::string>(std::move(value));
}

inline ResultVoid ok_v() {
    return ResultVoid(std::monostate{});
}

// Returns an `unexpected<string>`; implicit conversion makes `return err("..")`
// work in any function returning Result<T>.
inline auto err(std::string message) {
    return std::unexpected<std::string>(std::move(message));
}

[[nodiscard]] inline std::string trim(std::string_view s) {
    const auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    const auto end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(begin, end - begin + 1));
}

}  // namespace fileguard
