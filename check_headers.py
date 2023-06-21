# SPDX-License-Identifier: MIT
# Copyright 2020 (c), H2O.ai
import glob
import os
import re
import sys
from typing import Literal

c_extensions = [".c", ".cc", ".cxx", ".cpp", ".c++"]
h_extensions = [".h", ".hh", ".hxx", ".hpp", ".h++"]
all_extensions = c_extensions + h_extensions


# Mapping of C++ symbols into the list of header files where each symbol is defined. If
# a symbol is defined in multiple headers, then the first header in the list should be
# the "most canonical" header. If no such canonical header exists, then put "?" as the
# first entry in the list.
#
# Use `d = std_symbols_library; {k: d[k] for k in sorted(d)}` to sort keys.
#
std_symbols_library: dict[str, list[str]] = {
    "int16_t": ["cstdint"],
    "int32_t": ["cstdint"],
    "int64_t": ["cstdint"],
    "int8_t": ["cstdint"],
    "int_fast16_t": ["cstdint"],
    "int_fast32_t": ["cstdint"],
    "int_fast64_t": ["cstdint"],
    "int_fast8_t": ["cstdint"],
    "int_least16_t": ["cstdint"],
    "int_least32_t": ["cstdint"],
    "int_least64_t": ["cstdint"],
    "int_least8_t": ["cstdint"],
    "intmax_t": ["cstdint"],
    "intptr_t": ["cstdint"],
    "size_t": ["cstddef", "cstdio", "cstdlib", "cstring", "ctime"],
    "std::FILE": ["cstdio"],
    "std::abort": ["cstdlib"],
    "std::abs": ["cstdlib", "cmath", "complex", "valarray"],
    "std::accumulate": ["numeric"],
    "std::acos": ["cmath"],
    "std::acosh": ["cmath"],
    "std::add_const": ["type_traits"],
    "std::add_cv": ["type_traits"],
    "std::add_lvalue_reference": ["type_traits"],
    "std::add_pointer": ["type_traits"],
    "std::add_rvalue_reference": ["type_traits"],
    "std::add_volatile": ["type_traits"],
    "std::addressof": ["memory"],
    "std::adjacent_find": ["algorithm"],
    "std::adopt_lock": ["mutex"],
    "std::adopt_lock_t": ["mutex"],
    "std::align": ["memory"],
    "std::aligned_alloc": ["cstdlib"],
    "std::aligned_storage": ["type_traits"],
    "std::all_of": ["algorithm"],
    "std::allocator": ["memory"],
    "std::allocator_traits": ["memory"],
    "std::any_of": ["algorithm"],
    "std::array": ["array"],
    "std::asin": ["cmath"],
    "std::asinh": ["cmath"],
    "std::atan": ["cmath"],
    "std::atan2": ["cmath"],
    "std::atanh": ["cmath"],
    "std::atomic": ["atomic"],
    "std::atomic_flag": ["atomic"],
    "std::bad_alloc": ["new"],
    "std::bad_function_call": ["functional"],
    "std::bad_optional_access": ["optional"],
    "std::bad_variant_access": ["variant"],
    "std::basic_ostream": ["ostream"],
    "std::begin": [
        "array",
        "deque",
        "forward_list",
        "iterator",
        "list",
        "map",
        "regex",
        "set",
        "span",
        "string",
        "string_view",
        "unordered_map",
        "unordered_set",
        "vector",
    ],
    "std::bidirectional_iterator_tag": ["iterator"],
    "std::binary_search": ["algorithm"],
    "std::bitset": ["bitset"],
    "std::bsearch": ["cstdlib"],
    "std::calloc": ["cstdlib"],
    "std::cbrt": ["cmath"],
    "std::ceil": ["cmath"],
    "std::ceilf": ["cmath"],
    "std::ceill": ["cmath"],
    "std::cerr": ["iostream"],
    "std::chrono": ["chrono"],
    "std::cin": ["iostream"],
    "std::clamp": ["algorithm"],
    "std::clog": ["iostream"],
    "std::common_reference": ["type_traits"],
    "std::common_type": ["type_traits"],
    "std::condition_variable": ["condition_variable"],
    "std::condition_variable_any": ["condition_variable"],
    "std::conditional": ["type_traits"],
    "std::conditional_t": ["type_traits"],
    "std::contiguous_iterator_tag": ["iterator"],
    "std::copy": ["algorithm"],
    "std::copy_backward": ["algorithm"],
    "std::copy_if": ["algorithm"],
    "std::copy_n": ["algorithm"],
    "std::copysign": ["cmath"],
    "std::copysignf": ["cmath"],
    "std::copysignl": ["cmath"],
    "std::cos": ["cmath"],
    "std::cosf": ["cmath"],
    "std::cosh": ["cmath"],
    "std::cosl": ["cmath"],
    "std::count": ["algorithm"],
    "std::count_if": ["algorithm"],
    "std::cout": ["iostream"],
    "std::current_exception": ["exception"],
    "std::dec": ["ios"],
    "std::decay": ["type_traits"],
    "std::declval": ["utility"],
    "std::default_random_engine": ["random"],
    "std::defer_lock": ["mutex"],
    "std::defer_lock_t": ["mutex"],
    "std::distance": ["iterator"],
    "std::domain_error": ["stdexcept"],
    "std::dynamic_extent": ["span"],
    "std::enable_if": ["type_traits"],
    "std::enable_shared_from_this": ["memory"],
    "std::end": [
        "array",
        "deque",
        "forward_list",
        "iterator",
        "list",
        "map",
        "regex",
        "set",
        "span",
        "string",
        "string_view",
        "unordered_map",
        "unordered_set",
        "vector",
    ],
    "std::endl": ["ostream"],
    "std::ends": ["ostream"],
    "std::equal": ["algorithm"],
    "std::equal_range": ["algorithm"],
    "std::equal_to": ["functional"],
    "std::erf": ["cmath"],
    "std::erfc": ["cmath"],
    "std::exception": ["exception"],
    "std::exception_ptr": ["exception"],
    "std::exp": ["cmath"],
    "std::exp2": ["cmath"],
    "std::expm1": ["cmath"],
    "std::fabs": ["cmath", "cstdlib"],
    "std::fabsf": ["cmath", "cstdlib"],
    "std::fabsl": ["cmath", "cstdlib"],
    "std::false_type": ["type_traits"],
    "std::fclose": ["cstdio"],
    "std::fill": ["algorithm"],
    "std::fill_n": ["algorithm"],
    "std::find": ["algorithm"],
    "std::find_end": ["algorithm"],
    "std::find_first_of": ["algorithm"],
    "std::find_if": ["algorithm"],
    "std::find_if_not": ["algorithm"],
    "std::fixed": ["ios"],
    "std::floor": ["cmath"],
    "std::floorf": ["cmath"],
    "std::floorl": ["cmath"],
    "std::flush": ["ostream"],
    "std::fmod": ["cmath"],
    "std::fmodf": ["cmath"],
    "std::fmodl": ["cmath"],
    "std::fopen": ["cstdio"],
    "std::for_each": ["algorithm"],
    "std::for_each_n": ["algorithm"],
    "std::forward": ["utility"],
    "std::forward_as_tuple": ["tuple"],
    "std::forward_iterator_tag": ["iterator"],
    "std::fprintf": ["cstdio"],
    "std::free": ["cstdlib"],
    "std::function": ["functional"],
    "std::future": ["future"],
    "std::generate": ["algorithm"],
    "std::generate_n": ["algorithm"],
    "std::get": ["?", "array", "tuple", "utility", "variant"],
    "std::get_if": ["variant"],
    "std::hash": ["functional"],
    "std::hex": ["ios"],
    "std::holds_alternative": ["variant"],
    "std::hypot": ["cmath"],
    "std::in_place": ["utility"],
    "std::in_place_index": ["utility"],
    "std::in_place_index_t": ["utility"],
    "std::in_place_t": ["utility"],
    "std::in_place_type": ["utility"],
    "std::in_place_type_t": ["utility"],
    "std::includes": ["algorithm"],
    "std::initializer_list": ["initializer_list"],
    "std::inplace_merge": ["algorithm"],
    "std::input_iterator_tag": ["iterator"],
    "std::integral_constant": ["type_traits"],
    "std::invalid_argument": ["stdexcept"],
    "std::iota": ["numeric"],
    "std::is_array": ["type_traits"],
    "std::is_assignable": ["type_traits"],
    "std::is_base_of": ["type_traits"],
    "std::is_class": ["type_traits"],
    "std::is_const": ["type_traits"],
    "std::is_constructible": ["type_traits"],
    "std::is_convertible": ["type_traits"],
    "std::is_copy_constructible": ["type_traits"],
    "std::is_default_constructible": ["type_traits"],
    "std::is_destructible": ["type_traits"],
    "std::is_empty": ["type_traits"],
    "std::is_enum": ["type_traits"],
    "std::is_floating_point": ["type_traits"],
    "std::is_function": ["type_traits"],
    "std::is_heap": ["algorithm"],
    "std::is_heap_until": ["algorithm"],
    "std::is_integral": ["type_traits"],
    "std::is_lvalue_reference": ["type_traits"],
    "std::is_move_constructible": ["type_traits"],
    "std::is_nothrow_copy_constructible": ["type_traits"],
    "std::is_nothrow_default_constructible": ["type_traits"],
    "std::is_nothrow_destructible": ["type_traits"],
    "std::is_nothrow_move_assignable": ["type_traits"],
    "std::is_nothrow_move_constructible": ["type_traits"],
    "std::is_null_pointer": ["type_traits"],
    "std::is_object": ["type_traits"],
    "std::is_partitioned": ["algorithm"],
    "std::is_permutation": ["algorithm"],
    "std::is_place_t": ["utility"],
    "std::is_pointer": ["type_traits"],
    "std::is_reference": ["type_traits"],
    "std::is_rvalue_reference": ["type_traits"],
    "std::is_same": ["type_traits"],
    "std::is_scalar": ["type_traits"],
    "std::is_signed": ["type_traits"],
    "std::is_sorted": ["algorithm"],
    "std::is_sorted_until": ["algorithm"],
    "std::is_standard_layout": ["type_traits"],
    "std::is_trivial": ["type_traits"],
    "std::is_trivially_copy_assignable": ["type_traits"],
    "std::is_trivially_copy_constructible": ["type_traits"],
    "std::is_trivially_default_constructible": ["type_traits"],
    "std::is_trivially_destructible": ["type_traits"],
    "std::is_union": ["type_traits"],
    "std::is_unsigned": ["type_traits"],
    "std::is_void": ["type_traits"],
    "std::is_volatile": ["type_traits"],
    "std::isfinite": ["cmath"],
    "std::isinf": ["cmath"],
    "std::isnan": ["cmath"],
    "std::iter_swap": ["algorithm"],
    "std::ldexp": ["cmath"],
    "std::ldexpf": ["cmath"],
    "std::ldexpl": ["cmath"],
    "std::length_error": ["stdexcept"],
    "std::lexicographical_compare": ["algorithm"],
    "std::lexicographical_compare_three_way": ["algorithm"],
    "std::lgamma": ["cmath"],
    "std::localtime": ["ctime"],
    "std::lock": ["mutex"],
    "std::lock_guard": ["mutex"],
    "std::log": ["cmath"],
    "std::log10": ["cmath"],
    "std::log1p": ["cmath"],
    "std::log2": ["cmath"],
    "std::logic_error": ["stdexcept"],
    "std::lower_bound": ["algorithm"],
    "std::lrint": ["cmath"],
    "std::lrintf": ["cmath"],
    "std::lrintl": ["cmath"],
    "std::make_heap": ["algorithm"],
    "std::make_optional": ["optional"],
    "std::make_pair": ["utility"],
    "std::make_shared": ["memory"],
    "std::make_signed": ["type_traits"],
    "std::make_tuple": ["tuple"],
    "std::make_unique": ["memory"],
    "std::make_unsigned": ["type_traits"],
    "std::malloc": ["cstdlib"],
    "std::map": ["map"],
    "std::max": ["algorithm"],
    "std::max_element": ["algorithm"],
    "std::memcmp": ["cstring"],
    "std::memcpy": ["cstring"],
    "std::memmove": ["cstring"],
    "std::memory_order": ["atomic"],
    "std::memory_order_acq_rel": ["atomic"],
    "std::memory_order_acquire": ["atomic"],
    "std::memory_order_consume": ["atomic"],
    "std::memory_order_relaxed": ["atomic"],
    "std::memory_order_release": ["atomic"],
    "std::memory_order_seq_cst": ["atomic"],
    "std::memset": ["cstring"],
    "std::merge": ["algorithm"],
    "std::min": ["algorithm"],
    "std::min_element": ["algorithm"],
    "std::minmax": ["algorithm"],
    "std::minmax_element": ["algorithm"],
    "std::mismatch": ["algorithm"],
    "std::monostate": ["variant"],
    "std::move": ["utility", "algorithm"],
    "std::move_backward": ["algorithm"],
    "std::mt19937": ["random"],
    "std::mutex": ["mutex"],
    "std::nan": ["cmath"],
    "std::nanf": ["cmath"],
    "std::nanl": ["cmath"],
    "std::next": ["iterator"],
    "std::next_permutation": ["algorithm"],
    "std::nextafter": ["cmath"],
    "std::nextafterf": ["cmath"],
    "std::nextafterl": ["cmath"],
    "std::nexttoward": ["cmath"],
    "std::nexttowardf": ["cmath"],
    "std::nexttowardl": ["cmath"],
    "std::none_of": ["algorithm"],
    "std::normal_distribution": ["random"],
    "std::nth_element": ["algorithm"],
    "std::nullopt": ["optional"],
    "std::nullopt_t": ["optional"],
    "std::nullptr_t": ["cstddef"],
    "std::numeric_limits": ["limits"],
    "std::optional": ["optional"],
    "std::ostream": ["ostream"],
    "std::ostringstream": ["sstream"],
    "std::out_of_range": ["stdexcept"],
    "std::output_iterator_tag": ["iterator"],
    "std::overflow_error": ["stdexcept"],
    "std::packaged_task": ["future"],
    "std::pair": ["utility"],
    "std::partial_sort": ["algorithm"],
    "std::partial_sort_copy": ["algorithm"],
    "std::partition": ["algorithm"],
    "std::partition_copy": ["algorithm"],
    "std::partition_point": ["algorithm"],
    "std::perror": ["cstdio"],
    "std::piecewise_construct": ["utility"],
    "std::piecewise_construct_t": ["utility"],
    "std::pop_heap": ["algorithm"],
    "std::pow": ["cmath"],
    "std::prev_permutation": ["algorithm"],
    "std::printf": ["cstdio"],
    "std::ptrdiff_t": ["cstddef"],
    "std::push_heap": ["algorithm"],
    "std::rand": ["cstdlib"],
    "std::random_access_iterator_tag": ["iterator"],
    "std::random_device": ["random"],
    "std::random_shuffle": ["algorithm"],
    "std::range_error": ["stdexcept"],
    "std::ranges": ["algorithm"],
    "std::realloc": ["cstdlib"],
    "std::recursive_mutex": ["mutex"],
    "std::regex": ["regex"],
    "std::regex_error": ["regex"],
    "std::regex_match": ["regex"],
    "std::remove": ["?", "algorithm", "cstdio"],
    "std::remove_all_extents": ["type_traits"],
    "std::remove_const": ["type_traits"],
    "std::remove_copy": ["algorithm"],
    "std::remove_copy_if": ["algorithm"],
    "std::remove_cv": ["type_traits"],
    "std::remove_extent": ["type_traits"],
    "std::remove_if": ["algorithm"],
    "std::remove_pointer": ["type_traits"],
    "std::remove_reference": ["type_traits"],
    "std::remove_volatile": ["type_traits"],
    "std::replace": ["algorithm"],
    "std::replace_copy": ["algorithm"],
    "std::replace_copy_if": ["algorithm"],
    "std::replace_if": ["algorithm"],
    "std::result_of": ["type_traits"],
    "std::rethrow_exception": ["exception"],
    "std::reverse": ["algorithm"],
    "std::reverse_copy": ["algorithm"],
    "std::reverse_iterator": ["iterator"],
    "std::rint": ["cmath"],
    "std::rintf": ["cmath"],
    "std::rintl": ["cmath"],
    "std::rotate": ["algorithm"],
    "std::rotate_copy": ["algorithm"],
    "std::rundom_shuffle": ["algorithm"],
    "std::runtime_error": ["stdexcept"],
    "std::sample": ["algorithm"],
    "std::search": ["algorithm"],
    "std::search_n": ["algorithm"],
    "std::set": ["set"],
    "std::set_difference": ["algorithm"],
    "std::set_intersection": ["algorithm"],
    "std::set_symmetric_difference": ["algorithm"],
    "std::set_union": ["algorithm"],
    "std::setbase": ["iomanip"],
    "std::setfill": ["iomanip"],
    "std::setprecision": ["iomanip"],
    "std::setw": ["iomanip"],
    "std::shared_lock": ["shared_mutex"],
    "std::shared_mutex": ["shared_mutex"],
    "std::shared_ptr": ["memory"],
    "std::shift_left": ["algorithm"],
    "std::shift_right": ["algorithm"],
    "std::shuffle": ["algorithm"],
    "std::sig_atomic_t": ["csignal"],
    "std::signal": ["csignal"],
    "std::signbit": ["cmath"],
    "std::sin": ["cmath"],
    "std::sinf": ["cmath"],
    "std::sinh": ["cmath"],
    "std::sinl": ["cmath"],
    "std::size_t": ["cstddef", "cstdio", "cstdlib", "cstring", "ctime"],
    "std::snprintf": ["cstdio"],
    "std::sort": ["algorithm"],
    "std::sort_heap": ["algorithm"],
    "std::span": ["span"],
    "std::sprintf": ["cstdio"],
    "std::sqrt": ["cmath"],
    "std::sqrtf": ["cmath"],
    "std::sqrtl": ["cmath"],
    "std::srand": ["cstdlib"],
    "std::stable_partition": ["algorithm"],
    "std::stable_sort": ["algorithm"],
    "std::stack": ["stack"],
    "std::strcmp": ["cstring"],
    "std::strerror": ["cstring"],
    "std::string": ["string"],
    "std::string_view": ["string_view"],
    "std::stringstream": ["sstream"],
    "std::strlen": ["cstring"],
    "std::strncmp": ["cstring"],
    "std::strncpy": ["cstring"],
    "std::strrchr": ["cstring"],
    "std::swap": ["utility", "algorithm", "string_view"],
    "std::swap_ranges": ["algorithm"],
    "std::tan": ["cmath"],
    "std::tanf": ["cmath"],
    "std::tanh": ["cmath"],
    "std::tanhf": ["cmath"],
    "std::tanhl": ["cmath"],
    "std::tanl": ["cmath"],
    "std::tgamma": ["cmath"],
    "std::this_thread": ["thread"],
    "std::thread": ["thread"],
    "std::tie": ["tuple"],
    "std::time": ["ctime"],
    "std::time_t": ["ctime"],
    "std::tm": ["ctime"],
    "std::to_address": ["memory"],
    "std::to_string": ["string"],
    "std::tr1": [],
    "std::transform": ["algorithm"],
    "std::true_type": ["type_traits"],
    "std::trunc": ["cmath"],
    "std::try_to_lock": ["mutex"],
    "std::try_to_lock_t": ["mutex"],
    "std::tuple": ["tuple"],
    "std::tuple_element": ["tuple", "array", "utility"],
    "std::tuple_size": ["tuple", "array", "utility"],
    "std::uncaught_exception": ["exception"],
    "std::underflow_error": ["stdexcept"],
    "std::underlying_type": ["type_traits"],
    "std::uniform_int_distribution": ["random"],
    "std::unique": ["algorithm"],
    "std::unique_copy": ["algorithm"],
    "std::unique_lock": ["mutex"],
    "std::unique_ptr": ["memory"],
    "std::unordered_map": ["unordered_map"],
    "std::unordered_set": ["unordered_set"],
    "std::upper_bound": ["algorithm"],
    "std::variant": ["variant"],
    "std::variant_alternative": ["variant"],
    "std::variant_alternative_t": ["variant"],
    "std::variant_npos": ["variant"],
    "std::variant_size": ["variant"],
    "std::variant_size_v": ["variant"],
    "std::vector": ["vector"],
    "std::visit": ["variant"],
    "std::wcerr": ["iostream"],
    "std::wcin": ["iostream"],
    "std::wclog": ["iostream"],
    "std::wcout": ["iostream"],
    "std::weak_ptr": ["memory"],
    "std::wostream": ["ostream"],
    "uint16_t": ["cstdint"],
    "uint32_t": ["cstdint"],
    "uint64_t": ["cstdint"],
    "uint8_t": ["cstdint"],
    "uint_fast16_t": ["cstdint"],
    "uint_fast32_t": ["cstdint"],
    "uint_fast64_t": ["cstdint"],
    "uint_fast8_t": ["cstdint"],
    "uint_least16_t": ["cstdint"],
    "uint_least32_t": ["cstdint"],
    "uint_least64_t": ["cstdint"],
    "uint_least8_t": ["cstdint"],
    "uintmax_t": ["cstdint"],
    "uintptr_t": ["cstdint"],
}


Status = Literal[None, "string", "rstring", "comment"]


class Source:
    def __init__(self, path: str):
        self._path = path
        self._lines: list[str] = []
        self._sys_includes_base: list[str] = []
        self._src_includes_base: list[str] = []
        self._sys_includes_resolved: set[str] | None = None
        self._std_symbols: set[str] | None = None
        self.read_source(path)
        self.remove_comments()
        self.find_includes()

    def read_source(self, filename: str) -> None:
        with open(filename, "rt") as inp:
            self._lines = [line.strip() for line in inp]

    def remove_comments(self) -> None:
        """
        Removes all comments, strings, and R-strings in the file, so that we wouldn't
        accidentally find C++ symbols in them.
        """

        def process_line(line: str, status: Status):
            if status is None:
                return process_linestart(line)
            elif status == "string":
                return process_string("", line, '"')
            elif status == "rstring":
                return process_rstring("", line)
            elif status == "comment":
                return process_comment("", line)
            else:
                raise RuntimeError(status)

        def process_linestart(line: str) -> tuple[str, Status]:
            match = re.match(r'^\s*#\s*include\s*(".*?"|<.*?>)', line)
            if match:
                i = match.end()
                return process_normal(line[:i], line[i:])
            else:
                return process_normal("", line)

        def process_normal(prefix: str, line: str) -> tuple[str, Status]:
            for i, ch in enumerate(line):
                if ch == '"':
                    return process_string(prefix + line[: i + 1], line[i + 1 :], ch)
                if ch == "'":
                    return process_string(prefix + line[: i + 1], line[i + 1 :], ch)
                if ch == "/":
                    nextch = line[i + 1 : i + 2]
                    if nextch == "/":
                        return (prefix + line[:i], None)
                    if nextch == "*":
                        return process_comment(prefix + line[:i], line[i + 2 :])
                if ch == "R" and line[i : i + 3] == 'R"(':
                    return process_rstring(prefix + line[:i] + '"', line[i + 3 :])
            return prefix + line, None

        def process_string(prefix: str, line: str, quote: str) -> tuple[str, Status]:
            skip_next = False
            for i, ch in enumerate(line):
                if skip_next:
                    skip_next = False
                    continue
                if ch == quote:  # end of string
                    return process_normal(prefix + ch, line[i + 1 :])
                if ch == "\\":
                    skip_next = True
            return (prefix, "string")

        def process_rstring(prefix: str, line: str) -> tuple[str, Status]:
            for i, ch in enumerate(line):
                if ch == ")" and line[i : i + 2] == ')"':
                    return process_normal(prefix + '"', line[i + 2 :])
            return (prefix, "rstring")

        def process_comment(prefix: str, line: str) -> tuple[str, Status]:
            for i, ch in enumerate(line):
                if ch == "*" and line[i : i + 2] == "*/":
                    return process_normal(prefix, line[i + 2 :])
            return (prefix, "comment")

        out: list[str] = []
        status: Status = None
        for line in self._lines:
            line, status = process_line(line, status)
            out.append(line)
        assert status is None, "status=%r when parsing file %s" % (status, self._path)
        self._lines = out

    def find_includes(self) -> None:
        for line in self._lines:
            match = re.match(r'\s*#\s*include\s*(".*?"|<.*?>)', line)
            if match:
                quoted = match.group(1)
                if quoted[0] == "<":
                    self._sys_includes_base.append(quoted[1:-1])
                else:
                    self._src_includes_base.append(quoted[1:-1])

    def resolve_includes(self, all_sources: dict[str, "Source"]) -> set[str]:
        assert self._path in all_sources
        if self._sys_includes_resolved is None:
            resolved = set(self._sys_includes_base)
            # for include_path in self._src_includes_base:
            #     if include_path not in all_sources:
            #         raise ValueError(
            #             'Path "%s" (#include\'d from %s) is not in '
            #             "the list of all sources" % (include_path, self._path)
            #         )
            #     incl = all_sources[include_path]
            #     incl_sys_includes = incl.resolve_includes(all_sources)
            #     resolved |= incl_sys_includes
            self._sys_includes_resolved = resolved
        return self._sys_includes_resolved

    def find_std_symbols(self):
        symbols: set[str] = set()
        for line in self._lines:
            matches = re.findall(r"\bstd::\w+", line)
            symbols |= set(matches)
            matches = re.findall(
                r"\b(size_t|u?int(?:_fast|_least)?\d+_t|u?intmax_t|u?intptr_t)\b", line
            )
            symbols |= set(matches)
        self._std_symbols = symbols

    def check_std_symbols(self):
        self.find_std_symbols()
        includes = self._sys_includes_resolved
        symbols = self._std_symbols
        assert includes is not None
        assert symbols is not None
        errors_found = 0
        for std_symbol in symbols:
            if std_symbol == "std::experimental":
                continue
            headers = std_symbols_library.get(std_symbol)
            if headers is None:
                print(f"Unknown symbol {std_symbol} in file {self._path}")
            elif not headers or includes.intersection(headers):
                pass
            else:
                errors_found += 1
                print(
                    f"Missing header <{headers[0]}> for symbol {std_symbol} in "
                    f"file {self._path}"
                )
        return errors_found


def analyze(paths: list[str]) -> int:
    all_sources: dict[str, Source] = {}
    for entry in paths:
        if os.path.isfile(entry):
            all_sources[entry] = Source(entry)
            continue
        elif os.path.isdir(entry):
            if entry.endswith("/"):
                entry = entry[:-1]
            pattern = entry + "/**"
        elif "*" in entry or "?" in entry or "[" in entry:
            pattern = entry
        else:
            raise SystemExit(f"Unknown path `{entry}`")

        files = glob.glob(pattern, recursive=True)
        for file in files:
            if not os.path.isfile(file):
                continue
            ext = os.path.splitext(file)[1]
            if ext.lower() not in all_extensions:
                continue
            all_sources[file] = Source(file)

    n_errors = 0
    for src in all_sources.values():
        src.resolve_includes(all_sources)
        n_errors += src.check_std_symbols()
    if n_errors:
        print("-----------\n%d errors found" % n_errors)
        return 2
    else:
        print("ok")
        return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze C/C++ source files to detect missing standard headers",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="Path to the directory with C/C++ source files",
    )

    args = parser.parse_args()
    ret = analyze(args.paths)
    sys.exit(ret)
