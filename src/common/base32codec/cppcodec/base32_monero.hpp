/**
 *  Copyright (C) 2015 Topology LP
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

#ifndef CPPCODEC_BASE32_MONERO
#define CPPCODEC_BASE32_MONERO

#include "detail/codec.hpp"
#include "detail/base32.hpp"

namespace cppcodec {

namespace detail {

static constexpr char base32_monero_alphabet[] = {
  'x','m','r','b','a','s','e','3','2','c',
  'd','f','g','h','i','j','k','n','p','q',
  't','u','w','y','0','1','4','5','6','7','8','9'};

class base32_monero_base
{
public:
    static CPPCODEC_ALWAYS_INLINE constexpr size_t alphabet_size() {
        static_assert(sizeof(base32_monero_alphabet) == 32, "base32 alphabet must have 32 values");
        return sizeof(base32_monero_alphabet);
    }
    static CPPCODEC_ALWAYS_INLINE constexpr char symbol(alphabet_index_t idx)
    {
        return base32_monero_alphabet[idx];
    }
    static CPPCODEC_ALWAYS_INLINE constexpr char normalized_symbol(char c)
    {
        // Hex decoding is always case-insensitive (even in RFC 4648), the question
        // is only for encoding whether to use upper-case or lower-case letters.
        return c;
    }

    static CPPCODEC_ALWAYS_INLINE constexpr bool generates_padding() { return false; }
    static CPPCODEC_ALWAYS_INLINE constexpr bool requires_padding() { return false; }
    static CPPCODEC_ALWAYS_INLINE constexpr bool is_padding_symbol(char) { return false; }
    static CPPCODEC_ALWAYS_INLINE constexpr bool is_eof_symbol(char c) { return c == '\0'; }

    static CPPCODEC_ALWAYS_INLINE constexpr bool should_ignore(char c) {
        return c == '-'; // "Hyphens (-) can be inserted into strings [for readability]."
    }
};

// base32_crockford is a concatenative iterative (i.e. streaming) interpretation of Crockford base32.
// It interprets the statement "zero-extend the number to make its bit-length a multiple of 5"
// to mean zero-extending it on the right.
// (The other possible interpretation is base32_crockford_num, a place-based single number encoding system.
// See http://merrigrove.blogspot.ca/2014/04/what-heck-is-base64-encoding-really.html for more info.)
class base32_monero : public base32_monero_base
{
public:
    template <typename Codec> using codec_impl = stream_codec<Codec, base32_monero>;
};

} // namespace detail

using base32_monero = detail::codec<detail::base32<detail::base32_monero>>;

} // namespace cppcodec

#endif // CPPCODEC_BASE32_CROCKFORD
