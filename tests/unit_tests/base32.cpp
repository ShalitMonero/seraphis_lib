// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote
// developers

#include "gtest/gtest.h"

// #include <cstdint>

#include "common/base32.h"

using namespace tools;
using namespace std;

// #define MAKE_STR(arr) std::string(arr, sizeof(arr) - 1)

// namespace
// {
//   void do_test_encode(std::string expected, std::string data)
//   {
//     std::string result = base32::encode(data);
//     ASSERT_EQ(result, expected);
//   }
// }

void do_test_encode_b32(std::string data, std::string expected) {
  ASSERT_EQ(base32::encode(data), expected);
}

void do_test_decode_b32(std::string data, std::string expected) {
  ASSERT_EQ(base32::decode(data), expected);
}


TEST(base32, encode) {
do_test_encode_b32("a","cr");
do_test_encode_b32("aa","cfoo");
do_test_encode_b32("aaa","cfosn");
do_test_encode_b32("aaaa","cfosnae");
do_test_encode_b32("aaaaa","cfosnamb");
}



TEST(base32, decode) {
do_test_decode_b32("cr","a");
do_test_decode_b32("cfoo","aa");
do_test_decode_b32("cfosn","aaa");
do_test_decode_b32("cfosnae","aaaa");
do_test_decode_b32("cfosnamb","aaaaa");
}

