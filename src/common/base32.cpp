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

// Inspired by https://github.com/cryptii/cryptii/blob/main/src/Encoder/Base32.js

// At the moment only std::string are accepted as inputs/outputs

#include "base32.h"
#include <cmath>
#include <iostream>
using namespace std;

static const std::string alphabet = "ybndrfg8ejkmcpqxot1uwis2a345h769";

namespace tools {
namespace base32 {

std::string encode(std::string input) {

  const uint64_t input_size = input.size();
  const uint64_t output_size = ceil((float)input_size / 5) * 8;
  std::string result(output_size, '=');

  int64_t j = 0;
  int64_t shift = 3;
  int64_t carry = 0;

  char encoding_target, index;

  for (uint64_t i = 0; i < input_size; i++) {
    encoding_target = input[i];
    index = carry | (encoding_target >> shift);
    result[j++] = alphabet[index & 0x1f];

    if (shift > 5) {
      shift -= 5;
      index = encoding_target >> shift;
      result[j++] = alphabet[index & 0x1f];
    }

    shift = 5 - shift;
    carry = encoding_target << shift;
    shift = 8 - shift;
  }

  if (shift != 3) {
    result[j++] = alphabet[carry & 0x1f];
  }

  // The padding ('=') is removed by slicing the string up to the position j
  return result.substr(0, j);
}

std::string decode(std::string input) {

  const uint64_t input_size = input.size();
  const uint64_t output_size = ceil((float)input_size / 8) * 5;
  std::string result(output_size, '=');

  int64_t j = 0;
  int64_t shift = 8;
  int64_t carry = 0;

  char decoding_target;
  char index;

  for (uint64_t i = 0; i < input_size; i++) {
    decoding_target = input[i];

    index = alphabet.find(decoding_target) & 0xff;
    shift -= 5;
    if (shift > 0) {
      carry |= index << shift;
    } else if (shift < 0) {
      result[j++] = carry | (index >> -shift);
      shift += 8;
      carry = (index << shift) & 0xff;
    } else {
      result[j++] = carry | index;
      shift = 8;
      carry = 0;
    }
  }

  // The padding ('=') is removed by slicing the string up to the position j
  return result.substr(0, j);
}
} // namespace base32
} // namespace tools
