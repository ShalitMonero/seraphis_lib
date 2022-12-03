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

#include <cstdint>

const std::vector<int64_t> GEN{0x7a46a12681, 0xf48d424822, 0xab58143444,
                               0x1eb0286888, 0x377244f510};
const int64_t M = 0xffeffffeff;

static const std::string alphabet = "ybndrfg8ejkmcpqxot1uwis2a345h769";

const std::string addr_test =
    ("xmr1majob1977bw3ympyh2yxd7hjymrw8crc9kinodkm8d3"
     "wdu8jdhf3fkdpmgxfkbywbb9mdwkhkya4jtfnod5h7s49bf"
     "yji1936w19tyf39o6ypjo9n64runqjrxwp6k2s3phxwm6wr"
     "b5cob6c1ntrg2mugeocwdgnnr7u7bgknya9arksrjore7wb");

int64_t jamtis_polymod(const std::vector<int> data) {
  int64_t c = 1;
  int64_t b = 0;
  for (const auto v : data) {
    b = (c >> 35);
    c = ((c & 0x07ffffffff) << 5) ^ v;
    for (int64_t j = 0; j < 5; j++) {
      if ((b >> j) & 1) {
        c ^= GEN[j];
      } else {
        c ^= 0;
      }
    }
  }
  return c;
}

bool jamtis_verify_checksum(const std::vector<int> data) { return jamtis_polymod(data) == M; }

std::vector<int> jamtis_create_checksum(const std::vector<int> data) {
  std::vector<int> data_extended{data};
  data_extended.resize(data.size() + 8);
  int64_t polymod = jamtis_polymod(data_extended) ^ M;
  std::vector<int> checksum;
  for (int64_t i = 0; i < 8; i++) {
    data_extended[data.size() + i] = ((polymod >> 5 * (7 - i)) & 31);
  }
  return data_extended;
}

TEST(checksum_bch, simple_test) {
  std::vector<int> addr_data;
  for (auto x : addr_test) {
    addr_data.push_back(alphabet.find(x));
  }

  std::vector<int> address_with_checksum = jamtis_create_checksum(addr_data);
  std::string addr_final{};
  for (int i = 0; i < address_with_checksum.size(); i++)
    addr_final.push_back(alphabet[address_with_checksum[i]]);

  std::cout << "Final address: " << addr_final << std::endl;

  bool ver = jamtis_verify_checksum(address_with_checksum);

  ASSERT_EQ(ver, true);
}