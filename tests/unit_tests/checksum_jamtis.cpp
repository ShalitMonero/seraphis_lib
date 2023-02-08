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

#include "common/checksum_jamtis.h"

#include <cstdint>
#include <string>
// #include "string_tools.h"
// #include "include_base_utils.h"


using namespace std;

void do_test_checksum(std::string &without, std::string &checksum)
{

    // string with{jamtis_add_checksum(without)};
    std::string address_with_checksum{tools::jamtis_checksum::jamtis_add_checksum(without)};
    ASSERT_EQ(address_with_checksum, without + checksum);
}

TEST(checksum_jamtis, checksum_polymod)
{
    std::string t1{
        "xmra1mj0b1977bw3ympyh2yxd7hjymrw8crc9kin0dkm8d3wdu8jdhf3fkdpmgxfkbywbb9mdwkhkya4jtfn0d5h7s49bfyji1936w19tyf390"
        "6ypj09n64runqjrxwp6k2s3phxwm6wrb5c0b6c1ntrg2muge0cwdgnnr7u7bgknya9arksrj0re7wh"};
    std::string checksum_t1{"kckh51ik"};
    do_test_checksum(t1,checksum_t1);
}
