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

#include <string>
#include "gtest/gtest.h"

// #include <cstdint>

#include "common/base32.h"
#include "common/base32codec/cppcodec/base32_monero.hpp"
#include "crypto/crypto.h"
#include "include_base_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_main/serialization_demo_types.h"
#include "seraphis_main/serialization_demo_utils.h"
#include "seraphis_mocks/jamtis_mock_keys.h"
#include "seraphis_mocks/legacy_mock_keys.h"
#include "string_tools.h"

using namespace tools;
using namespace std;
using namespace sp;
using namespace sp::jamtis;
using base32_lib = cppcodec::base32_monero;

void do_test_b32()
{
    JamtisDestinationV1 address_zero{gen_jamtis_destination_v1()};

    sp::serialization::ser_JamtisDestinationV1 serializable_destination;
    sp::serialization::make_serializable_sp_destination_v1(address_zero, serializable_destination);
    std::string serialized_address;
    sp::serialization::try_append_serializable(serializable_destination, serialized_address);

    std::string address_main;
    base32::encode(serialized_address,address_main);
    std::string address_main_lib = base32_lib::encode(serialized_address);

  ASSERT_EQ(address_main, address_main_lib);
    

    std::string serialized_recovered;
    std::string serialized_recovered_lib;
    base32::decode(address_main, serialized_recovered);
    base32_lib::decode(serialized_recovered_lib, address_main);

  ASSERT_EQ(serialized_recovered, serialized_recovered_lib);
}



TEST(base32, encode_decode) {
for (int i=0; i<1000; i++)
{
    do_test_b32();
}
}


