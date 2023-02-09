// Copyright (c) 2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"

#include "common/base32.h"
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

#include <string>

using namespace tools;
using namespace std;
using namespace sp;
using namespace sp::jamtis;

void do_test_b32()
{
    JamtisDestinationV1 address_initial{gen_jamtis_destination_v1()};

    sp::serialization::ser_JamtisDestinationV1 serializable_destination;
    sp::serialization::make_serializable_sp_destination_v1(address_initial, serializable_destination);
    std::string serialized_address;
    sp::serialization::try_append_serializable(serializable_destination, serialized_address);

    std::string address_main;
    base32::encode(serialized_address,address_main);


    std::string serialized_recovered;
    std::string serialized_recovered_lib;
    base32::decode(address_main, serialized_recovered);
  
    ASSERT_EQ(serialized_recovered, serialized_address);


    JamtisDestinationV1 address_final;
    sp::serialization::ser_JamtisDestinationV1 serializable_destination_recovered;
    sp::serialization::try_get_serializable(epee::strspan<std::uint8_t>(serialized_recovered),
                                        serializable_destination_recovered);
    sp::serialization::recover_sp_destination_v1(serializable_destination_recovered, address_final);

    ASSERT_EQ(address_final, address_initial);

}



TEST(base32, encode_decode) {
for (int i=0; i<1000; i++)
{
    do_test_b32();
}
}


