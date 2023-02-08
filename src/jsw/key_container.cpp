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

// paired header
#include "key_container.h"

// local headers
#include "common/base58.h"
#include "crypto/blake2b.h"
// #include "common/base32.h"
#include "common/base32codec/cppcodec/base32_monero.hpp"
#include "common/checksum_jamtis.h"

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
#include "warnings.h"
extern "C"
{
#include "crypto/keccak.h"
}
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

// standard headers
#include <fstream>
#include <iostream>
#include <string>
#include <ostream>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "account"

using namespace std;
using base32 = cppcodec::base32_monero;
using namespace tools::jamtis_checksum;

namespace sp
{
namespace jamtis
{


//-----------------------------------------------------------------
key_container_base::key_container_base()
{
    m_sp_keys = mocks::jamtis_mock_keys();
    m_creation_timestamp = 0;
}
std::string key_container_base::get_public_address_str() const
{

    // Fixed parameters for version 1 mainnet anonymous address
    std::string address_prefix = "xmr";
    std::string address_type = "a";
    std::string address_version = "1";
    std::string address_network = "m";

    // Encode ------------------------
    serialization::ser_JamtisDestinationV1 serializable_destination;
    serialization::make_serializable_sp_destination_v1(m_address_zero, serializable_destination);
    std::string serialized_address;
    serialization::try_append_serializable(serializable_destination, serialized_address);

    std::string address_main = base32::encode(serialized_address);
    std::string address;

    address = address_prefix + address_type + address_version + address_network + address_main;
    std::string address_with_checksum{jamtis_add_checksum(address)};

    return address_with_checksum;

}
std::string key_container_base::get_public_address_str(const address_index_t &t) const
{

    JamtisDestinationV1 destination_address;
    make_jamtis_destination_v1(m_sp_keys.K_1_base, m_sp_keys.xK_ua, m_sp_keys.xK_fr, m_sp_keys.s_ga, t,
                               destination_address);

    // Fixed parameters for version 1 mainnet anonymous address
    std::string address_prefix = "xmr";
    std::string address_type = "a";
    std::string address_version = "1";
    std::string address_network = "m";

    // Encode ------------------------
    serialization::ser_JamtisDestinationV1 serializable_destination;
    serialization::make_serializable_sp_destination_v1(destination_address, serializable_destination);
    std::string serialized_address;
    serialization::try_append_serializable(serializable_destination, serialized_address);

    std::string address_main = base32::encode(serialized_address);
    // std::string address_main = tools::base58::encode(serialized_address);

    std::string address;

    address = address_prefix + address_type + address_version + address_network + address_main;
    std::string address_with_checksum{jamtis_add_checksum(address)};

    // cout << "\n---Public keys---" << endl;
    // std::cout << "K_1: " << m_address_zero.m_addr_K1 << std::endl;
    // std::cout << "K_2: " << epee::string_tools::pod_to_hex(m_address_zero.m_addr_K2) << std::endl;
    // std::cout << "K_3: " << epee::string_tools::pod_to_hex(m_address_zero.m_addr_K3) << std::endl;
    // std::cout << "t: " << epee::string_tools::pod_to_hex(m_address_zero.m_addr_tag) << std::endl;

    // cout << "\n+++Private keys+++" << endl;
    // cout << "m_k_m: " << m_sp_keys.k_m << endl;

    // // address += address_checksum;
    // cout << "\n***Address for index 0***" << endl;

    // return address_with_checksum;
    return address_with_checksum;
}
//-----------------------------------------------------------------
void key_container_base::get_destination_from_str(const std::string &address, JamtisDestinationV1 &dest_out)
{
    std::string main_address = address.substr(6, address.length() - 14);
    std::string checksum = address.substr(address.length() - 8);

    // CHECK_AND_ASSERT_THROW_MES(add_checksum(main_address) == (main_address+checksum), "get_destination_from_str:
    // Invalid checksum.");
    // Throw wallet message

    std::string serialized_address;
    base32::decode(serialized_address, main_address);
    // tools::base58::decode(main_address,serialized_address);
    serialization::ser_JamtisDestinationV1 serializable_destination_recovered;
    serialization::try_get_serializable(epee::strspan<std::uint8_t>(serialized_address),
                                        serializable_destination_recovered);
    serialization::recover_sp_destination_v1(serializable_destination_recovered, dest_out);

    // std::cout << "K_1: " << dest_out.m_addr_K1 << std::endl;
    // std::cout << "K_2: " << epee::string_tools::pod_to_hex(dest_out.m_addr_K2) << std::endl;
    // std::cout << "K_3: " << epee::string_tools::pod_to_hex(dest_out.m_addr_K3) << std::endl;
    // std::cout << "t: " << epee::string_tools::pod_to_hex(dest_out.m_addr_tag) << std::endl;
}
//-----------------------------------------------------------------
size_t key_container_base::get_wallet_type()
{ 
    if (m_sp_keys.k_m == rct::rct2sk(rct::zero()))
    {
        if (m_sp_keys.k_vb == rct::rct2sk(rct::zero()))
        {
        // Derived from viewbalance
            return 999;

        }
        else
        {
            return size_t{1}; // View-balance 
        }

    }
    else
    {
        return size_t{0}; // Master
    }
}
//-----------------------------------------------------------------
void key_container_base::generate_master(const address_index_t &t)
{
    // Master wallet
    make_jamtis_mock_keys(m_sp_keys);
    make_jamtis_destination_v1(m_sp_keys.K_1_base, m_sp_keys.xK_ua, m_sp_keys.xK_fr, m_sp_keys.s_ga, t,
                                m_address_zero);
    make_legacy_mock_keys(m_legacy_keys);

    m_creation_timestamp = time(NULL);
}
//-----------------------------------------------------------------
void key_container_base::generate_master()
{
    make_jamtis_mock_keys(m_sp_keys);
    address_index_t t{make_address_index(0, 0)};
    make_jamtis_destination_v1(m_sp_keys.K_1_base, m_sp_keys.xK_ua, m_sp_keys.xK_fr, m_sp_keys.s_ga, t,
                                m_address_zero);
    make_legacy_mock_keys(m_legacy_keys);

    m_creation_timestamp = time(NULL);
}
//-----------------------------------------------------------------
void key_container_base::get_viewbalance(key_container_base &new_keys)
{
    // jamtis_mock_keys new_sp_keys;
    new_keys.m_sp_keys.k_m = rct::rct2sk(rct::zero());
    new_keys.m_sp_keys.k_vb = m_sp_keys.k_vb;
    new_keys.m_sp_keys.xk_ua = m_sp_keys.xk_ua;
    new_keys.m_sp_keys.xk_fr = m_sp_keys.xk_fr;
    new_keys.m_sp_keys.s_ga = m_sp_keys.s_ct;
    new_keys.m_sp_keys.K_1_base = m_sp_keys.K_1_base;
    new_keys.m_sp_keys.xK_ua = m_sp_keys.xK_ua;
    new_keys.m_sp_keys.xK_fr = m_sp_keys.xK_fr;

    new_keys.m_legacy_keys.k_s = rct::rct2sk(rct::zero()); 
    new_keys.m_legacy_keys.k_v = m_legacy_keys.k_v;
    new_keys.m_legacy_keys.Ks = m_legacy_keys.Ks;
    new_keys.m_legacy_keys.Kv = m_legacy_keys.Kv;

    new_keys.m_creation_timestamp = m_creation_timestamp;
    new_keys.m_address_zero = m_address_zero;
    
}
bool key_container_base::verify_keys()
{
    rct::key spendkey_out;
    make_seraphis_spendkey(m_sp_keys.k_vb, m_sp_keys.k_m, spendkey_out);
    return (m_sp_keys.K_1_base == spendkey_out);
}
}  // namespace jamtis
}  // namespace sp