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


//paired header
#include "key_container.h"

// local headers
#include "crypto/blake2b.h"
#include "common/base58.h"
// #include "common/jamtis_keysbase32.h"
#include "include_base_utils.h"
#include "crypto/crypto.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_mocks/jamtis_mock_keys.h"
#include "warnings.h"
extern "C" {
#include "crypto/keccak.h"
}
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

// standard headers
#include <iostream>
#include <string>
#include <fstream>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "account"

using namespace std;

namespace sp {
namespace jamtis {

static const std::vector<int64_t> GEN{0x7a46a12681, 0xf48d424822, 0xab58143444,
                               0x1eb0286888, 0x377244f510};
static const int64_t M = 0xffeffffeff;
static const std::string alphabet = "ybndrfg8ejkmcpqxot1uwis2a345h769";

//-----------------------------------------------------------------
static void derive_key(const crypto::chacha_key &base_key,
                       crypto::chacha_key &key) {
  static_assert(sizeof(base_key) == sizeof(crypto::hash),
                "chacha key and hash should be the same size");
  epee::mlocked<tools::scrubbed_arr<char, sizeof(base_key) + 1>> data;
  memcpy(data.data(), &base_key, sizeof(base_key));
  data[sizeof(base_key)] = 'k';
  crypto::generate_chacha_key(data.data(), sizeof(data), key, 1);
}
//-----------------------------------------------------------------
static epee::wipeable_string get_key_stream(const crypto::chacha_key &base_key,
                                            const crypto::chacha_iv &iv,
                                            size_t bytes) {
  // derive a new key
  crypto::chacha_key key;
  derive_key(base_key, key);

  // chacha
  epee::wipeable_string buffer0(std::string(bytes, '\0'));
  epee::wipeable_string buffer1 = buffer0;
  crypto::chacha20(buffer0.data(), buffer0.size(), key, iv, buffer1.data());
  return buffer1;
}
//-----------------------------------------------------------------
// void key_container::xor_with_key_stream(const crypto::chacha_key &key) {
//   // encrypt a large enough byte stream with chacha20
//   epee::wipeable_string key_stream =
//       get_key_stream(key, m_encryption_iv,
//                      sizeof(crypto::secret_key) * (6));
//   const char *ptr = key_stream.data();
//   for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
//     k_m.data[i] ^= *ptr++;
//   for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
//     k_vb.data[i] ^= *ptr++;
//   for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
//     xk_ua.data[i] ^= *ptr++;
//   for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
//     xk_fr.data[i] ^= *ptr++;
//   for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
//     s_ga.data[i] ^= *ptr++;
//   for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
//     s_ct.data[i] ^= *ptr++;
// }
// //-----------------------------------------------------------------
// void key_container::encrypt(const crypto::chacha_key &key) {
//   m_encryption_iv = crypto::rand<crypto::chacha_iv>();
//   xor_with_key_stream(key);
// }
// //-----------------------------------------------------------------
// void key_container::decrypt(const crypto::chacha_key &key) {
//   xor_with_key_stream(key);
// }
// //-----------------------------------------------------------------
// void key_container::encrypt_viewkey(const crypto::chacha_key &key) {
//   // encrypt a large enough byte stream with chacha20
//   epee::wipeable_string key_stream =
//       get_key_stream(key, m_encryption_iv, sizeof(crypto::secret_key) * 2);
//   const char *ptr = key_stream.data();
//   ptr += sizeof(crypto::secret_key);
//   for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
//     k_vb.data[i] ^= *ptr++;
// }
// //-----------------------------------------------------------------
// void key_container::decrypt_viewkey(const crypto::chacha_key &key) {
//   encrypt_viewkey(key);
// }

//-----------------------------------------------------------------
key_container_base::key_container_base() { set_null(); }
//-----------------------------------------------------------------
void key_container_base::set_null() {
  m_keys = mocks::jamtis_mock_keys();
  m_wallet_type = 0;
  m_creation_timestamp = 0;
}
//-----------------------------------------------------------------

// std::string key_container_master_base::get_address_tag(const crypto::secret_key sk,
//                                           const std::string tag) {
//   std::string m_k_et_tag = std::string(sk.data, 32);
//   m_k_et_tag.append(tag);

//   unsigned char hash_out[8];
//   size_t outlen = 8;
//   std::string address_tag;

//   blake2b(hash_out, outlen, m_k_et_tag.data(), m_k_et_tag.size(), nullptr, 0);

//   char *hash_data = reinterpret_cast<char *>(hash_out);
//   address_tag = std::string(hash_data, outlen);

//   return tools::base32::encode(address_tag);
// }

int64_t key_container_base::jamtis_polymod(const std::vector<int> data) {
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

bool key_container_base::jamtis_verify_checksum(const std::string data) {
  std::vector<int> addr_data;
  for (auto x : data) {
    addr_data.push_back(alphabet.find(x));
  }
  return jamtis_polymod(addr_data) == M;
}

std::string key_container_base::get_checksum(const std::string addr_without_checksum) {

  std::vector<int> addr_data;
  for (auto x : addr_without_checksum) {
    addr_data.push_back(alphabet.find(x));
  }

  std::vector<int> data_extended{addr_data};
  data_extended.resize(addr_data.size() + 8);
  int64_t polymod = jamtis_polymod(data_extended) ^ M;
  for (int64_t i = 0; i < 8; i++) {
    data_extended[addr_data.size() + i] = ((polymod >> 5 * (7 - i)) & 31);
  }

  std::string addr_with_checksum{};
  for (uint64_t j = 0; j < data_extended.size(); j++) {
    addr_with_checksum.push_back(alphabet[data_extended[j]]);
  }

  return addr_with_checksum;
}

std::string key_container_base::get_public_address_str() {

  // Fixed parameters for version 1 mainnet anonymous address
  std::string address_prefix = "xmr";
  std::string address_version = "1";
  std::string address_network = "m";
  std::string address_type = "a";
  std::string str_tag = "1";
  // std::string address_main_ser =
  //     cryptonote::t_serializable_object_to_blob(m_keys.m_account_address);
  // std::string address_main = tools::base32::encode(address_main_ser);
  std::string address_main{};
  std::string address_tag{};
  std::string address_checksum;
  std::string address_without_checksum;

  // address_tag = get_address_tag(m_keys.s_ct, str_tag);

  address_without_checksum = address_prefix + address_version +
                             address_network + address_type + address_main +
                             address_tag;

  cout << "Address without checksum: " << address_without_checksum << endl;
  address_checksum = get_checksum(address_without_checksum);
  cout << "Address with checksum:    " << address_checksum << endl;

  cout << "\n---Public keys---" << endl;
  // cout << "K1: " << m_keys.m_account_address.K_1 << endl;
  // cout << "K2: " << m_keys.m_account_address.K_2 << endl;
  // cout << "K3: " << m_keys.m_account_address.K_3 << endl;

  cout << "\n+++Private keys+++" << endl;
  cout << "m_k_m: " << m_keys.k_m << endl;

  cout << "\n***Wallet address***" << endl;

  return address_checksum;
}
//-----------------------------------------------------------------
void key_container_base::set_wallet_type(size_t wallet_type)
{
    m_wallet_type = wallet_type;
}

void key_container_base::generate(size_t type)
{
  //Master wallet
  if (type== 0)
  {
    make_jamtis_mock_keys(m_keys);
  }

  //View only wallet
  if (type== 1)
  {
    make_jamtis_mock_keys_viewbalance(m_keys);
  }


  m_creation_timestamp = time(NULL);

}

bool key_container_base::verify_keys()
{
  rct::key spendkey_out;
  make_seraphis_spendkey(m_keys.k_vb, m_keys.k_m, spendkey_out);
  return (m_keys.K_1_base == spendkey_out);
    
}
// void key_container_base::generate() 
// {
//     make_jamtis_mock_keys(m_keys);
// }


} // namespace jamtis
} // namespace sp