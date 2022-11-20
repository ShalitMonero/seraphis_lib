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

#pragma once

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "serialization/keyvalue_serialization.h"

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "ringct/rctTypes.h"

namespace sp {
namespace jamtis {
/*Generate the set of public wallet addresses, where:
 * k_aj = key_derive(k_ga,"address_key",j)
 * k_xj = key_derive(k_ga,"key_extension",j)
 */
struct account_public_address {
  rct::key K_1; // K_1 = k_vb X + k_m U + k_kj X
  rct::key K_2; // K_2 = k_aj K_fr
  rct::key K_3; // K_3 = k_aj G
  // crypto::signature signature;

  BEGIN_SERIALIZE_OBJECT()
  FIELD(K_1)
  FIELD(K_2)
  FIELD(K_3)
  // FIELD(signature)
  END_SERIALIZE()

  BEGIN_KV_SERIALIZE_MAP()
  KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(K_1)
  KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(K_2)
  KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(K_3)
  // KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(signature)
  END_KV_SERIALIZE_MAP()

  bool operator==(const account_public_address &rhs) const {
    return K_1 == rhs.K_1 && K_2 == rhs.K_2 && K_3 == rhs.K_3;
  }

  bool operator!=(const account_public_address &rhs) const {
    return !(*this == rhs);
  }
};

struct jamtis_keys {
  account_public_address m_account_address;
  crypto::secret_key m_k_m;  // master
  crypto::secret_key m_k_vb; // view-balance
  crypto::secret_key m_k_et; // encrypt-tag
  crypto::chacha_iv m_encryption_iv;

  BEGIN_KV_SERIALIZE_MAP()
  KV_SERIALIZE(m_account_address)
  KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_k_m)
  KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_k_vb)
  KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_k_et)
  const crypto::chacha_iv default_iv{{0, 0, 0, 0, 0, 0, 0, 0}};
  KV_SERIALIZE_VAL_POD_AS_BLOB_OPT(m_encryption_iv, default_iv)
  END_KV_SERIALIZE_MAP()

  void encrypt(const crypto::chacha_key &key);
  void decrypt(const crypto::chacha_key &key);
  void encrypt_viewkey(const crypto::chacha_key &key);
  void decrypt_viewkey(const crypto::chacha_key &key);

private:
  void xor_with_key_stream(const crypto::chacha_key &key);
};

/************************************************************************/
/*                                                                      */
/************************************************************************/
class account_base {
public:
  account_base();

  /**
   * MOCK generate private keys
   */
  void generate();

  /**
   * Get the jamtis keys struct
   */
  const jamtis_keys &get_keys() const;

  /**
   * Get the public addresses keys
   */
  std::string get_public_address_str();

  /**
   * Encrypt keys in memory
   */
  void encrypt_keys(const crypto::chacha_key &key) { m_keys.encrypt(key); }

  /**
   * Decrypt keys in memory
   */
  void decrypt_keys(const crypto::chacha_key &key) { m_keys.decrypt(key); }

  /**
   * Encrypt keys in memory
   */
  void encrypt_viewkey(const crypto::chacha_key &key) {
    m_keys.encrypt_viewkey(key);
  }

  /**
   * Decrypt keys in memory
   */
  void decrypt_viewkey(const crypto::chacha_key &key) {
    m_keys.decrypt_viewkey(key);
  }
  /**
   * get address_tag in base32
   */
  std::string get_address_tag(const crypto::secret_key sk,
                              const std::string tag);

  /**
   * get checksum in base32
   */
  std::string get_checksum(const std::string addr);

  template <class t_archive>
  inline void serialize(t_archive &a, const unsigned int /*ver*/) {
    a &m_keys;
    a &m_creation_timestamp;
  }

  BEGIN_KV_SERIALIZE_MAP()
  KV_SERIALIZE(m_keys)
  KV_SERIALIZE(m_creation_timestamp)
  END_KV_SERIALIZE_MAP()

private:
  void set_null();
  jamtis_keys m_keys;
  uint64_t m_creation_timestamp;
};
} // namespace jamtis
} // namespace sp
