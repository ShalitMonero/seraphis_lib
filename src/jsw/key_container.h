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

#pragma once

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_mocks/jamtis_mock_keys.h"
#include "seraphis_mocks/legacy_mock_keys.h"
#include "serialization/keyvalue_serialization.h"

using namespace sp;
using namespace sp::mocks;
using namespace sp::jamtis::mocks;

namespace sp
{
namespace jamtis
{
class key_container_base
{
   public:
    key_container_base();

    /**
     * MOCK generate private keys
     */

    // void generate();
    void generate_master();
    void generate_master(const address_index_t &t);
    size_t get_wallet_type();
    void get_viewbalance(key_container_base &new_sp_keys);

    bool verify_keys();

    /**
     * Get jamtis and legacy keys struct
     */
    const jamtis_mock_keys get_keys_sp() { return m_sp_keys; };
    const legacy_mock_keys get_keys_legacy() { return m_legacy_keys; };

    /**
     * Get the public addresses keys
     */
    std::string get_public_address_str(const address_index_t &t) const;
    std::string get_public_address_str() const;

    void get_destination_from_str(const std::string &address, JamtisDestinationV1 &dest_out);

    /**
     * Encrypt keys in memory
     */
    void encrypt_keys(const crypto::chacha_key &key) { m_sp_keys.encrypt(key); }

    /**
     * Decrypt keys in memory
     */
    void decrypt_keys(const crypto::chacha_key &key) { m_sp_keys.decrypt(key); }

    /**
     * get address_tag in base32
     */
    std::string get_address_tag(const crypto::secret_key sk, const std::string tag);

    void set_wallet_type(size_t wallet_type);

    /**
     * get checksum in base32
     */

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int /*ver*/)
    {
        a &m_sp_keys;
        a &m_legacy_keys;
        a &m_creation_timestamp;
        a &m_address_zero;
    }

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(m_sp_keys)
    KV_SERIALIZE(m_legacy_keys)
    KV_SERIALIZE(m_creation_timestamp)
    KV_SERIALIZE(m_address_zero)
    END_KV_SERIALIZE_MAP()

   private:
    jamtis_mock_keys m_sp_keys;
    legacy_mock_keys m_legacy_keys;
    uint64_t m_creation_timestamp;
    JamtisDestinationV1 m_address_zero;
};
}  // namespace jamtis
}  // namespace sp