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

// NOT FOR PRODUCTION

//paired header
#include "sp_core_enote_utils.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_types.h"

//third party headers

//standard headers
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::public_key &zU, crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(y)), "y must be nonzero for making a key image!");
    CHECK_AND_ASSERT_THROW_MES(!(rct::pk2rct(zU) == rct::identity()),
        "zU must not be identity element for making a key image!");

    // KI = (z/y)*U
    rct::key temp{sp::invert(rct::sk2rct(y))}; // 1/y
    rct::scalarmultKey(temp, rct::pk2rct(zU), temp); // (z/y)*U

    key_image_out = rct::rct2ki(temp);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::secret_key &z, crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(y)), "y must be nonzero for making a key image!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(z)), "z must be nonzero for making a key image!");

    // KI = (z/y)*U
    rct::key zU{rct::scalarmultKey(rct::pk2rct(crypto::get_U()), rct::sk2rct(z))}; // z U
    make_seraphis_key_image(y, rct::rct2pk(zU), key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image(const crypto::secret_key &k_a_sender,
    const crypto::secret_key &k_a_recipient,
    const crypto::public_key &k_bU,
    crypto::key_image &key_image_out)
{
    // KI = (k_b/(k_a_sender + k_a_recipient))*U
    crypto::secret_key k_a_combined;
    sc_add(to_bytes(k_a_combined), to_bytes(k_a_sender), to_bytes(k_a_recipient));

    make_seraphis_key_image(k_a_combined, k_bU, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_spendbase(const crypto::secret_key &sp_spend_privkey, rct::key &spendbase_pubkey_out)
{
    // spendbase = k_{b, recipient} U
    rct::scalarmultKey(spendbase_pubkey_out, rct::pk2rct(crypto::get_U()), rct::sk2rct(sp_spend_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void extend_seraphis_spendkey_x(const crypto::secret_key &k_extender_x, rct::key &spendkey_inout)
{
    // K = k_extender_x X + K_original
    rct::key extender_key;

    rct::scalarmultKey(extender_key, rct::pk2rct(crypto::get_X()), rct::sk2rct(k_extender_x));
    rct::addKeys(spendkey_inout, extender_key, spendkey_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void extend_seraphis_spendkey_u(const crypto::secret_key &k_extender_u, rct::key &spendkey_inout)
{
    // K = k_extender_u U + K_original
    rct::key extender_key;

    rct::scalarmultKey(extender_key, rct::pk2rct(crypto::get_U()), rct::sk2rct(k_extender_u));
    rct::addKeys(spendkey_inout, extender_key, spendkey_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void reduce_seraphis_spendkey_g(const crypto::secret_key &k_reducer_g, rct::key &spendkey_inout)
{
    static const rct::key MINUS_ONE{minus_one()};

    // K = K_original - k_reducer_g G
    crypto::secret_key mask_to_remove;

    sc_mul(to_bytes(mask_to_remove), MINUS_ONE.bytes, to_bytes(k_reducer_g));  // -k_reducer_g
    mask_key(mask_to_remove, spendkey_inout, spendkey_inout);  // (-k_reducer_g) G + Ko_t
}
//-------------------------------------------------------------------------------------------------------------------
void reduce_seraphis_spendkey_x(const crypto::secret_key &k_reducer_x, rct::key &spendkey_inout)
{
    static const rct::key MINUS_ONE{minus_one()};

    // K = K_original - k_reducer_x X
    crypto::secret_key extension;

    sc_mul(to_bytes(extension), MINUS_ONE.bytes, to_bytes(k_reducer_x));  // -k_reducer_x
    extend_seraphis_spendkey_x(extension, spendkey_inout);  // (-k_reducer_x) X + Ko_t
}
//-------------------------------------------------------------------------------------------------------------------
void reduce_seraphis_spendkey_u(const crypto::secret_key &k_reducer_u, rct::key &spendkey_inout)
{
    static const rct::key MINUS_ONE{minus_one()};

    // K = K_original - k_reducer_u U
    crypto::secret_key extension;

    sc_mul(to_bytes(extension), MINUS_ONE.bytes, to_bytes(k_reducer_u));  // -k_reducer_u
    extend_seraphis_spendkey_u(extension, spendkey_inout);  // (-k_reducer_u) U + Ko_t
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_spendkey(const crypto::secret_key &k_a, const crypto::secret_key &k_b, rct::key &spendkey_out)
{
    // K = k_a X + k_b U
    make_seraphis_spendbase(k_b, spendkey_out);  //k_b U

    // finish address
    extend_seraphis_spendkey_x(k_a, spendkey_out);  //k_a X + k_b U
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_squash_prefix(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &squash_prefix_out)
{
    // H_n(Ko, C)
    SpKDFTranscript transcript{config::HASH_KEY_SERAPHIS_SQUASHED_ENOTE, 2*sizeof(rct::key)};
    transcript.append("Ko", onetime_address);
    transcript.append("C", amount_commitment);

    // hash to the result
    sp_hash_to_scalar(transcript, squash_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_squashed_address_key(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &squashed_address_out)
{
    // Ko^t = H_n(Ko,C) Ko
    rct::key squash_prefix;
    make_seraphis_squash_prefix(onetime_address, amount_commitment, squash_prefix);

    rct::scalarmultKey(squashed_address_out, onetime_address, squash_prefix);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_squashed_enote_Q(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &Q_out)
{
    // Ko^t
    make_seraphis_squashed_address_key(onetime_address, amount_commitment, Q_out);

    // Q = Ko^t + C^t
    rct::addKeys(Q_out, Q_out, amount_commitment);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_enote_core(const rct::key &onetime_address,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out)
{
    // Ko
    enote_core_out.m_onetime_address = onetime_address;

    // C = x G + a H
    enote_core_out.m_amount_commitment = rct::commit(amount, rct::sk2rct(amount_blinding_factor));
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_enote_core(const crypto::secret_key &extension_privkey_g,
    const crypto::secret_key &extension_privkey_x,
    const crypto::secret_key &extension_privkey_u,
    const rct::key &initial_address,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out)
{
    // Ko = k_sender_extension_g G + k_sender_extension_x X + k_sender_extension_u U + K
    enote_core_out.m_onetime_address = initial_address;
    extend_seraphis_spendkey_u(extension_privkey_u, enote_core_out.m_onetime_address);
    extend_seraphis_spendkey_x(extension_privkey_x, enote_core_out.m_onetime_address);
    mask_key(extension_privkey_g, enote_core_out.m_onetime_address, enote_core_out.m_onetime_address);

    // finish making the enote
    make_seraphis_enote_core(enote_core_out.m_onetime_address, amount_blinding_factor, amount, enote_core_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_enote_core(const crypto::secret_key &enote_view_privkey_g,
    const crypto::secret_key &enote_view_privkey_x,
    const crypto::secret_key &enote_view_privkey_u,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out)
{
    // spendbase = k_{b, recipient} U
    rct::key spendbase;
    make_seraphis_spendbase(sp_spend_privkey, spendbase);

    // finish making the enote
    make_seraphis_enote_core(enote_view_privkey_g,
        enote_view_privkey_x,
        enote_view_privkey_u,
        spendbase,
        amount_blinding_factor,
        amount,
        enote_core_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_enote_image_masked_keys(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    rct::key &masked_address_out,
    rct::key &masked_commitment_out)
{
    // K" = t_k G + H_n(Ko,C) Ko
    make_seraphis_squashed_address_key(onetime_address, amount_commitment, masked_address_out);  //H_n(Ko,C) Ko
    sp::mask_key(address_mask, masked_address_out, masked_address_out);  //t_k G + H_n(Ko,C) Ko

    // C" = t_c G + C
    sp::mask_key(commitment_mask, amount_commitment, masked_commitment_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
