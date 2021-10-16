// Copyright (c) 2021, The Monero Project
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
#include "mock_sp_component_types.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "mock_sp_core.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSpV1::make(const crypto::secret_key &enote_privkey,
    const rct::key &recipient_DH_base,
    const rct::key &recipient_view_key,
    const rct::key &recipient_spend_key,
    const rct::xmr_amount amount,
    const std::size_t enote_index,
    rct::key &enote_pubkey_out)
{
    // note: t = enote_index

    // r_t: sender-receiver shared secret
    crypto::secret_key sender_receiver_secret;
    make_seraphis_sender_receiver_secret(enote_privkey, recipient_view_key, enote_index, sender_receiver_secret);

    // x_t: amount commitment mask (blinding factor)
    crypto::secret_key amount_mask;
    make_seraphis_amount_commitment_mask(sender_receiver_secret, amount_mask);

    // k_{a, sender, t}: extension to add to user's spend key
    crypto::secret_key k_a_extender;
    make_seraphis_sender_address_extension(sender_receiver_secret, k_a_extender);

    // make the base of the enote (Ko_t, C_t)
    this->make_base_with_address_extension(k_a_extender, recipient_spend_key, amount_mask, amount);

    // enc(a_t): encoded amount
    m_encoded_amount = enc_dec_seraphis_amount(sender_receiver_secret, amount);

    // view_tag_t: view tag
    m_view_tag = make_seraphis_view_tag(sender_receiver_secret);

    // R_t: enote pubkey to send back to caller
    make_seraphis_enote_pubkey(enote_privkey, recipient_DH_base, enote_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSpV1::gen()
{
    // gen base of enote
    this->gen_base();

    // memo
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
    m_view_tag = 0;
}
//-------------------------------------------------------------------------------------------------------------------
MockENoteSpV1 MockDestSpV1::to_enote_v1(const std::size_t output_index, rct::key &enote_pubkey_out) const
{
    MockENoteSpV1 enote;

    enote.make(m_enote_privkey,
        m_recipient_DHkey,
        m_recipient_viewkey,
        m_recipient_spendkey,
        m_amount,
        output_index,
        enote_pubkey_out);

    return enote;
}
//-------------------------------------------------------------------------------------------------------------------
void MockDestSpV1::gen_v1(const rct::xmr_amount amount)
{
    // gen base of destination
    this->gen_base(amount);

    m_enote_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockMembershipProofSpV1::get_size_bytes() const
{
    std::size_t num_elements = m_concise_grootle_proof.X.size();  // X

    if (m_concise_grootle_proof.f.size() > 0)
        num_elements += num_elements * m_concise_grootle_proof.f[0].size();  // f

    num_elements += 7;  // A, B, C, D, zA, zC, z

    return 32 * num_elements;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockImageProofSpV1::get_size_bytes() const
{
    return 32 * (3 + m_composition_proof.r_i.size() + m_composition_proof.K_t1.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockBalanceProofSpV1::get_size_bytes() const
{
    // note: ignore the amount commitment set stored in the range proofs, they are double counted by the output set
    //TODO? don't store amount commitment set in range proofs at all
    std::size_t size{0};

    for (const auto &proof : m_bpp_proofs)
        size += 32 * (6 + proof.L.size() + proof.R.size());;

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockSupplementSpV1::get_size_bytes() const
{
    return 32 * m_output_enote_pubkeys.size();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx