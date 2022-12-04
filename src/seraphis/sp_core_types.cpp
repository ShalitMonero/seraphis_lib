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
#include "sp_core_types.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool SpCoinbaseEnoteCore::onetime_address_is_canonical() const
{
    return key_domain_is_prime_subgroup(m_onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void SpCoinbaseEnoteCore::gen()
{
    // all random
    m_onetime_address = rct::pkGen();
    crypto::rand(8, reinterpret_cast<unsigned char*>(&m_amount));
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpCoinbaseEnoteCore &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("Ko", container.m_onetime_address);
    transcript_inout.append("a", container.m_amount);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteCore::onetime_address_is_canonical() const
{
    return key_domain_is_prime_subgroup(m_onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteCore::gen()
{
    // all random
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteCore &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("Ko", container.m_onetime_address);
    transcript_inout.append("C", container.m_amount_commitment);
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const SpEnoteCoreVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<const rct::key&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const rct::key& operator()(const SpCoinbaseEnoteCore &enote) const { return enote.m_onetime_address; }
        const rct::key& operator()(const SpEnoteCore &enote) const { return enote.m_onetime_address; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
rct::key amount_commitment_ref(const SpEnoteCoreVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<rct::key>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::key operator()(const SpCoinbaseEnoteCore &enote) const { return rct::zeroCommit(enote.m_amount); }
        rct::key operator()(const SpEnoteCore &enote) const { return enote.m_amount_commitment; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteCoreVariant &variant1, const SpEnoteCoreVariant &variant2)
{
    // check they have the same type
    if (!SpEnoteCoreVariant::same_type(variant1, variant2))
        return false;

    // use a visitor to test equality with variant2
    struct visitor : public tools::variant_static_visitor<bool>
    {
        visitor(const SpEnoteCoreVariant &other_ref) : other{other_ref} {}
        const SpEnoteCoreVariant &other;

        using variant_static_visitor::operator();  //for blank overload
        bool operator()(const SpCoinbaseEnoteCore &enote) const { return enote == other.unwrap<SpCoinbaseEnoteCore>(); }
        bool operator()(const SpEnoteCore &enote) const { return enote == other.unwrap<SpEnoteCore>(); }
    };

    return variant1.visit(visitor{variant2});
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteImageCore &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("K_masked", container.m_masked_address);
    transcript_inout.append("C_masked", container.m_masked_commitment);
    transcript_inout.append("KI", container.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposalCore::get_squash_prefix(rct::key &squash_prefix_out) const
{
    // H_n(Ko,C)
    make_seraphis_squash_prefix(onetime_address_ref(m_enote_core), amount_commitment_ref(m_enote_core), squash_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposalCore::get_enote_image_core(SpEnoteImageCore &image_out) const
{
    // K" = t_k G + H_n(Ko,C) Ko
    // C" = t_c G + C
    make_seraphis_enote_image_masked_keys(onetime_address_ref(m_enote_core),
        amount_commitment_ref(m_enote_core),
        m_address_mask,
        m_commitment_mask,
        image_out.m_masked_address,
        image_out.m_masked_commitment);

    // KI = k_b/k_a U
    image_out.m_key_image = this->key_image();
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposalCore::gen(const crypto::secret_key &sp_spend_privkey, const rct::xmr_amount amount)
{
    m_enote_view_privkey_g = rct::rct2sk(rct::skGen());
    m_enote_view_privkey_x = rct::rct2sk(rct::skGen());
    m_enote_view_privkey_u = rct::rct2sk(rct::skGen());
    crypto::secret_key sp_spend_privkey_extended;
    sc_add(to_bytes(sp_spend_privkey_extended), to_bytes(m_enote_view_privkey_u), to_bytes(sp_spend_privkey));
    make_seraphis_key_image(m_enote_view_privkey_x, sp_spend_privkey_extended, m_key_image);
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
    SpEnoteCore enote_core_temp;
    make_seraphis_enote_core(m_enote_view_privkey_g,
        m_enote_view_privkey_x,
        m_enote_view_privkey_u,
        sp_spend_privkey,
        m_amount_blinding_factor,
        m_amount,
        enote_core_temp);
    m_enote_core = enote_core_temp;
    m_address_mask = rct::rct2sk(rct::skGen());;
    m_commitment_mask = rct::rct2sk(rct::skGen());;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpOutputProposalCore::onetime_address_is_canonical() const
{
    return key_domain_is_prime_subgroup(m_onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposalCore::get_enote_core(SpEnoteCore &enote_out) const
{
    make_seraphis_enote_core(m_onetime_address, m_amount_blinding_factor, m_amount, enote_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposalCore::gen(const rct::xmr_amount amount)
{
    // all random except amount
    m_onetime_address = rct::pkGen();
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
