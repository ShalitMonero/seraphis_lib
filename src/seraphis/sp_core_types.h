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

// Seraphis core types.


#pragma once

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }


namespace sp
{

////
// SpCoinbaseEnoteCore
///
struct SpCoinbaseEnoteCore final
{
    /// Ko = k_g G + k_x X + (k_u + k_{b, recipient}) U
    rct::key m_onetime_address;
    /// a
    rct::xmr_amount m_amount;

    /// less-than operator for sorting
    bool operator<(const SpCoinbaseEnoteCore &other_enote) const
    {
        return memcmp(m_onetime_address.bytes, other_enote.m_onetime_address.bytes, sizeof(rct::key)) < 0;
    }
    /// comparison operator for equivalence testing
    bool operator==(const SpCoinbaseEnoteCore &other_enote) const
    {
        return m_onetime_address == other_enote.m_onetime_address &&
            m_amount == other_enote.m_amount;
    }

    /**
    * brief: onetime_address_is_canonical - check if the onetime address is canonical (prime subgroup)
    */
    bool onetime_address_is_canonical() const;

    static std::size_t size_bytes() { return 32 + 8; }

    /**
    * brief: gen() - generate a seraphis coinbase enote (all random)
    */
    void gen();
};
inline const boost::string_ref container_name(const SpCoinbaseEnoteCore&) { return "SpCoinbaseEnoteCore"; }
void append_to_transcript(const SpCoinbaseEnoteCore &container, SpTranscriptBuilder &transcript_inout);

////
// SpEnoteCore
///
struct SpEnoteCore final
{
    /// Ko = k_g G + k_x X + (k_u + k_{b, recipient}) U
    rct::key m_onetime_address;
    /// C = x G + a H
    rct::key m_amount_commitment;

    /// less-than operator for sorting
    bool operator<(const SpEnoteCore &other_enote) const
    {
        return memcmp(m_onetime_address.bytes, other_enote.m_onetime_address.bytes, sizeof(rct::key)) < 0;
    }
    /// comparison operator for equivalence testing
    bool operator==(const SpEnoteCore &other_enote) const
    {
        return m_onetime_address == other_enote.m_onetime_address &&
            m_amount_commitment  == other_enote.m_amount_commitment;
    }

    /**
    * brief: onetime_address_is_canonical - check if the onetime address is canonical (prime subgroup)
    */
    bool onetime_address_is_canonical() const;

    static std::size_t size_bytes() { return 32*2; }

    /**
    * brief: gen() - generate a seraphis enote (all random)
    */
    void gen();
};
inline const boost::string_ref container_name(const SpEnoteCore&) { return "SpEnoteCore"; }
void append_to_transcript(const SpEnoteCore &container, SpTranscriptBuilder &transcript_inout);

////
// SpEnoteCoreVariant
// - variant of all seraphis core enote types
//
// onetime_address_ref(): get the enote's onetime address
// amount_commitment_ref(): get the enote's amount commitment (this is a copy because coinbase enotes need to
//                          compute the commitment)
// operator==(): test equalify of two enote cores
///
using SpEnoteCoreVariant = tools::variant<SpCoinbaseEnoteCore, SpEnoteCore>;
const rct::key& onetime_address_ref(const SpEnoteCoreVariant &variant);
rct::key amount_commitment_ref(const SpEnoteCoreVariant &variant);
bool operator==(const SpEnoteCoreVariant &variant1, const SpEnoteCoreVariant &variant2);

////
// SpEnoteImageCore
///
struct SpEnoteImageCore final
{
    /// K" = t_k G + H_n(Ko,C)*Ko   (in the squashed enote model)
    rct::key m_masked_address;
    /// C" = (t_c + x) G + a H
    rct::key m_masked_commitment;
    /// KI = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient})) U
    crypto::key_image m_key_image;

    /// less-than operator for sorting
    bool operator<(const SpEnoteImageCore &other_image) const
    {
        return m_key_image < other_image.m_key_image;
    }

    static std::size_t size_bytes() { return 32*3; }
};
inline const boost::string_ref container_name(const SpEnoteImageCore&) { return "SpEnoteImageCore"; }
void append_to_transcript(const SpEnoteImageCore &container, SpTranscriptBuilder &transcript_inout);

////
// SpInputProposalCore
// - for spending an enote
///
struct SpInputProposalCore final
{
    /// core of the original enote
    SpEnoteCoreVariant m_enote_core;
    /// the enote's key image
    crypto::key_image m_key_image;

    /// k_{mask, sender} + k_{mask, recipient}
    crypto::secret_key m_enote_view_privkey_g;
    /// k_{a, sender} + k_{a, recipient}
    crypto::secret_key m_enote_view_privkey_x;
    /// k_{b, sender} + k_{b, recipient}  (does not include k_s)
    crypto::secret_key m_enote_view_privkey_u;
    /// x
    crypto::secret_key m_amount_blinding_factor;
    /// a
    rct::xmr_amount m_amount;

    /// t_k
    crypto::secret_key m_address_mask;
    /// t_c
    crypto::secret_key m_commitment_mask;

    /// less-than operator for sorting
    bool operator<(const SpInputProposalCore &other_proposal) const { return m_key_image < other_proposal.m_key_image; }

    /**
    * brief: key_image - get this input's key image
    * outparam: key_image_out - KI
    */
    const crypto::key_image& key_image() const { return m_key_image; }

    /**
    * brief: enote_core - get the enote this input proposal represents
    * outparam: enote_out -
    */
    const SpEnoteCoreVariant& enote_core() const { return m_enote_core; }

    /**
    * brief: get_squash_prefix - get this input's enote's squash prefix
    * outparam: squash_prefix_out - H_n(Ko, C)
    */
    void get_squash_prefix(rct::key &squash_prefix_out) const;

    /**
    * brief: get_enote_image_core - get this input's enote image in the squashed enote model
    * outparam: image_out -
    */
    void get_enote_image_core(SpEnoteImageCore &image_out) const;

    /**
    * brief: gen - generate random enote keys
    * param: sp_spend_privkey -
    * param: amount -
    */
    void gen(const crypto::secret_key &sp_spend_privkey, const rct::xmr_amount amount);
};

////
// SpOutputProposalCore
// - for creating an enote to send an amount to someone
///
struct SpOutputProposalCore final
{
    /// Ko
    rct::key m_onetime_address;
    /// y
    crypto::secret_key m_amount_blinding_factor;
    /// b
    rct::xmr_amount m_amount;

    /// less-than operator for sorting
    bool operator<(const SpOutputProposalCore &other_proposal) const
    {
        return memcmp(&m_onetime_address, &other_proposal.m_onetime_address, sizeof(rct::key)) < 0;
    }

    /**
    * brief: onetime_address_is_canonical - check if the onetime address is canonical (prime subgroup)
    */
    bool onetime_address_is_canonical() const;

    /**
    * brief: get_enote_core - get the enote this input proposal represents
    * outparam: enote_out -
    */
    void get_enote_core(SpEnoteCore &enote_out) const;

    /**
    * brief: gen - generate a random proposal
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

} //namespace sp
