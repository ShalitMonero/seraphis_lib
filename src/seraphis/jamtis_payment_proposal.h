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

// A 'payment proposal' is a proposal to make an enote sending funds to a Jamtis address


#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_destination.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_extra.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

////
// JamtisPaymentProposalV1
// - for creating an output proposal to send an amount to someone
///
struct JamtisPaymentProposalV1 final
{
    /// user address
    JamtisDestinationV1 m_destination;

    /// b
    rct::xmr_amount m_amount;

    /// enote ephemeral privkey: r
    crypto::secret_key m_enote_ephemeral_privkey;
    
    /// memo elements to add to the tx memo
    TxExtra m_partial_memo;

    /**
    * brief: get_output_proposal_v1 - convert this proposal to a concrete output proposal
    * outparam: output_proposal_out -
    */
    void get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const;

    /**
    * brief: gen - generate a random proposal
    * param: amount -
    * param: num_random_memo_elements -
    */
    void gen(const rct::xmr_amount amount, const std::size_t num_random_memo_elements);
};

////
// JamtisPaymentProposalSelfSendV1
// - for creating an output proposal to send an amount to the tx author
///
struct JamtisPaymentProposalSelfSendV1 final
{
    /// user address
    JamtisDestinationV1 m_destination;

    /// b
    rct::xmr_amount m_amount;

    /// self-send type
    JamtisSelfSendMAC m_type;
    /// enote ephemeral privkey: r
    crypto::secret_key m_enote_ephemeral_privkey;
    /// view-balance privkey: k_vb
    crypto::secret_key m_viewbalance_privkey;

    /// memo elements to add to the tx memo
    TxExtra m_partial_memo;

    /**
    * brief: get_output_proposal_v1 - convert this proposal to a concrete output proposal
    * outparam: output_proposal_out -
    */
    void get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const;

    /**
    * brief: gen - generate a random proposal
    * param: amount -
    * param: type -
    * param: num_random_memo_elements
    */
    void gen(const rct::xmr_amount amount,
        const JamtisSelfSendMAC type,
        const std::size_t num_random_memo_elements);
};

/**
* brief: is_self_send_output_proposal - test if an output proposal is a self-send-type
* param: proposal -
* param: wallet_spend_key -
* param: k_view_balance -
* return: true if it's a self-send proposal (either change or self-spend)
*/
bool is_self_send_output_proposal(const SpOutputProposalV1 &proposal,
    const rct::key &wallet_spend_key,
    const crypto::secret_key &k_view_balance);

} //namespace jamtis
} //namespace sp