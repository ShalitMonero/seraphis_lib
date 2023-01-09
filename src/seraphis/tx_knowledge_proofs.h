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

// Interface for interacting with a context where a tx should be valid (e.g. a ledger).

// Seraphis tx knowledge proofs.

#pragma once

// local headers
#include "seraphis/jamtis_destination.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_validation_context.h"
#include "seraphis_crypto/sp_composition_proof.h"

// third party headers

// standard headers
#include <vector>

namespace sp {

struct SpKnowledgeProofTxSentV1 
{
    std::vector<SpMembershipProofV1> membership_proofs;
    std::vector<SpEnoteImageV1> input_enote_images;
    std::vector<SpImageProofV1> image_proofs;
};

struct SpKnowledgeProofEnoteSentV1 
{
    rct::key one_time_address;
    jamtis::JamtisDestinationV1 destination_address;
    rct::xmr_amount amount;
    crypto::x25519_secret_key enote_ephemeral_privkey;
    rct::key input_context;
};

struct SpKnowledgeProofEnoteOwnershipV1
{
    rct::key one_time_address;
    crypto::key_image fake_key_image;
    sp::SpCompositionProof comp_proof;
};

//TransactionSentProof (SpendProof)

/**
 * brief: generate_sp_tx_spend_proof_v1 - Create SpKnowledgeProofTxSentV1 
 * param: tx_id - Transaction id
 * param: sp_proofs_input_proposals - InputProposal vector
 * param: proofs_preps - MembershipProofPrep vector
 * param: sp_viewbalance_privkey - k_vb -> private view-balance key 
 * param: sp_spend_privkey - k_m -> private master key
 * outparam: - SpKnowledgeProofTxSentV1 struct with proof
 */
SpKnowledgeProofTxSentV1 generate_sp_tx_spend_proof_v1(
    const rct::key &tx_id,
    const std::vector<sp::SpInputProposalV1> &sp_proofs_input_proposals,
    const std::vector<SpMembershipProofPrepV1> &proofs_preps,
    const crypto::secret_key &sp_viewbalance_privkey,
    const crypto::secret_key &sp_spend_privkey);

/**
 * brief: verify_sp_tx_spend_proof_v1 - Verify if SpKnowledgeProofTxSentV1 is valid
 * param: proof - SpKnowledgeProofTxSentV1 struct with proof
 * param: tx - Whole transaction information
 * param: tx_validattion_context - Context of tx
 * outparam: - Boolean (true if valid proof)
 */
bool verify_sp_tx_spend_proof_v1(
    const SpKnowledgeProofTxSentV1 &proof,
    const sp::SpTxSquashedV1 &tx,
    const TxValidationContext &tx_validation_context);

//EnoteSentProof (OutProof)

/**
 * brief: generate_sp_enote_send_proof_v1 - Create SpKnowledgeProofEnoteSentV1 
 * param: enote_ephemeral_privkey - Enote private key
 * param: amount - Amount of enote
 * param: destination_address - Jamtis destination address
 * param: input_context - Input context
 * outparam: - SpKnowledgeProofEnoteSentV1 struct with proof
 */
SpKnowledgeProofEnoteSentV1 generate_sp_enote_send_proof_v1(
    const crypto::x25519_secret_key &enote_ephemeral_privkey,
    const rct::xmr_amount &amount,
    const jamtis::JamtisDestinationV1 &destination_address,
    const rct::key &input_context);  
    
/**
 * brief: verify_sp_enote_send_proof_v1 - Verify if SpKnowledgeProofEnoteSentV1 is valid
 * param: proof - SpKnowledgeProofEnoteSentV1 struct with proof
 * param: enote_tx - Enote exposed
 * param: tx - Transaction where the enote is
 * param: eph_index - Index of ephemeral public key corresponding to tested Enote 
 * outparam: - boolean (true if valid proof)
 */
bool verify_sp_enote_send_proof_v1(
    const SpKnowledgeProofEnoteSentV1 &proof,
    const SpEnoteV1 &enote_tx,
    const sp::SpTxSquashedV1 &tx,
    const size_t &eph_index);
    
//EnoteOwnershipProof (InProof)

/**
 * brief: generate_sp_enote_ownership_proof_v1 - Create SpKnowledgeProofEnoteOwnershipV1
 * param: enote_record - Enote recorded in the wallet with private information
 * param: enote_tx - Enote stored in the blockchain
 * param: k_vb - Private view balance key
 * param: k_m - Private master key
 * outparam: - SpKnowledgeProofEnoteOwnershipV1 struct with proof
 */
SpKnowledgeProofEnoteOwnershipV1 generate_sp_enote_ownership_proof_v1(
    const SpEnoteRecordV1 &enote_record,
    const SpEnoteV1 &enote_tx,
    const crypto::secret_key &k_vb,
    const crypto::secret_key &k_m);

/**
 * brief: verify_sp_enote_ownership_proof_v1 - Verify if SpKnowledgeProofEnoteOwnershipV1 is valid
 * param: proof - SpKnowledgeProofEnoteOwnershipV1 struct with proof
 * param: enote_tx - Enote stored in the blockchain
 * outparam: - boolean (true if valid proof)
 */
bool verify_sp_enote_ownership_proof_v1(
    const SpKnowledgeProofEnoteOwnershipV1 &proof,
    const SpEnoteV1 &enote_tx);

//ReserveProof
//todo

//EnoteUnspentProof
//todo

//Serialize and deserialize

std::string serialize_sp_tx_spend_proof_v1(const SpKnowledgeProofTxSentV1 &proof);

SpKnowledgeProofTxSentV1 deserialize_sp_tx_spend_proof_v1(const std::string &proof, const sp::SpTxSquashedV1 &tx);

std::string serialize_sp_enote_send_proof_v1(const SpKnowledgeProofEnoteSentV1 &proof);

SpKnowledgeProofEnoteSentV1 deserialize_sp_enote_send_proof_v1(const std::string &proof);

std::string serialize_sp_enote_ownership_proof_v1(const SpKnowledgeProofEnoteOwnershipV1 &proof);

SpKnowledgeProofEnoteOwnershipV1 deserialize_sp_enote_ownership_proof_v1(const std::string &proof);


}  // namespace sp