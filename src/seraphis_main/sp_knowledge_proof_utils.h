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
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/matrix_proof.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/tx_validation_context.h"
#include "seraphis_crypto/sp_composition_proof.h"

// third party headers

// standard headers
#include <vector>

namespace sp 
{
namespace knowledge_proofs
{

/**
* brief: generate enote ownership knowledge proof
* param: sender_receiver_secret - q 
* param: jamtis_address_spend_key - K_1 
* param: onetime_address - Ko 
* outparam: EnoteOwnershipProofV1 struct
*/
void make_enote_ownership_proof_v1(const rct::key &sender_receiver_secret,
    const rct::key &jamtis_address_spend_key,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out);
/**
* brief: verify enote ownership knowledge proof
* param: proof - EnoteOwnershipProofV1 struct with the proof
* param: enote - Enote related to the proof
* return: true/false according to proof validity 
*/
bool verify_enote_ownership_proof_v1(const EnoteOwnershipProofV1 &proof,
    const SpEnoteVariant &enote);

/**
* brief: generate enote amount knowledge proof
* param: amount - xmr amount a
* param: mask - blinding factor x
* param: commitment - C = xG+aH
* outparam: EnoteAmountProofV1 struct
*/
void make_enote_amount_proof_v1(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    EnoteAmountProofV1 &proof_out);
/**
* brief: verify enote amount knowledge proof
* param: proof - EnoteAmountProofV1 struct with the proof
* param: commitment - Enote amount commitment
* return: true/false according to proof validity 
*/
bool verify_enote_amount_proof_v1(const EnoteAmountProofV1 &proof,
    const rct::key &commitment);

/**
* brief: generate enote sent knowledge proof
* param: ownership_proof - proof of enote ownership
* param: amount_proof - proof of enote amount
* outparam: EnoteSentProofV1 struct
*/
void make_enote_sent_proof_v1(const EnoteOwnershipProofV1 &ownership_proof,
    const EnoteAmountProofV1 &amount_proof,
    EnoteSentProofV1 &proof_out);
/**
* brief: verify enote sent knowledge proof
* param: proof - EnoteSentProofV1 struct with the proof
* param: enote - Enote related to the proof
* return: true/false according to proof validity 
*/
bool verify_enote_sent_proof_v1(const EnoteSentProofV1 &proof,
    const SpEnoteVariant &enote);

/**
* brief: generate address ownership knowledge proof
* param: message - message provided by verifier
* param: address - address which has the format xG + yX + zU. It can be K_1 (recommended) or K_1_base (K_s).
* param: x - secret key corresponding to base G
* param: y - secret key corresponding to base X
* param: z - secret key corresponding to base U
* outparam: AddressOwnershipProofV1 struct
*/
void make_address_ownership_proof_v1(const rct::key &message,
    const rct::key &address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    AddressOwnershipProofV1 &proof_out);
void make_address_ownership_proof_v1(const rct::key &address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    AddressOwnershipProofV1 &proof_out);
/**
* brief: verify address ownership knowledge proof
* param: proof - AddressOwnershipProofV1 struct with the proof
* param: address - Initial address being proved 
* return: true/false according to proof validity 
*/
bool verify_address_ownership_proof_v1(const AddressOwnershipProofV1 &proof,
    const rct::key &address);

/**
* brief: generate address index knowledge proof
* param: spend_pubkey - K_s = k_vb X + k_m U
* param: j - address index
* param: s_generate_address - s_ga
* outparam: AddressIndexProofV1 struct
*/
void make_address_index_proof_v1(const rct::key &spend_pubkey,
    const jamtis::address_index_t &j,
    const crypto::secret_key &s_generate_address,
    AddressIndexProofV1 &proof_out);
/**
* brief: verify address index knowledge proof
* param: proof - AddressIndexProofV1 struct with the proof
* return: true/false according to proof validity 
*/
bool verify_address_index_proof_v1(const AddressIndexProofV1 &proof);

/**
* brief: generate enote key image knowledge proof
* param: onetime_address - address which has the format xG + yX + zU. 
* param: x - secret key corresponding to base G
* param: y - secret key corresponding to base X
* param: z - secret key corresponding to base U
* outparam: EnoteKeyImageProofV1 struct
*/
void make_enote_key_image_proof_v1(const rct::key &onetime_address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    EnoteKeyImageProofV1 &proof_out);
/**
* brief: verify enote key image knowledge proof
* param: proof - EnoteKeyImageProofV1 struct with the proof
* param: onetime_address - address which has the format xG + yX + zU. 
* param: KI - Key image corresponding to the onetime_address 
* return: true/false according to proof validity 
*/
bool verify_enote_key_image_proof_v1(const EnoteKeyImageProofV1 &proof,
    const rct::key &onetime_address,
    const crypto::key_image &KI);

/**
* brief: generate funded tx knowledge proof
* param: message - message signing the proof
* param: enote_record - enote_record containing all the mask openings 
* param: onetime_address - address which has the format xG + yX + zU. 
* param: k_vb - view_balance secret key 
* param: k_m - master secret key 
* outparam: TxFundedProofV1 struct
*/
void make_tx_funded_proof_v1(const rct::key &message,
    const SpEnoteRecordV1 &enote_record,
    const rct::key &onetime_address,
    const crypto::secret_key &k_vb,
    const crypto::secret_key &k_m,
    TxFundedProofV1 &proof_out);
void make_tx_funded_proof_v1(const SpEnoteRecordV1 &enote_record,
    const rct::key &onetime_address,
    const crypto::secret_key &k_vb,
    const crypto::secret_key &k_m,
    TxFundedProofV1 &proof_out);
/**
* brief: verify funded tx knowledge proof
* param: proof - TxFundedProofV1 struct with the proof
* param: KI_enote - Key image from enote in that tx
* return: true/false according to proof validity 
*/
bool verify_tx_funded_proof_v1(const TxFundedProofV1 &proof,
    const crypto::key_image KI_enote);

/**
* brief: generate enote unspent knowledge proof
* param: message - message signing the proof
* param: enote_record - enote_record containing all the mask openings 
* param: k_vb - view_balance secret key 
* param: k_m - master secret key 
* param: onetime_address - address which has the format xG + yX + zU. 
* param: KI_test - Key image from enote in that tx
* outparam: EnoteUnspentProofV1 struct
*/
void make_enote_unspent_proof_v1(const rct::key &message,
    const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &k_vb,
    const crypto::secret_key &k_m,
    const rct::key &onetime_address,
    const crypto::key_image &KI_test,
    EnoteUnspentProofV1 &proof_out);
/**
* brief: verify enote unspent knowledge proof
* param: proof - EnoteUnspentProofV1 struct with the proof
* param: enote - Enote being tested 
* param: KI_enote - Key image from enote being tested
* return: true/false according to proof validity 
*/
bool verify_enote_unspent_proof_v1(const EnoteUnspentProofV1 &proof,
    const SpEnoteVariant &enote,
    const crypto::key_image &KI_test);

/**
* brief: generate reserve proof
* param: vec_ownership_proof - vector with all ownership proofs
* param: vec_amount_proof - vector with all amount proofs
* param: vec_key_image_proof- vector with all key_images proofs
* param: vec_enotes - vector with all enotes being tested
* param: vec_ki - vector with all key images corresponding to the enotes being tested
* param: vec_ledger index - vector with all indices of enotes 
* outparam: ReserveProofsV1 struct
*/
void make_reserve_proof_v1(const std::vector<EnoteOwnershipProofV1> &vec_ownership_proof,
    const std::vector<EnoteAmountProofV1> &vec_amount_proof,
    const std::vector<EnoteKeyImageProofV1> &vec_ki_proof,
    const std::vector<SpEnoteVariant> &vec_enotes,
    const std::vector<crypto::key_image> &vec_ki,
    const std::vector<uint64_t> &vec_ledger_index,
    ReserveProofsV1 &proof_out);

/**
* brief: verify reserve proof
* param: proof - ReserveProofsV1 struct with the proof
* return: true/false according to proof validity 
*/
bool verify_reserve_proof_v1(const ReserveProofsV1 &proof);

}  // namespace knowledge_proofs
}  // namespace sp