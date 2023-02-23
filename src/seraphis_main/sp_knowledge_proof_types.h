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

struct EnoteOwnershipProofV1
{
    rct::key sender_receiver_secret;
    rct::key jamtis_address_spend_key;
    rct::key onetime_address;
}; 

struct EnoteAmountProofV1
{
    rct::xmr_amount amount;
    crypto::secret_key mask;
    rct::key commitment;
};

struct EnoteSentProofV1
{
    EnoteOwnershipProofV1 ownership_proof;
    EnoteAmountProofV1 amount_proof;
};

struct AddressOwnershipProofV1
{
    rct::key message;
    sp::SpCompositionProof composition_proof;
    crypto::key_image key_image_address;
};

struct AddressIndexProofV1
{
    rct::key K_s;
    crypto::secret_key generator;
    jamtis::address_index_t j;
    rct::key K_1;
};

struct EnoteKeyImageProofV1
{
    sp::SpCompositionProof composition_proof;
};

struct TxFundedProofV1
{
    rct::key masked_address;
    sp::SpCompositionProof composition_proof;
    crypto::key_image KI;
};

struct EnoteUnspentProofV1
{
    rct::key KI_transform;
    rct::key x_component;
    rct::key u_component;
    rct::key g_component;
    sp::MatrixProof g_component_proof;
    sp::MatrixProof x_component_transform_proof;
    sp::MatrixProof u_component_proof;
};

struct ReserveProofsV1
{
    std::vector<EnoteOwnershipProofV1> vec_enote_ownership_proof;
    std::vector<EnoteAmountProofV1> vec_amount_proof;
    std::vector<EnoteKeyImageProofV1> vec_ki_proof;
    std::vector<SpEnoteVariant> vec_enotes;
    std::vector<crypto::key_image> vec_ki;
    std::vector<uint64_t> vec_ledger_index;
};

}  // namespace knowledge_proofs
}  // namespace sp
