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
#include "seraphis/tx_base.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/enote_record_types.h"
#include "seraphis/tx_validation_context.h"
#include "seraphis_crypto/sp_composition_proof.h"

// third party headers

// standard headers
#include <vector>

namespace sp {



struct EnoteOwnershipProofV1
{
    rct::key q;
    rct::key K_1;
    rct::key Ko;
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

EnoteOwnershipProofV1 generate_knowledge_proof_enote_ownership_v1(const rct::key &q, const rct::key &K_1, const rct::key &Ko);

bool verify_knowledge_proof_enote_ownership_v1(const EnoteOwnershipProofV1 &proof,const SpEnoteV1 &Enote);

EnoteAmountProofV1 generate_knowledge_proof_enote_amount_v1(const rct::xmr_amount &amount, const crypto::secret_key &mask, const rct::key &commitment);

bool verify_knowledge_proof_enote_amount_v1(const EnoteAmountProofV1 &proof, const rct::key &commitment);

EnoteSentProofV1 generate_knowledge_proof_enote_sent_v1(const EnoteOwnershipProofV1 &ownership_proof, const EnoteAmountProofV1 &amount_proof);

bool verify_knowledge_proof_enote_sent_v1(const EnoteSentProofV1 &proof, const SpEnoteV1 &Enote);


}  // namespace sp