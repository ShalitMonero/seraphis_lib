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

#include "seraphis/knowledge_proofs.h"
#include "seraphis_core/jamtis_enote_utils.h"

namespace sp
{

EnoteOwnershipProofV1 generate_knowledge_proof_enote_ownership_v1(const rct::key &q, const rct::key &K_1, const rct::key &Ko)
{
    return EnoteOwnershipProofV1{q,K_1,Ko};
}

bool verify_knowledge_proof_enote_ownership_v1(const EnoteOwnershipProofV1 &proof,const SpEnoteV1 &Enote)
{
    rct::key one_time_address_out;
    jamtis::make_jamtis_onetime_address(proof.q,Enote.m_core.m_amount_commitment , proof.K_1 , one_time_address_out);
    return proof.Ko == one_time_address_out;
}

EnoteAmountProofV1 generate_knowledge_proof_enote_amount_v1(const rct::xmr_amount &amount, const crypto::secret_key &mask, const rct::key &commitment)
{
    return EnoteAmountProofV1{amount, mask, commitment};
}

bool verify_knowledge_proof_enote_amount_v1(const EnoteAmountProofV1 &proof, const rct::key &commitment)
{
    rct::key test_commitment{rct::commit(proof.amount, rct::sk2rct(proof.mask))};
    return test_commitment == commitment;
}


EnoteSentProofV1 generate_knowledge_proof_enote_sent_v1(const EnoteOwnershipProofV1 &ownership_proof, const EnoteAmountProofV1 &amount_proof)
{
    return EnoteSentProofV1{ownership_proof,amount_proof};
}

bool verify_knowledge_proof_enote_sent_v1(const EnoteSentProofV1 &proof, const SpEnoteV1 &Enote)
{
    return verify_knowledge_proof_enote_ownership_v1(proof.ownership_proof, Enote) &&
            verify_knowledge_proof_enote_amount_v1(proof.amount_proof, Enote.m_core.m_amount_commitment);
}





}