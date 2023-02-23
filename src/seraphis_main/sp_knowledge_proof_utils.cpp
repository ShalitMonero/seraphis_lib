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

//paired header
#include "sp_knowledge_proof_utils.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_crypto/matrix_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "crypto/generators.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/tx_component_types.h"

// standard headers
#include <cstdint>

namespace sp
{
namespace knowledge_proofs
{
static void make_offset(const rct::key &K, crypto::secret_key &offset)
{
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_KNOWLEDGE_PROOFS_OFFSET_V1,
            32,            
        };
    transcript.append("K", K);
    sp_hash_to_scalar(transcript.data(), transcript.size(),to_bytes(offset));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_message_v1(const crypto::key_image &KI, rct::key &message_out)
{
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_KNOWLEDGE_PROOFS_MESSAGE_V1,
            32,            
        };
    transcript.append("KI", KI);
    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_message_v2(const crypto::key_image &KI, const rct::key &onetime_address, rct::key &message_out)
{
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_KNOWLEDGE_PROOFS_MESSAGE_V2,
            2*32,            
        };
    transcript.append("KI", KI);
    transcript.append("Ko", onetime_address);
    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_message_v3(const rct::key &onetime_address, rct::key &message_out)
{
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_KNOWLEDGE_PROOFS_MESSAGE_V3,
            32,            
        };
    transcript.append("Ko", onetime_address);
    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_enote_ownership_proof_v1(const rct::key &sender_receiver_secret,
    const rct::key &jamtis_address_spend_key,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out)
{
    proof_out = EnoteOwnershipProofV1{sender_receiver_secret,jamtis_address_spend_key,onetime_address};
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_ownership_proof_v1(const EnoteOwnershipProofV1 &proof,const SpEnoteVariant &enote)
{
    rct::key one_time_address_out;
    jamtis::make_jamtis_onetime_address(proof.jamtis_address_spend_key, proof.sender_receiver_secret,amount_commitment_ref(enote), one_time_address_out);
    return proof.onetime_address == one_time_address_out;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_amount_proof_v1(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    EnoteAmountProofV1 &proof_out)
{
    proof_out = EnoteAmountProofV1{amount, mask, commitment};
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_amount_proof_v1(const EnoteAmountProofV1 &proof, const rct::key &commitment)
{
    return rct::commit(proof.amount, rct::sk2rct(proof.mask)) == commitment;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_sent_proof_v1(const EnoteOwnershipProofV1 &ownership_proof,
    const EnoteAmountProofV1 &amount_proof,
    EnoteSentProofV1 &proof_out)
{
    proof_out = EnoteSentProofV1{ownership_proof,amount_proof};
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_sent_proof_v1(const EnoteSentProofV1 &proof, const SpEnoteVariant &enote)
{
    return verify_enote_ownership_proof_v1(proof.ownership_proof, enote) &&
            verify_enote_amount_proof_v1(proof.amount_proof, amount_commitment_ref(enote));
}
//-------------------------------------------------------------------------------------------------------------------
// Notice that it works for K_1 or K_S though it is not recommended to perform proofs on the last one
void make_address_ownership_proof_v1(const rct::key &message,
    const rct::key &address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    AddressOwnershipProofV1 &proof_out)
{
    crypto::secret_key k_g_offset;
    make_offset(address, k_g_offset);

    rct::key address_new;
    mask_key(k_g_offset, address,address_new);

    sc_add(to_bytes(k_g_offset),to_bytes(x),to_bytes(k_g_offset)); 

    SpCompositionProof proof;
    make_sp_composition_proof(message, address_new, k_g_offset, y, z, proof);

    crypto::key_image key_image_address;
    make_seraphis_key_image(y,z,key_image_address); 

    proof_out = AddressOwnershipProofV1{message,proof,key_image_address};
}
//-------------------------------------------------------------------------------------------------------------------
void make_address_ownership_proof_v1(const rct::key &address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    AddressOwnershipProofV1 &proof_out)
{
    rct::key message;
    make_message_v3(address,message);
    make_address_ownership_proof_v1(message,address, x, y, z,proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_address_ownership_proof_v1(const AddressOwnershipProofV1 &proof, const rct::key &address)
{
    crypto::secret_key k_g_offset;
    make_offset(address, k_g_offset);

    rct::key address_new;
    mask_key(k_g_offset, address,address_new);

    return verify_sp_composition_proof(proof.composition_proof, proof.message, address_new, proof.key_image_address);
}
//-------------------------------------------------------------------------------------------------------------------
void make_address_index_proof_v1(const rct::key &spend_pubkey,
    const jamtis::address_index_t &j,
    const crypto::secret_key &s_generate_address,
    AddressIndexProofV1 &proof_out)
{
    // k^j_gen = H_32[s_ga](j)
    crypto::secret_key generator;
    make_jamtis_index_extension_generator(s_generate_address, j, generator);

    // jamtis_address_spend_key - K_1 
    rct::key K_1;
    make_jamtis_address_spend_key(spend_pubkey,s_generate_address,j,K_1);

    proof_out = AddressIndexProofV1{spend_pubkey,generator,j,K_1};
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_address_index_proof_v1(const AddressIndexProofV1 &proof)
{
    // Verify that K_1 is properly built from these terms
    // K_1 = k^j_g G + k^j_x X + k^j_u U + K_s
    crypto::secret_key address_extension_key_u;
    crypto::secret_key address_extension_key_x;
    crypto::secret_key address_extension_key_g;

    // k^j_g = H_n("..g..", K_s, j, H_32[s_ga](j))
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_G,
        proof.K_s, proof.j, proof.generator, address_extension_key_g);

    // k^j_u = H_n("..u..", K_s, j, H_32[s_ga](j))
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_U,
        proof.K_s, proof.j, proof.generator, address_extension_key_u);
    
    // k^j_x = H_n("..x..", K_s, j, H_32[s_ga](j))
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_X,
        proof.K_s, proof.j, proof.generator, address_extension_key_x);

    rct::key address_nominal;
    address_nominal = proof.K_s;  //K_s
    extend_seraphis_spendkey_u(address_extension_key_u, address_nominal);      //k^j_u U + K_s
    extend_seraphis_spendkey_x(address_extension_key_x, address_nominal);      //k^j_x X + k^j_u U + K_s
    mask_key(address_extension_key_g, address_nominal, address_nominal);  //k^j_g G + k^j_x X + k^j_u U + K_s
    
    return address_nominal == proof.K_1;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_key_image_proof_v1(const rct::key &onetime_address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    EnoteKeyImageProofV1 &proof_out)
{
    crypto::key_image key_image_address;
    make_seraphis_key_image(y,z,key_image_address); 

    rct::key message;
    make_message_v2(key_image_address,onetime_address,message);

    SpCompositionProof comp_proof;
    make_sp_composition_proof(message, onetime_address, x, y, z, comp_proof);

   proof_out = EnoteKeyImageProofV1{comp_proof};
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_key_image_proof_v1(const EnoteKeyImageProofV1 &proof, const rct::key &onetime_address, const crypto::key_image &KI)
{
    // Verify that enote and key image are the same as stored in the tx by signing
    // the composition proofs with them.
    rct::key message;
    make_message_v2(KI,onetime_address,message);
    return verify_sp_composition_proof(proof.composition_proof, message, onetime_address, KI);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_funded_proof_v1(const rct::key &message,
    const SpEnoteRecordV1 &enote_record,
    const rct::key &onetime_address,
    const crypto::secret_key &k_vb,
    const crypto::secret_key &k_m,
    TxFundedProofV1 &proof_out)
{
    const crypto::secret_key t_k_new = rct::rct2sk(rct::skGen());
    rct::key masked_address;
    rct::addKeys(masked_address, rct::scalarmultBase(rct::sk2rct(t_k_new)),
        onetime_address);
    
    SpCompositionProof comp_proof;
    crypto::secret_key x_new, y_new, z_new;
    sc_add(to_bytes(x_new),to_bytes(enote_record.m_enote_view_extension_g),to_bytes(t_k_new));
    sc_add(to_bytes(y_new),to_bytes(enote_record.m_enote_view_extension_x),to_bytes(k_vb));
    sc_add(to_bytes(z_new),to_bytes(enote_record.m_enote_view_extension_u),to_bytes(k_m));

    make_sp_composition_proof(message, masked_address, x_new, y_new, z_new, comp_proof);

    proof_out = TxFundedProofV1{masked_address,comp_proof,enote_record.m_key_image};
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_funded_proof_v1(const SpEnoteRecordV1 &enote_record,
    const rct::key &onetime_address,
    const crypto::secret_key &k_vb,
    const crypto::secret_key &k_m,
    TxFundedProofV1 &proof_out)
{
    rct::key message;
    make_message_v1(enote_record.m_key_image,message);
    make_tx_funded_proof_v1(message,enote_record,onetime_address,k_vb,k_m,proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_tx_funded_proof_v1(const TxFundedProofV1 &proof, const crypto::key_image KI_enote)
{
    // Verify that enote and key image are the same as stored in the tx by signing
    // the composition proofs with them.
    CHECK_AND_ASSERT_THROW_MES(KI_enote == proof.KI, "verify_tx_funded_v1: expected key image does not match with the proof.");
    rct::key message;
    make_message_v1(KI_enote,message);

    return verify_sp_composition_proof(proof.composition_proof, message, proof.masked_address, proof.KI);
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_unspent_proof_v1(const rct::key &message,
    const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &k_vb,
    const crypto::secret_key &k_m,
    const rct::key &onetime_address,
    const crypto::key_image &KI_test,
    EnoteUnspentProofV1 &proof_out)
{
    // Generate:

    // Expose k_a X,k_b U,k_c G
    // Expose kaKI = (k^o_x + k^j_x + k_vb) KI

    // Original Key image:
    // KI = ((k^o_u + k^j_u + k_m)/(k^o_x + k^j_x + k_vb)) U = (k_b/k_a)U
    // KI_test = key image from enote being tested
    
    // Make proof of knowledge of ka (k^o_x + k^j_x + k_vb) in the bases {X,KI}
    // Make proof of knowledge of kb (k^o_u + k^j_u + k_m) in the base U

    crypto::secret_key ka, kb;
    crypto::secret_key kc{enote_record.m_enote_view_extension_g};
    sc_add(to_bytes(ka),to_bytes(enote_record.m_enote_view_extension_x),to_bytes(k_vb));
    sc_add(to_bytes(kb),to_bytes(enote_record.m_enote_view_extension_u),to_bytes(k_m));

    rct::key kaX, kbU, kcG, kaKI_test;

    rct::scalarmultKey(kaX,rct::pk2rct(crypto::get_X()), rct::sk2rct(ka));
    rct::scalarmultKey(kbU,rct::pk2rct(crypto::get_U()), rct::sk2rct(kb));
    rct::scalarmultKey(kcG,rct::pk2rct(crypto::get_G()), rct::sk2rct(kc));
    rct::scalarmultKey(kaKI_test, rct::ki2rct(KI_test), rct::sk2rct(ka));

    MatrixProof proof_ka,proof_kb,proof_kc;

    make_matrix_proof(message,
     {
        crypto::get_X(),
        rct::rct2pk(rct::ki2rct(KI_test))
        },
         {ka}, proof_ka);

    make_matrix_proof(message, {crypto::get_U()}, {kb}, proof_kb);
    make_matrix_proof(message, {crypto::get_G()}, {kc}, proof_kc);

    proof_out = EnoteUnspentProofV1{kaKI_test,kaX,kbU,kcG, proof_ka,proof_kb,proof_kc};

}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_unspent_proof_v1(const EnoteUnspentProofV1 &proof, const SpEnoteVariant &enote, const crypto::key_image &KI_test)
{
    // Verify that the terms can reconstruct the onetime address
    rct::key Ko_nominal;
    addKeys(Ko_nominal,proof.g_component,proof.x_component);
    addKeys(Ko_nominal,Ko_nominal,proof.u_component);
    CHECK_AND_ASSERT_THROW_MES(Ko_nominal == onetime_address_ref(enote), "Proof does not correspond to Enote.");

    // Verify that proofs corresponding to the bases {X,KI},U,G are correct
    CHECK_AND_ASSERT_THROW_MES(verify_matrix_proof(proof.g_component_proof, 
     {
        crypto::get_X(),
        rct::rct2pk(rct::ki2rct(KI_test))
        }), "verify_enote_unspent_v1: Proof on ka in the bases {X,KI_test} is wrong.");
    
    CHECK_AND_ASSERT_THROW_MES(verify_matrix_proof(proof.x_component_transform_proof, 
    {crypto::get_U()}), "verify_enote_unspent_v1: Proof on kb in the base U is wrong.");

    CHECK_AND_ASSERT_THROW_MES(verify_matrix_proof(proof.u_component_proof,
    {crypto::get_G()}), "verify_enote_unspent_v1: Proof on kc in the base G is wrong.");

    // Verify if k_a KI_test == k_b U,
    // if they are the same, the enote was spent in that tx

    return !(proof.KI_transform == proof.u_component);
}

void make_reserve_proof_v1(const std::vector<EnoteOwnershipProofV1> &vec_ownership_proof,
    const std::vector<EnoteAmountProofV1> &vec_amount_proof,
    const std::vector<EnoteKeyImageProofV1> &vec_ki_proof,
    const std::vector<SpEnoteVariant> &vec_enotes,
    const std::vector<crypto::key_image> &vec_ki,
    const std::vector<uint64_t> &vec_ledger_index,
    ReserveProofsV1 &proof_out)
{
    proof_out = ReserveProofsV1{vec_ownership_proof,
        vec_amount_proof,
        vec_ki_proof,
        vec_enotes,
        vec_ki,
        vec_ledger_index};
}

bool verify_reserve_proof_v1(const ReserveProofsV1 &proof) 
{
    // Very important:
    // Verify that enotes are in the ledger (check enote squashed)
    // NOT DONE HERE

    // Very important:
    // Verify that key images are not in the ledger
    // NOT DONE HERE

    const size_t number_proofs{proof.vec_enote_ownership_proof.size()};

    // Verify that proofs are valid
    for (size_t i=0;i<number_proofs;i++)
    {
        CHECK_AND_ASSERT_THROW_MES(verify_enote_ownership_proof_v1(proof.vec_enote_ownership_proof[i],
            proof.vec_enotes[i]),
            "verify reserve proofs: Enote_ownership proof is wrong.");
        CHECK_AND_ASSERT_THROW_MES(verify_enote_amount_proof_v1(proof.vec_amount_proof[i],
            amount_commitment_ref(proof.vec_enotes[i])),
            "verify reserve proofs: Enote_amount proof is wrong.");
        CHECK_AND_ASSERT_THROW_MES(verify_enote_key_image_proof_v1(proof.vec_ki_proof[i],
            onetime_address_ref(proof.vec_enotes[i]),
                proof.vec_ki[i]),
            "verify reserve proofs: Enote_key_image proof is wrong.");
    }
    return true;
}

}
}