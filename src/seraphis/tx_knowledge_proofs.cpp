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

// paired header
#include "tx_knowledge_proofs.h"

// local headers
#include "common/base58.h"
#include "common/container_helpers.h"
#include "crypto/crypto-ops.h"
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/serialization_demo_types.h"
#include "seraphis/serialization_demo_utils.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_validation_context.h"
#include "seraphis/txtype_squashed_v1.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "serialization/binary_utils.h"

// third party headers

// standard headers
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp 
{

//-------------------------------------------------------------------------------------------------------------------
//Static functions
//-------------------------------------------------------------------------------------------------------------------
static void encode_next_info(std::string &proof, const std::string encoded_temp) 
{
    proof.append(std::to_string(encoded_temp.size()))
        .append("/")
        .append(encoded_temp)
        .append("/");
}
//-------------------------------------------------------------------------------------------------------------------
static std::string decode_next_info_and_update_offset(
    uint64_t &offset, const std::string encoded_proof) 
{
    std::string decoded_temp{}, encoded_info{}, next_str{};
    size_t pos_bar, pos_bar_info;

    pos_bar = encoded_proof.find("/", offset);
    next_str = encoded_proof.substr(offset, pos_bar - offset);
    pos_bar_info = encoded_proof.find("/", offset + next_str.size() + 1);
    encoded_info = encoded_proof.substr(pos_bar + 1, pos_bar_info - offset - next_str.size() - 1);
    tools::base58::decode(encoded_info, decoded_temp);
    offset = pos_bar_info + 1;
    return decoded_temp;
}
//-------------------------------------------------------------------------------------------------------------------
static void make_tx_knowledge_proof_tx_spend_message_v1(
    const rct::key &tx_id,
    const std::vector<sp::SpEnoteImageV1> &sp_proofs_input_images,
    const std::vector<sp::SpMembershipProofV1> &sp_membership_proofs,
    rct::key &tx_proofs_prefix_out) 
{
    sp::SpFSTranscript transcript{
        config::HASH_KEY_SERAPHIS_KNOWLEDGE_PROOFS_PREFIX_V1,
        32 + sp_proofs_input_images.size() * sp_enote_image_v1_size_bytes() +
            sp_membership_proofs.size() *
                sp_membership_proof_v1_size_bytes(sp_membership_proofs[0])};
    transcript.append("tx_id", tx_id);
    transcript.append("sp_input_images", sp_proofs_input_images);
    transcript.append("sp_membership_proofs", sp_membership_proofs);

    sp_hash_to_32(transcript.data(), transcript.size(),
                  tx_proofs_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
static void make_tx_knowledge_proof_enote_ownership_message_v1(
    const rct::key &enote_one_time_address,
    const crypto::secret_key &k_extra,
    const crypto::key_image &key_image_fake,
    rct::key &message_out) 
{
    sp::SpFSTranscript transcript{
        config::HASH_KEY_SERAPHIS_KNOWLEDGE_PROOFS_PREFIX_V1, 32*3};

    transcript.append("one_time_address", enote_one_time_address);
    transcript.append("k_extra", k_extra);
    transcript.append("key_image_fake", key_image_fake);

    sp_hash_to_32(transcript.data(), transcript.size(),
                  message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
static void get_one_time_address_hash(const rct::key &one_time_address, crypto::secret_key &k_extra_out)
{
    sp::SpFSTranscript transcript{
        config::HASH_KEY_SERAPHIS_KNOWLEDGE_PROOFS_PREFIX_V1, 32};

    transcript.append("one_time_address", one_time_address);

    rct::key key_out;
    sp_hash_to_scalar(transcript.data(), transcript.size(), key_out.bytes);
    //Verify that k_extra !=0 to not expose the real key image
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(key_out.bytes), "Hash of one-time-address must be nonzero!");

    k_extra_out = rct::rct2sk(key_out);
}

//-------------------------------------------------------------------------------------------------------------------
//TransactionSentProof (SpendProof)
//-------------------------------------------------------------------------------------------------------------------

SpKnowledgeProofTxSentV1 generate_sp_tx_spend_proof_v1(
    const rct::key &tx_id,
    const std::vector<sp::SpInputProposalV1> &sp_proofs_input_proposals,
    const std::vector<sp::SpMembershipProofPrepV1> &proofs_preps,
    const crypto::secret_key &sp_viewbalance_privkey,
    const crypto::secret_key &sp_spend_privkey)
{

    rct::key message;
    std::vector<SpEnoteImageV1> sp_audit_proofs_input_images;
    std::vector<SpAlignableMembershipProofV1>
        sp_audit_proofs_alignable_membership_proofs;
    std::vector<SpMembershipProofV1> sp_audit_proofs_membership_proofs;
    std::vector<SpImageProofV1> sp_audit_proofs_image_proofs;

    std::size_t proof_size = sp_proofs_input_proposals.size();

    // Get Enote Images from enotes in the input proposals
    for (std::size_t enote_index = 0; enote_index < proof_size; enote_index++) 
    {
        sp_audit_proofs_input_images.emplace_back();
        get_enote_image_v1(sp_proofs_input_proposals[enote_index],
                           sp_audit_proofs_input_images.back());
    }

    make_v1_alignable_membership_proofs_v1(
        std::move(proofs_preps), sp_audit_proofs_alignable_membership_proofs);

    align_v1_membership_proofs_v1(
        sp_audit_proofs_input_images,
        std::move(sp_audit_proofs_alignable_membership_proofs),
        sp_audit_proofs_membership_proofs);

    make_tx_knowledge_proof_tx_spend_message_v1(tx_id, sp_audit_proofs_input_images,
                                  sp_audit_proofs_membership_proofs, message);

    // Sign composition proof with message including tx_id and key_images.
    make_v1_image_proofs_v1(sp_proofs_input_proposals, message,
                            sp_spend_privkey, sp_viewbalance_privkey,
                            sp_audit_proofs_image_proofs);

    return SpKnowledgeProofTxSentV1{sp_audit_proofs_membership_proofs,sp_audit_proofs_input_images,sp_audit_proofs_image_proofs};
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_sp_tx_spend_proof_v1(const SpKnowledgeProofTxSentV1 &proof, const sp::SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context)
{
    std::vector<const SpMembershipProofV1 *> sp_membership_proof_ptrs;
    std::vector<const SpEnoteImageCore *> sp_input_image_ptrs;
    size_t proof_size = proof.input_enote_images.size();

    //Proofs must be aligned with tx
    for (size_t i=0;i<proof_size;i++)
    {
        //Verify that the input key images are the same as recorded in the tx
        CHECK_AND_ASSERT_THROW_MES(tx.m_sp_input_images[i].m_core.m_key_image == proof.input_enote_images[i].m_core.m_key_image,
         "Key images in the proof do not represent key images in the transaction.");

        //Verify that the composition proofs are not the same as recorded in the tx
        CHECK_AND_ASSERT_THROW_MES(!(tx.m_sp_image_proofs[i].m_composition_proof == proof.image_proofs[i].m_composition_proof),
         "Failed. The composition proof is the same as in the transaction.");
    }

    for (size_t i = 0; i<proof_size; i++)
    {
        sp_membership_proof_ptrs.push_back(&proof.membership_proofs[i]);
        sp_input_image_ptrs.push_back(
            &proof.input_enote_images[i].m_core);
    }

    rct::key tx_id;
    get_sp_squashed_v1_txid(tx, tx_id);

    rct::key message;
    make_tx_knowledge_proof_tx_spend_message_v1(tx_id, proof.input_enote_images,
                                  proof.membership_proofs, message);

    // Check if the composition proofs are valid
    bool validated_composition_proofs = validate_sp_composition_proofs_v1(
        proof.image_proofs, proof.input_enote_images,
        message);

    // Check if the membership proofs are valid
    std::list<SpMultiexpBuilder> validation_data_out;
    try_get_sp_membership_proofs_v1_validation_data(
        sp_membership_proof_ptrs, sp_input_image_ptrs, tx_validation_context,
        validation_data_out);

    bool validated_membership_proofs =
        SpMultiexp{validation_data_out}.evaluates_to_point_at_infinity();

    // If both are valid then spend_proof is valid
    return (validated_membership_proofs && validated_composition_proofs);
}

//-------------------------------------------------------------------------------------------------------------------
//EnoteSentProof (OutProof)
//-------------------------------------------------------------------------------------------------------------------

SpKnowledgeProofEnoteSentV1 generate_sp_enote_send_proof_v1(const crypto::x25519_secret_key &enote_ephemeral_privkey, const rct::xmr_amount &amount, const jamtis::JamtisDestinationV1 &destination_address, const rct::key &input_context)
{
    jamtis::JamtisPaymentProposalV1 payment_proposal{destination_address,amount,enote_ephemeral_privkey,{}};

    //convert payment proposal to SpOutputProposalV1
    SpOutputProposalV1 output_proposal;
    jamtis::get_output_proposal_v1(payment_proposal, input_context, output_proposal);

    return SpKnowledgeProofEnoteSentV1{output_proposal.m_core.m_onetime_address,destination_address,amount,enote_ephemeral_privkey,input_context};
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_sp_enote_send_proof_v1(const SpKnowledgeProofEnoteSentV1 &proof, const SpEnoteV1 &enote_tx, const sp::SpTxSquashedV1 &tx, const size_t &eph_index)
{
    //verify if ephemeral public key is the same
    crypto::x25519_pubkey test_ephemeral_pubkey;
    x25519_scmul_key(proof.enote_ephemeral_privkey, proof.destination_address.m_addr_K3, test_ephemeral_pubkey);
    CHECK_AND_ASSERT_THROW_MES(tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys[eph_index] == test_ephemeral_pubkey,
         "Transaction ephemeral public key and generated ephemeral public key are not the same");
    
    //make a Jamtis payment proposal
    jamtis::JamtisPaymentProposalV1 payment_proposal{proof.destination_address,proof.amount,proof.enote_ephemeral_privkey,{}};

    //convert payment proposal to SpOutputProposalV1
    SpOutputProposalV1 output_proposal;
    jamtis::get_output_proposal_v1(payment_proposal, proof.input_context, output_proposal);

    //extract SpEnoteV1
    SpEnoteV1 enote_test;
    get_enote_v1(output_proposal, enote_test);

    return (enote_tx == enote_test);
}

//-------------------------------------------------------------------------------------------------------------------
//EnoteOwnershipProof (InProof)
//-------------------------------------------------------------------------------------------------------------------

SpKnowledgeProofEnoteOwnershipV1 generate_sp_enote_ownership_proof_v1(const SpEnoteRecordV1 &enote_record, const SpEnoteV1 &enote_tx, const crypto::secret_key &k_vb, const crypto::secret_key &k_m)
{
    //Given that the prover knows everything about the real enote K = k_g G + (k_x + k_a) X + (k_u + k_b) U 
    //The prover will generate the fake enote K' = K+ k_extra X = k_g G + (k_x + k_a + k_extra) X + (k_u + k_b) U
    //Which has the fake key image KI' = ((k_u + k_b) / (k_x + k_a + k_extra)) U
    //Then a composition proof will be made on K' and KI'

    crypto::secret_key k_extra; 
    get_one_time_address_hash(enote_tx.m_core.m_onetime_address, k_extra);

    //Prepare secret keys for fake enote
    //x = k_g
    //y = k_x + k_vb + k_extra
    //z = k_u + k_m
    crypto::secret_key x,y,z;
    x = enote_record.m_enote_view_extension_g;
    sc_add(to_bytes(y), to_bytes(enote_record.m_enote_view_extension_x), to_bytes(k_vb)); 
    sc_add(to_bytes(y), to_bytes(y), to_bytes(k_extra)); 
    sc_add(to_bytes(z), to_bytes(enote_record.m_enote_view_extension_u), to_bytes(k_m));

    //Get fake key image KI' = ((k_u + k_m)/(k_x + k_vb + k_extra)) U
    crypto::key_image fake_key_image;
    make_seraphis_key_image(y, z, fake_key_image);

    //Make message
    rct::key message;
    make_tx_knowledge_proof_enote_ownership_message_v1(enote_tx.m_core.m_onetime_address,k_extra,fake_key_image,message);

    //Make fake enote K'
    rct::key K_fake;
    rct::scalarmultKey(K_fake,rct::pk2rct(crypto::get_X()),rct::sk2rct(k_extra));
    rct::addKeys(K_fake,K_fake,enote_tx.m_core.m_onetime_address);
    
    //Make seraphis composition proof
    sp::SpCompositionProof proof;
    make_sp_composition_proof(message,
        K_fake,
        x,
        y,
        z,
        proof);

    return SpKnowledgeProofEnoteOwnershipV1{enote_tx.m_core.m_onetime_address,fake_key_image,proof};
}

//-------------------------------------------------------------------------------------------------------------------
bool verify_sp_enote_ownership_proof_v1(const SpKnowledgeProofEnoteOwnershipV1 &proof, const SpEnoteV1 &enote_tx)
{
    //Recover k_extra from enote one_time_address
    crypto::secret_key k_extra; 
    get_one_time_address_hash(enote_tx.m_core.m_onetime_address, k_extra);

    //Make message
    rct::key message;
    make_tx_knowledge_proof_enote_ownership_message_v1(enote_tx.m_core.m_onetime_address,k_extra,proof.fake_key_image,message);

    //Recreate supposed fake enote
    rct::key K_fake;
    rct::scalarmultKey(K_fake,rct::pk2rct(crypto::get_X()),rct::sk2rct(k_extra));
    rct::addKeys(K_fake,K_fake,enote_tx.m_core.m_onetime_address);

    //Verify composition proof 
    // If the composition proof is valid, then the prover must know the openings for the 
    // fake enote K' = K + k_extra X = k_g G + (k_x + k_a + k_extra) X + (k_u + k_b) U
    // and therefore he must know also the openings of the real enote.
    return (verify_sp_composition_proof(proof.comp_proof,
    message,
    K_fake,
    proof.fake_key_image));
}


//-------------------------------------------------------------------------------------------------------------------
//Serialize and deserialize proofs
//-------------------------------------------------------------------------------------------------------------------

std::string serialize_sp_tx_spend_proof_v1(const SpKnowledgeProofTxSentV1 &proof)
{
    sp::serialization::ser_SpMembershipProofV1_PARTIAL
        serializable_membership_proof;
    sp::serialization::ser_SpEnoteImageV1 serializable_input_image;
    sp::serialization::ser_SpImageProofV1 serializable_image_proof;
    std::vector<std::string> serialized_membership_proof;
    std::vector<std::string> serialized_input_images;
    std::vector<std::string> serialized_image_proof;

    std::size_t proof_size = proof.image_proofs.size();

    // Serialize
    for (std::size_t i = 0; i < proof_size; i++) 
    {
        serialized_membership_proof.emplace_back();
        serialized_input_images.emplace_back();
        serialized_image_proof.emplace_back();

        sp::serialization::make_serializable_sp_membership_proof_v1(
            proof.membership_proofs[i], serializable_membership_proof);
        sp::serialization::make_serializable_sp_enote_image_v1(
            proof.input_enote_images[i], serializable_input_image);
        sp::serialization::make_serializable_sp_image_proof_v1(
            proof.image_proofs[i], serializable_image_proof);

        CHECK_AND_ASSERT_THROW_MES(sp::serialization::try_append_serializable(
                                       serializable_membership_proof,
                                       serialized_membership_proof.back()),
                                   "Error with membership proof serialization");
        CHECK_AND_ASSERT_THROW_MES(
            sp::serialization::try_append_serializable(
                serializable_input_image, serialized_input_images.back()),
            "Error with image proof serialization");
        CHECK_AND_ASSERT_THROW_MES(
            sp::serialization::try_append_serializable(
                serializable_image_proof, serialized_image_proof.back()),
            "Error with image proof serialization");
    }

    // The proof consists of:
    // Header: SpKnowledgeProofTxSentV1
    //  N (where N is the number of enotes being proved) chunks containing:
    //  membership_proof
    //  input_image
    //  image_proof
    //
    // The format of each field is:  /<size>/<field_base58>

    std::string out_proof{};
    std::string encoded_temp{};
    for (size_t N = 0; N < proof_size; N++) 
    {
        encoded_temp = tools::base58::encode(serialized_membership_proof[N]);
        encode_next_info(out_proof, encoded_temp);
        encoded_temp = tools::base58::encode(serialized_input_images[N]);
        encode_next_info(out_proof, encoded_temp);
        encoded_temp = tools::base58::encode(serialized_image_proof[N]);
        encode_next_info(out_proof, encoded_temp);
    }

    // Save into file should be part of the wallet

    return std::string{std::string{"SpKnowledgeProofTxSentV1"} + out_proof};
}
//-------------------------------------------------------------------------------------------------------------------
SpKnowledgeProofTxSentV1 deserialize_sp_tx_spend_proof_v1(const std::string &proof, const sp::SpTxSquashedV1 &tx)
{
    size_t proof_size = tx.m_sp_input_images.size();

    // Check if header is the same (SpKnowledgeProofTxSentV1)
    std::string header{"SpKnowledgeProofTxSentV1"};
    CHECK_AND_ASSERT_THROW_MES(
        proof.substr(0, header.size()).compare(header) == 0,
        "Header is different");

    std::string encoded_proof = proof.substr(header.size());

    std::vector<std::string> serialized_membership_proof;
    std::vector<std::string> serialized_input_images;
    std::vector<std::string> serialized_image_proof;

    uint64_t offset{0};
    for (size_t i = 0; i < proof_size; i++) 
    {
        serialized_membership_proof.push_back(
            decode_next_info_and_update_offset(offset, encoded_proof));
        serialized_input_images.push_back(
            decode_next_info_and_update_offset(offset, encoded_proof));
        serialized_image_proof.push_back(
            decode_next_info_and_update_offset(offset, encoded_proof));
    }

    sp::serialization::ser_SpMembershipProofV1_PARTIAL
        serializable_membership_proof_recovered;
    sp::serialization::ser_SpEnoteImageV1 serializable_input_image_recovered;
    sp::serialization::ser_SpImageProofV1 serializable_image_proof_recovered;

    std::vector<SpMembershipProofV1> sp_membership_proofs_recovered;
    std::vector<SpEnoteImageV1> sp_proofs_input_images_recovered;
    std::vector<SpImageProofV1> sp_image_proofs_recovered;


    sp_membership_proofs_recovered.reserve(proof_size);
    sp_image_proofs_recovered.reserve(proof_size);
    sp_proofs_input_images_recovered.reserve(proof_size);

    rct::key generator_seed_temp;

    for (size_t i = 0; i < proof_size; i++) 
    {
        CHECK_AND_ASSERT_THROW_MES(
            sp::serialization::try_get_serializable(
                epee::strspan<std::uint8_t>(serialized_membership_proof[i]),
                serializable_membership_proof_recovered),
            "Error with membership proof serialization.");
        CHECK_AND_ASSERT_THROW_MES(
            sp::serialization::try_get_serializable(
                epee::strspan<std::uint8_t>(serialized_input_images[i]),
                serializable_input_image_recovered),
            "Error with input image serialization.");
        CHECK_AND_ASSERT_THROW_MES(
            sp::serialization::try_get_serializable(
                epee::strspan<std::uint8_t>(serialized_image_proof[i]),
                serializable_image_proof_recovered),
            "Error with image proof serialization.");

        // Recover enote_images so it can be used to recover the membership proofs
        sp::serialization::recover_sp_enote_image_v1(
            serializable_input_image_recovered,
            tools::add_element(sp_proofs_input_images_recovered));

        // Check if key_images are the same as the original tx
        CHECK_AND_ASSERT_THROW_MES(
            tx.m_sp_input_images[i].m_core.m_key_image ==
                sp_proofs_input_images_recovered[i].m_core.m_key_image,
            "Passed key image and transaction key image are not the same.");

        make_binned_ref_set_generator_seed_v1(
            sp_proofs_input_images_recovered[i].m_core.m_masked_address,
            sp_proofs_input_images_recovered[i].m_core.m_masked_commitment,
            generator_seed_temp);

        SpBinnedReferenceSetConfigV1 sp_binned_ref_recovered =
            tx.m_sp_membership_proofs[i].m_binned_reference_set.m_bin_config;

        sp::serialization::recover_sp_membership_proof_v1(
            serializable_membership_proof_recovered, sp_binned_ref_recovered,
            generator_seed_temp,
            tx.m_sp_membership_proofs[i].m_ref_set_decomp_n,
            tx.m_sp_membership_proofs[i].m_ref_set_decomp_m,
            tools::add_element(sp_membership_proofs_recovered));

        sp::serialization::recover_sp_image_proof_v1(
            serializable_image_proof_recovered,
            tools::add_element(sp_image_proofs_recovered));

    }

    return SpKnowledgeProofTxSentV1{sp_membership_proofs_recovered,sp_proofs_input_images_recovered,sp_image_proofs_recovered};

}
//-------------------------------------------------------------------------------------------------------------------
std::string serialize_sp_enote_send_proof_v1(const SpKnowledgeProofEnoteSentV1 &proof)
{
    std::string serialized_proof;
    serialization::ser_SpKnowledgeProofEnoteSentV1 serializable_proof;

    sp::serialization::make_serializable_sp_knowledge_proof_enote_send_v1(
        proof, serializable_proof);

    CHECK_AND_ASSERT_THROW_MES(sp::serialization::try_append_serializable(
                                    serializable_proof,
                                    serialized_proof),
                                "Error EnoteSentV1 proof serialization");

    return std::string{std::string{"SpKnowledgeProofEnoteSentV1"} + serialized_proof};
}
//-------------------------------------------------------------------------------------------------------------------
SpKnowledgeProofEnoteSentV1 deserialize_sp_enote_send_proof_v1(const std::string &proof)
{
    // Check if header is the same 
    std::string header{"SpKnowledgeProofEnoteSentV1"};
    CHECK_AND_ASSERT_THROW_MES(
        proof.substr(0, header.size()).compare(header) == 0,
        "Header is different");

    std::string encoded_proof = proof.substr(header.size());

    serialization::ser_SpKnowledgeProofEnoteSentV1 serializable_proof;
    SpKnowledgeProofEnoteSentV1 recovered_proof;

    CHECK_AND_ASSERT_THROW_MES(
        sp::serialization::try_get_serializable(
            epee::strspan<std::uint8_t>(encoded_proof),
            serializable_proof),
        "Error with EnoteSentV1 proof deserialization.");

    serialization::recover_sp_knowledge_proof_enote_send_v1(serializable_proof, recovered_proof);

    return recovered_proof;
}

std::string serialize_sp_enote_ownership_proof_v1(const SpKnowledgeProofEnoteOwnershipV1 &proof)
{
    std::string serialized_proof;
    serialization::ser_SpKnowledgeProofEnoteOwnershipV1 serializable_proof;

    sp::serialization::make_serializable_sp_knowledge_proof_enote_ownership_v1(
        proof, serializable_proof);

    CHECK_AND_ASSERT_THROW_MES(sp::serialization::try_append_serializable(
                                    serializable_proof,
                                    serialized_proof),
                                "Error EnoteOwnershipV1 proof serialization");

    return std::string{std::string{"SpKnowledgeProofEnoteOwnershipV1"} + serialized_proof};

}

SpKnowledgeProofEnoteOwnershipV1 deserialize_sp_enote_ownership_proof_v1(const std::string &proof)
{
    // Check if header is the same 
    std::string header{"SpKnowledgeProofEnoteOwnershipV1"};
    CHECK_AND_ASSERT_THROW_MES(
        proof.substr(0, header.size()).compare(header) == 0,
        "Header is different");

    std::string encoded_proof = proof.substr(header.size());

    serialization::ser_SpKnowledgeProofEnoteOwnershipV1 serializable_proof;
    SpKnowledgeProofEnoteOwnershipV1 recovered_proof;

    CHECK_AND_ASSERT_THROW_MES(
        sp::serialization::try_get_serializable(
            epee::strspan<std::uint8_t>(encoded_proof),
            serializable_proof),
        "Error with EnoteSentV1 proof deserialization.");

    serialization::recover_sp_knowledge_proof_enote_ownership_v1(serializable_proof, recovered_proof);

    return recovered_proof;

}
}  // namespace sp