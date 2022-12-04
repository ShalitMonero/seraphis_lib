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

//paired header
#include "dual_base_vector_proof.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// compute: A_inout += k * P
//-------------------------------------------------------------------------------------------------------------------
static void mul_add(const rct::key &k, const crypto::public_key &P, ge_p3 &A_inout)
{
    ge_p3 temp_p3;
    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;

    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&temp_p3, to_bytes(P)) == 0, "ge_frombytes_vartime failed!");
    ge_scalarmult_p3(&temp_p3, k.bytes, &temp_p3);  //k * P
    ge_p3_to_cached(&temp_cache, &temp_p3);
    ge_add(&temp_p1p1, &A_inout, &temp_cache);  //+ k * P
    ge_p1p1_to_p3(&A_inout, &temp_p1p1);
}
//-------------------------------------------------------------------------------------------------------------------
// aggregation coefficient 'mu' for concise structure
//
// mu = H_n(message, G_1, G_2, {V_1}, {V_2})
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_base_aggregation_coefficient(const rct::key &message,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2,
    const std::vector<crypto::public_key> &V_1,
    const std::vector<crypto::public_key> &V_2)
{
    // collect aggregation coefficient hash data
    SpFSTranscript transcript{
            config::HASH_KEY_DUAL_BASE_VECTOR_PROOF_AGGREGATION_COEFF,
            (3 + V_1.size() + V_2.size())*sizeof(rct::key)
        };
    transcript.append("message", message);
    transcript.append("G_1", G_1);
    transcript.append("G_2", G_2);
    transcript.append("V_1", V_1);
    transcript.append("V_2", V_2);

    // mu
    rct::key aggregation_coefficient;
    sp_hash_to_scalar(transcript, aggregation_coefficient.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(aggregation_coefficient.bytes),
        "dual base vector proof aggregation coefficient: aggregation coefficient must be nonzero!");

    return aggregation_coefficient;
}
//-------------------------------------------------------------------------------------------------------------------
// challenge message
// challenge_message = H_32(message)
//
// note: in practice, this extends the aggregation coefficient (i.e. message = mu)
// challenge_message = H_32(mu) = H_32(H_n(message, G_1, G_2, {V_1}, {V_2}))
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge_message(const rct::key &message)
{
    // collect challenge message hash data
    SpFSTranscript transcript{config::HASH_KEY_DUAL_BASE_VECTOR_PROOF_CHALLENGE_MSG, sizeof(rct::key)};
    transcript.append("message", message);

    // m
    rct::key challenge_message;
    sp_hash_to_32(transcript, challenge_message.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge_message.bytes),
        "dual base vector proof challenge message: challenge_message must be nonzero!");

    return challenge_message;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H_n(challenge_message, [V_1 proof key], [V_2 proof key])
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message, const rct::key &V_1_proofkey, const rct::key &V_2_proofkey)
{
    // collect challenge hash data
    SpFSTranscript transcript{config::HASH_KEY_DUAL_BASE_VECTOR_PROOF_CHALLENGE, 3*sizeof(rct::key)};
    transcript.append("message", message);
    transcript.append("V_1_proofkey", V_1_proofkey);
    transcript.append("V_2_proofkey", V_2_proofkey);

    // c
    rct::key challenge;
    sp_hash_to_scalar(transcript, challenge.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes),
        "dual base vector proof challenge: challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// proof response
// r = alpha - c * sum_i(mu^i * k_i)
//-------------------------------------------------------------------------------------------------------------------
static void compute_response(const std::vector<crypto::secret_key> &k,
    const rct::keyV &mu_pows,
    const crypto::secret_key &alpha,
    const rct::key &challenge,
    rct::key &r_out)
{
    CHECK_AND_ASSERT_THROW_MES(k.size() == mu_pows.size(), "dual base vector proof response: not enough keys!");

    // compute response
    // r = alpha - c * sum_i(mu^i * k_i)
    crypto::secret_key r_temp;
    crypto::secret_key r_sum_temp{rct::rct2sk(rct::zero())};

    for (std::size_t i{0}; i < k.size(); ++i)
    {
        sc_mul(to_bytes(r_temp), mu_pows[i].bytes, to_bytes(k[i]));    //mu^i * k_i
        sc_add(to_bytes(r_sum_temp), to_bytes(r_sum_temp), to_bytes(r_temp));  //sum_i(...)
    }
    sc_mulsub(r_out.bytes, challenge.bytes, to_bytes(r_sum_temp), to_bytes(alpha));  //alpha - c * sum_i(...)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_dual_base_vector_proof(const rct::key &message,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2,
    const std::vector<crypto::secret_key> &privkeys,
    DualBaseVectorProof &proof_out)
{
    /// input checks and initialization
    const std::size_t num_keys{privkeys.size()};
    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "dual base vector proof: not enough keys to make a proof!");

    proof_out.m = message;

    crypto::secret_key k_i_inv8_temp;
    std::vector<crypto::public_key> V_1_mul8;
    std::vector<crypto::public_key> V_2_mul8;
    V_1_mul8.reserve(num_keys);
    V_2_mul8.reserve(num_keys);
    proof_out.V_1.clear();
    proof_out.V_2.clear();
    proof_out.V_1.reserve(num_keys);
    proof_out.V_2.reserve(num_keys);

    for (const crypto::secret_key &k_i : privkeys)
    {
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(k_i)), "dual base vector proof: bad private key (k_i zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(k_i)) == 0, "dual base vector proof: bad private key (k_i)!");

        // k_i * (1/8)
        sc_mul(to_bytes(k_i_inv8_temp), to_bytes(k_i), rct::INV_EIGHT.bytes);

        // create the pubkey vectors
        proof_out.V_1.emplace_back(rct::rct2pk(rct::scalarmultKey(rct::pk2rct(G_1), rct::sk2rct(k_i_inv8_temp))));
        proof_out.V_2.emplace_back(rct::rct2pk(rct::scalarmultKey(rct::pk2rct(G_2), rct::sk2rct(k_i_inv8_temp))));
        V_1_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof_out.V_1.back()))));
        V_2_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof_out.V_2.back()))));
    }


    /// signature openers: alpha * G_1, alpha * G_2
    const crypto::secret_key alpha{rct::rct2sk(rct::skGen())};
    const rct::key alpha_1_pub{rct::scalarmultKey(rct::pk2rct(G_1), rct::sk2rct(alpha))};
    const rct::key alpha_2_pub{rct::scalarmultKey(rct::pk2rct(G_2), rct::sk2rct(alpha))};


    /// challenge message and aggregation coefficient
    const rct::key mu{compute_base_aggregation_coefficient(proof_out.m, G_1, G_2, V_1_mul8, V_2_mul8)};
    const rct::keyV mu_pows{sp::powers_of_scalar(mu, num_keys)};

    const rct::key m{compute_challenge_message(mu)};


    /// compute proof challenge
    proof_out.c = compute_challenge(m, alpha_1_pub, alpha_2_pub);


    /// response
    compute_response(privkeys, mu_pows, alpha, proof_out.c, proof_out.r);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_dual_base_vector_proof(const DualBaseVectorProof &proof,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2)
{
    /// input checks and initialization
    const std::size_t num_keys{proof.V_1.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "dual base vector proof (verify): proof has no keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == proof.V_2.size(),
        "dual base vector proof (verify): input key sets not the same size (V_2)!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proof.r.bytes), "dual base vector proof (verify): bad response (r zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r.bytes) == 0, "dual base vector proof (verify): bad response (r)!");

    // recover the proof keys
    std::vector<crypto::public_key> V_1_mul8;
    std::vector<crypto::public_key> V_2_mul8;
    V_1_mul8.reserve(num_keys);
    V_2_mul8.reserve(num_keys);

    for (std::size_t key_index{0}; key_index < num_keys; ++key_index)
    {
        V_1_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof.V_1[key_index]))));
        V_2_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof.V_2[key_index]))));
    }


    /// challenge message and aggregation coefficient
    const rct::key mu{compute_base_aggregation_coefficient(proof.m, G_1, G_2, V_1_mul8, V_2_mul8)};
    const rct::keyV mu_pows{sp::powers_of_scalar(mu, num_keys)};

    const rct::key m{compute_challenge_message(mu)};


    /// challenge pieces

    // V_1 part: [r G_1 + c * sum_i(mu^i * V_1[i])]
    // V_2 part: [r G_2 + c * sum_i(mu^i * V_2[i])]
    ge_p3 V_1_part_p3{ge_p3_identity};
    ge_p3 V_2_part_p3{ge_p3_identity};

    rct::key coeff_temp;

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        // c * mu^i
        sc_mul(coeff_temp.bytes, proof.c.bytes, mu_pows[i].bytes);

        // V_1_part: + c * mu^i * V_1[i]
        mul_add(coeff_temp, V_1_mul8[i], V_1_part_p3);

        // V_2_part: + c * mu^i * V_2[i]
        mul_add(coeff_temp, V_2_mul8[i], V_2_part_p3);
    }

    // r G_1 + V_1_part
    mul_add(proof.r, G_1, V_1_part_p3);

    // r G_2 + V_2_part
    mul_add(proof.r, G_2, V_2_part_p3);


    /// compute nominal challenge and validate proof
    rct::key V_1_part;
    rct::key V_2_part;
    ge_p3_tobytes(V_1_part.bytes, &V_1_part_p3);
    ge_p3_tobytes(V_2_part.bytes, &V_2_part_p3);

    return compute_challenge(m, V_1_part, V_2_part) == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
