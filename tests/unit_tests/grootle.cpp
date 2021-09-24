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

#include "ringct/rctOps.h"
#include "mock_tx/grootle.h"

#include "gtest/gtest.h"

#include <cmath>
#include <vector>


using namespace rct;

// Test random proofs in batches
bool test_grootle_proof(const std::size_t n,  // size base: N = n^m
    const std::size_t N_proofs,  // number of proofs with common keys to verify in a batch
    const std::size_t num_keys,  // number of parallel keys per-proof
    const std::size_t num_ident_offsets)  // number of commitment-to-zero offsets to set to identity element
{
    // Ring sizes: N = n^m
    for (std::size_t m = 2; m <= 6; m++)
    {
        // anonymity set size
        const std::size_t N = std::pow(n, m);

        // proofs
        std::vector<sp::ConciseGrootleProof> proofs;
        proofs.reserve(N_proofs);
        std::vector<const sp::ConciseGrootleProof *> proof_ptrs;
        proof_ptrs.reserve(N_proofs);

        // Build key vectors
        keyM M;                         // ref set (common)
        M.resize(N, keyV(num_keys));
        keyM proof_privkeys;            // privkey tuple per-proof (at secret indices in M)
        proof_privkeys.resize(N_proofs, keyV(num_keys));
        keyV proof_messages = keyV(N_proofs); // message per-proof
        keyM proof_offsets;             // commitment offset tuple per-proof
        proof_offsets.resize(N_proofs, keyV(num_keys));

        // Random keys
        key temp;
        for (std::size_t k = 0; k < N; k++)
        {
            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                skpkGen(temp, M[k][alpha]);
            }
        }

        // Signing keys, proof_messages, and commitment offsets
        key privkey, offset_privkey;
        for (std::size_t proof_i = 0; proof_i < N_proofs; proof_i++)
        {
            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                // set real-signer index = proof index (kludge)
                skpkGen(privkey, M[proof_i][alpha]);  //m_{l, alpha} * G
                proof_messages[proof_i] = skGen();

                // set the first 'num_ident_offsets' commitment offsets equal to identity
                // - the proof will show DL on G for the main key directly (instead of commitment to zero with offset)
                if (alpha + 1 > num_ident_offsets)
                {
                    skpkGen(offset_privkey, proof_offsets[proof_i][alpha]);  //c_{alpha} * G
                    sc_sub(proof_privkeys[proof_i][alpha].bytes, privkey.bytes, offset_privkey.bytes); //m - c [commitment to zero]
                }
                else
                {
                    proof_offsets[proof_i][alpha] = identity();
                    proof_privkeys[proof_i][alpha] = privkey;
                }
            }
        }

        // Build proofs
        for (std::size_t proof_i = 0; proof_i < N_proofs; proof_i++)
        {
            proofs.push_back(
                sp::concise_grootle_prove(M,
                    proof_i,
                    proof_offsets[proof_i],
                    proof_privkeys[proof_i],
                    n,
                    m,
                    proof_messages[proof_i])
                );
        }
        for (sp::ConciseGrootleProof &proof: proofs)
        {
            proof_ptrs.push_back(&proof);
        }

        // Verify batch
        if (!sp::concise_grootle_verify(proof_ptrs, M, proof_offsets, n, m, proof_messages))
            return false;
    }

    return true;
}


// [[[TODO: test multiple layers (1-3), test identity offset (0-all)]]]
// Fixed: n (size base)
// Variable: m (size exponent), l (signing index)
TEST(grootle_concise, random)
{
    //const std::size_t n                   // size base: N = n^m
    //const std::size_t N_proofs            // number of proofs with common keys to verify in a batch
    //const std::size_t num_keys            // number of parallel keys per-proof
    //const std::size_t num_ident_offsets   // number of commitm
    EXPECT_TRUE(test_grootle_proof(2, 1, 1, 0));
    EXPECT_TRUE(test_grootle_proof(2, 1, 2, 0));
    EXPECT_TRUE(test_grootle_proof(2, 1, 3, 0));
    EXPECT_TRUE(test_grootle_proof(2, 1, 3, 1));
    EXPECT_TRUE(test_grootle_proof(2, 1, 3, 2));
    EXPECT_TRUE(test_grootle_proof(2, 1, 3, 3));

    EXPECT_TRUE(test_grootle_proof(2, 2, 1, 0));
    EXPECT_TRUE(test_grootle_proof(2, 2, 2, 0));
    EXPECT_TRUE(test_grootle_proof(2, 2, 1, 1));
    EXPECT_TRUE(test_grootle_proof(2, 2, 2, 1));
    EXPECT_TRUE(test_grootle_proof(2, 2, 2, 2));

    EXPECT_TRUE(test_grootle_proof(3, 2, 2, 1));
    EXPECT_TRUE(test_grootle_proof(3, 3, 2, 1));
    EXPECT_TRUE(test_grootle_proof(3, 3, 3, 0));
    EXPECT_TRUE(test_grootle_proof(3, 3, 3, 1));
    EXPECT_TRUE(test_grootle_proof(3, 3, 3, 3));
}

