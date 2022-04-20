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

//paired header
#include "tx_binned_reference_set.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "int-util.h"
#include "misc_log_ex.h"
#include "seraphis_config_temp.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <limits>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t compute_bin_width(const std::uint64_t bin_radius)
{
    return 2*bin_radius + 1;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename BinDim>
static bool check_bin_config(const std::uint64_t reference_set_size,
    const SpBinnedReferenceSetConfigV1 &bin_config)
{
    // bin width outside bin dimension
    if (bin_config.m_bin_radius > std::numeric_limits<BinDim>::max()/2 - 1)
        return false;
    // too many bin members
    if (bin_config.m_num_bin_members > std::numeric_limits<BinDim>::max())
        return false;
    // can't fit bin members in bin
    if (bin_config.m_num_bin_members > compute_bin_width(bin_config.m_bin_radius))
        return false;
    // no bin members
    if (bin_config.m_num_bin_members < 1)
        return false;

    // reference set can't be perfectly divided into bins
    return bin_config.m_num_bin_members * (reference_set_size / bin_config.m_num_bin_members) == reference_set_size;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t clamp(const std::uint64_t a, const std::uint64_t min, const std::uint64_t max)
{
    if (a < min)
        return min;
    else if (a > max)
        return max;
    else
        return a;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t saturating_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t min)
{
    if (a < min)
        return min;

    return a - min >= b
        ? a - b
        : min;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t saturating_add(const std::uint64_t a, const std::uint64_t b, const std::uint64_t max)
{
    if (a > max)
        return max;

    return max - a >= b
        ? a + b
        : max;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod(const std::uint64_t a, const std::uint64_t n)
{
    // a mod n
    CHECK_AND_ASSERT_THROW_MES(n > 0, "Modulo 0 is illegal.");
    return a % n;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod_negate(const std::uint64_t a, const std::uint64_t n)
{
    // -a mod n = n - (a mod n)
    return n - mod(a, n);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod_add(std::uint64_t a, std::uint64_t b, const std::uint64_t n)
{
    // a + b mod n
    a = mod(a, n);
    b = mod(b, n);

    // if adding doesn't overflow the modulus, then add directly, otherwise overflow the modulus
    return (n - a > b) ? a + b : b - (n - a);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t mod_sub(const std::uint64_t a, const std::uint64_t b, const std::uint64_t n)
{
    // a - b mod n
    return mod_add(a, mod_negate(b, n), n);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_normalized_bin_members(const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &bin_generator_seed,
    const std::uint64_t bin_index_in_set,
    std::vector<std::uint64_t> &members_of_bin_out)
{
    // checks and initialization
    const std::uint64_t bin_width{compute_bin_width(bin_config.m_bin_radius)};

    CHECK_AND_ASSERT_THROW_MES(bin_config.m_num_bin_members > 0,
        "making normalized bin members: zero bin members were requested (at least one expected).");

    // set clip allowed max to be a large multiple of the bin width (minus 1 since we are zero-basis),
    //   to avoid bias in the bin members
    // example 1:
    //   max = 15  (e.g. 4 bits)
    //   width = 4
    //   15 = 15 - ((15 mod 4) + 1 mod 4)
    //   15 = 15 - ((3) + 1 mod 4)
    //   15 = 15 - 0
    //   perfect partitioning: [0..3][4..7][8..11][12..15]
    // example 2:
    //   max = 15  (e.g. 4 bits)
    //   width = 6
    //   11 = 15 - ((15 mod 6) + 1 mod 6)
    //   11 = 15 - ((3) + 1 mod 6)
    //   11 = 15 - 4
    //   perfect partitioning: [0..5][6..11]
    const std::uint64_t clip_allowed_max{
            std::numeric_limits<std::uint64_t>::max() -
                mod(mod(std::numeric_limits<std::uint64_t>::max(), bin_width) + 1, bin_width)
        };

    // make this bin's member generator
    // g = H("..", bin_generator_seed, bin_index_in_set)
    static const std::string domain_separator{config::HASH_KEY_BINNED_REF_SET_MEMBER};

    std::string data;
    data.reserve(domain_separator.size() + sizeof(bin_generator_seed) + sizeof(bin_index_in_set));
    data = domain_separator;
    data.append(reinterpret_cast<const char*>(bin_generator_seed.bytes), sizeof(bin_generator_seed));
    {
        unsigned char v_variable[(sizeof(std::size_t) * 8 + 6) / 7];
        unsigned char *v_variable_end = v_variable;

        // bin index
        v_variable_end = v_variable;
        tools::write_varint(v_variable_end, bin_index_in_set);
        assert(v_variable_end <= v_variable + sizeof(v_variable));
        data.append(reinterpret_cast<const char*>(v_variable), v_variable_end - v_variable);
    }
    crypto::hash member_generator{crypto::cn_fast_hash(data.data(), data.size())};

    // make each bin member (as indices within the bin)
    std::uint64_t generator_clip;
    members_of_bin_out.clear();
    members_of_bin_out.reserve(bin_config.m_num_bin_members);

    for (std::size_t bin_member_index{0}; bin_member_index < bin_config.m_num_bin_members; ++bin_member_index)
    {
        // update the generator for this bin member (find a generator that is within the allowed max)
        do
        {
            crypto::cn_fast_hash(member_generator.data, sizeof(member_generator), member_generator);
            memcpy(&generator_clip, member_generator.data, sizeof(generator_clip));
            generator_clip = SWAP64LE(generator_clip);
        } while (generator_clip > clip_allowed_max);

        // add the bin member: slice_8_bytes(generator) mod bin_width
        members_of_bin_out.emplace_back(mod(generator_clip, bin_width));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void rotate_elements(const std::uint64_t range_limit,
    const std::uint64_t rotation_factor,
    std::vector<std::uint64_t> &elements_inout)
{
    // rotate a group of elements by a rotation factor
    for (std::uint64_t &element : elements_inout)
        element = mod_add(element, rotation_factor, range_limit);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void denormalize_elements(const std::uint64_t normalization_factor, std::vector<std::uint64_t> &elements_inout)
{
    // de-normalize elements
    for (std::uint64_t &element : elements_inout)
        element += normalization_factor;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
SpBinLociGeneratorRand::SpBinLociGeneratorRand(const SpBinnedReferenceSetConfigV1 &bin_config,
    const std::uint64_t distribution_min_index,
    const std::uint64_t distribution_max_index) :
        m_bin_config{bin_config},
        m_distribution_min_index{distribution_min_index},
        m_distribution_max_index{distribution_max_index}
{
    // checks
    CHECK_AND_ASSERT_THROW_MES(m_distribution_max_index > m_distribution_min_index,
        "bin loci generator rand: invalid element range.");
    CHECK_AND_ASSERT_THROW_MES(m_distribution_max_index - m_distribution_min_index >=
            compute_bin_width(m_bin_config.m_bin_radius),
        "bin loci generator rand: insufficient elements for one bin.");
    CHECK_AND_ASSERT_THROW_MES(compute_bin_width(m_bin_config.m_bin_radius) >= m_bin_config.m_num_bin_members,
        "bin loci generator rand: bin radius not large enough to fit bin members.");
}
//-------------------------------------------------------------------------------------------------------------------
bool SpBinLociGeneratorRand::try_generate_bin_loci(const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index,
    std::vector<std::uint64_t> &bin_loci_out,
    std::uint64_t &bin_index_with_real_out) const
{
    /// checks and initialization
    if (reference_set_size   < 1                        ||
        real_reference_index < m_distribution_min_index ||
        real_reference_index > m_distribution_max_index ||
        !check_bin_config<ref_set_bin_dimension_v1_t>(reference_set_size, m_bin_config))
        return false;

    const std::uint64_t num_bins{reference_set_size/m_bin_config.m_num_bin_members};
    const std::uint64_t distribution_width{m_distribution_max_index - m_distribution_min_index + 1};


    /// pick a locus for the real reference's bin

    // 1) define range where the locus may reside (clamp bounds to distribution range)
    const std::uint64_t real_locus_min{
            saturating_sub(real_reference_index, m_bin_config.m_bin_radius, m_distribution_min_index)
        };
    const std::uint64_t real_locus_max{
            saturating_add(real_reference_index, m_bin_config.m_bin_radius, m_distribution_max_index)
        };

    // 2) generate the bin locus (normalized within the distribution)
    const std::uint64_t real_locus{
            crypto::rand_idx<std::uint64_t>(real_locus_max - real_locus_min + 1) + (real_locus_min - m_distribution_min_index)
        };


    /// randomly generate a set of bin loci (normalized within the distribution)
    // note: this step is the core piece of this loci generator (a different generator should use a different method of
    //       selecting loci)
    //todo: maybe refactor everything so that just the mapping between normalized bin loci space and distribution space
    //      is customize-able

    std::vector<std::uint64_t> bin_loci;
    bin_loci.resize(num_bins);

    for (std::uint64_t &bin_locus : bin_loci)
        bin_locus = crypto::rand_idx<std::uint64_t>(distribution_width);


    /// rotate the randomly generated bins so a random bin lines up with the real bin locus

    // 1) randomly select one of the bins
    const std::uint64_t designated_real_bin{crypto::rand_idx<std::uint64_t>(num_bins)};

    // 2) compute rotation factor
    const std::uint64_t bin_loci_rotation_factor{mod_sub(real_locus, bin_loci[designated_real_bin], distribution_width)};

    // 3) rotate all the bin loci
    rotate_elements(distribution_width, bin_loci_rotation_factor, bin_loci);


    /// prepare outputs

    // 1) sort bin loci
    std::sort(bin_loci.begin(), bin_loci.end());

    // 2) shift bin loci so their entire widths are within the distribution
    for (std::uint64_t &bin_locus : bin_loci)
        bin_locus = clamp(bin_locus, m_bin_config.m_bin_radius, distribution_width - m_bin_config.m_bin_radius - 1);

    const std::uint64_t real_locus_shifted{
            clamp(real_locus, m_bin_config.m_bin_radius, distribution_width - m_bin_config.m_bin_radius - 1)
        };

    // 3) find the real reference's locus (if multiple loci equal the real locus, pick one randomly)
    std::uint64_t last_locus_equal_to_real{0};
    std::uint64_t num_loci_equal_to_real{0};

    for (std::size_t bin_loci_index{0}; bin_loci_index < bin_loci.size(); ++bin_loci_index)
    {
        if (bin_loci[bin_loci_index] == real_locus_shifted)
        {
            last_locus_equal_to_real = bin_loci_index;
            ++num_loci_equal_to_real;
        }
    }

    bin_index_with_real_out =
        crypto::rand_range<std::uint64_t>(last_locus_equal_to_real - num_loci_equal_to_real + 1, last_locus_equal_to_real);

    // 4) de-normalize loci
    denormalize_elements(m_distribution_min_index, bin_loci);

    // 5) set bin loci output
    bin_loci_out = std::move(bin_loci);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_binned_reference_set_v1(const SpBinnedReferenceSetConfigV1 &bin_config,
    const std::uint64_t real_reference_index,
    const std::vector<std::uint64_t> &bin_loci,
    const std::uint64_t bin_index_with_real,  //index into bin_loci
    SpBinnedReferenceSetV1 &binned_reference_set_out)
{
    // make binned reference set

    /// checks and initialization
    const std::uint64_t bin_width{compute_bin_width(bin_config.m_bin_radius)};

    CHECK_AND_ASSERT_THROW_MES(check_bin_config<ref_set_bin_dimension_v1_t>(bin_config.m_num_bin_members * bin_loci.size(),
            bin_config),
        "binned reference set: invalid bin config.");

    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(bin_loci.begin(), bin_loci.end()),
        "binned reference set: bin loci aren't sorted.");
    for (const std::uint64_t bin_locus : bin_loci)
    {
        CHECK_AND_ASSERT_THROW_MES(bin_locus >= bin_config.m_bin_radius,
            "binned reference set: the bottom of a proposed bin hangs below 0.");        
        CHECK_AND_ASSERT_THROW_MES(bin_locus <= std::numeric_limits<std::uint64_t>::max() - bin_config.m_bin_radius,
            "binned reference set: the top of a proposed bin extends above uint64::max().");        
    }

    CHECK_AND_ASSERT_THROW_MES(bin_index_with_real <= bin_loci.size(),
        "binned reference set: real element's bin isn't in the bins proposed.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index >= bin_loci[bin_index_with_real] - bin_config.m_bin_radius,
        "binned reference set: real element is below its proposed bin.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index <= bin_loci[bin_index_with_real] + bin_config.m_bin_radius,
        "binned reference set: real element is above its proposed bin.");


    /// make the bin member generator seed
    crypto::rand(32, binned_reference_set_out.m_bin_generator_seed.bytes);


    /// make bins
    std::vector<SpReferenceBinV1> bins;
    bins.resize(bin_loci.size());

    for (std::size_t bin_index{0}; bin_index < bin_loci.size(); ++bin_index)
    {
        bins[bin_index].m_bin_locus = bin_loci[bin_index];
        bins[bin_index].m_rotation_factor =
            static_cast<ref_set_bin_dimension_v1_t>(crypto::rand_idx<std::uint64_t>(bin_width));
    }


    /// set real reference's bin rotation factor

    // 1) generate the bin members' indices into the element set (normalized and not rotated)
    std::vector<std::uint64_t> members_of_real_bin;
    make_normalized_bin_members(bin_config,
        binned_reference_set_out.m_bin_generator_seed,
        bin_index_with_real,
        members_of_real_bin);
    CHECK_AND_ASSERT_THROW_MES(members_of_real_bin.size() == bin_config.m_num_bin_members,
        "binned reference set: getting normalized bin members failed (bug).");

    // 2) select a random bin member to land on the real reference
    const std::uint64_t designated_real_bin_member{crypto::rand_idx<std::uint64_t>(bin_config.m_num_bin_members)};

    // 3) normalize the real reference within its bin (subtract the bottom of the bin)
    const std::uint64_t normalized_real_reference{
            real_reference_index - (bin_loci[bin_index_with_real] - bin_config.m_bin_radius)
        };

    // 4) compute rotation factor
    bins[bin_index_with_real].m_rotation_factor = static_cast<ref_set_bin_dimension_v1_t>(
        mod_sub(members_of_real_bin[designated_real_bin_member], normalized_real_reference, bin_width));


    /// set remaining output pieces
    binned_reference_set_out.m_bin_config = bin_config;
    binned_reference_set_out.m_bins = std::move(bins);
}
//-------------------------------------------------------------------------------------------------------------------
void make_binned_reference_set_v1(const SpBinLociGenerator &loci_generator,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index,
    SpBinnedReferenceSetV1 &binned_reference_set_out)
{
    // make binned reference set with loci generator

    // generate bin loci
    std::vector<std::uint64_t> bin_loci;
    std::uint64_t bin_index_with_real;
    CHECK_AND_ASSERT_THROW_MES(loci_generator.try_generate_bin_loci(reference_set_size,
            real_reference_index,
            bin_loci,
            bin_index_with_real),
        "binned reference set: unable to generate bin loci.");

    // make the reference set
    make_binned_reference_set_v1(loci_generator.get_bin_config(),
        real_reference_index,
        bin_loci,
        bin_index_with_real,
        binned_reference_set_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_reference_indices_from_binned_reference_set_v1(const SpBinnedReferenceSetV1 &binned_reference_set,
    std::vector<std::uint64_t> &reference_indices_out)
{
    // initialization
    const std::uint64_t bin_width{compute_bin_width(binned_reference_set.m_bin_config.m_bin_radius)};
    const std::uint64_t num_bin_members{
            binned_reference_set.m_bins.size() * binned_reference_set.m_bin_config.m_num_bin_members
        };

    // sanity check the bin config
    if (!check_bin_config<ref_set_bin_dimension_v1_t>(num_bin_members, binned_reference_set.m_bin_config))
        return false;

    // validate bins
    for (const SpReferenceBinV1 &bin : binned_reference_set.m_bins)
    {
        // bins must all fit in the range [0, 2^64 - 1]
        if (bin.m_bin_locus < binned_reference_set.m_bin_config.m_bin_radius)
            return false;
        if (bin.m_bin_locus > std::numeric_limits<std::uint64_t>::max() - binned_reference_set.m_bin_config.m_bin_radius)
            return false;

        // rotation factor must be within the bin (normalized)
        if (bin.m_rotation_factor >= bin_width)
            return false;
    }

    // add all the bin members
    reference_indices_out.clear();
    reference_indices_out.reserve(num_bin_members);

    std::vector<std::uint64_t> bin_members;

    for (std::size_t bin_index{0}; bin_index < binned_reference_set.m_bins.size(); ++bin_index)
    {
        bin_members.clear();

        // 1) make normalized bin members
        make_normalized_bin_members(binned_reference_set.m_bin_config,
            binned_reference_set.m_bin_generator_seed,
            bin_index,
            bin_members);

        // 2) rotate the bin members by the rotation factor
        rotate_elements(bin_width, binned_reference_set.m_bins[bin_index].m_rotation_factor, bin_members);

        // 3) de-normalize the bin members
        denormalize_elements(binned_reference_set.m_bins[bin_index].m_bin_locus, bin_members);

        // 4) save the bin members
        reference_indices_out.insert(reference_indices_out.end(), bin_members.begin(), bin_members.end());
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
