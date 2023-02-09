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

#include "checksum_jamtis.h"

#include <string>
#include <vector>

namespace tools
{
namespace jamtis_checksum
{

static const std::vector<int64_t> GEN{0x1ae45cd581, 0x359aad8f02, 0x61754f9b24, 0xc2ba1bb368, 0xcd2623e3f0};
static const int64_t M = 0xffffffffff;
static const std::string alphabet = "xmrbase32cdfghijknpqtuwy01456789";
//-----------------------------------------------------------------
//-----------------------------------------------------------------
int64_t jamtis_polymod(const std::vector<int> &data)
{
    int64_t c = 1;
    int64_t b = 0;
    for (const auto v : data)
    {
        b = (c >> 35);
        c = ((c & 0x07ffffffff) << 5) ^ v;
        for (int64_t j = 0; j < 5; j++)
        {
            if ((b >> j) & 1)
            {
                c ^= GEN[j];
            }
            else
            {
                c ^= 0;
            }
        }
    }
    return c;
}
//-----------------------------------------------------------------
bool jamtis_verify_checksum(const std::string &data)
{
    std::vector<int> addr_data;
    for (auto x : data)
    {
        addr_data.push_back(alphabet.find(x));
    }
    return jamtis_polymod(addr_data) == M;
}
//-----------------------------------------------------------------
std::string jamtis_add_checksum(const std::string &addr_without_checksum)
{
    std::vector<int> addr_data;
    for (auto x : addr_without_checksum)
    {
        addr_data.push_back(alphabet.find(x));
    }

    std::vector<int> data_extended{addr_data};
    data_extended.resize(addr_data.size() + 8);
    int64_t polymod = jamtis_polymod(data_extended) ^ M;
    for (int64_t i = 0; i < 8; i++)
    {
        data_extended[addr_data.size() + i] = ((polymod >> 5 * (7 - i)) & 31);
    }

    std::string addr_with_checksum{};
    for (uint64_t j = 0; j < data_extended.size(); j++)
    {
        addr_with_checksum.push_back(alphabet[data_extended[j]]);
    }

    return addr_with_checksum;
}
//-----------------------------------------------------------------
}  // namespace jamtis_checksum
}  // namespace tools