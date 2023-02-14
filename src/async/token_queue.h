// Copyright (c) 2023, The Monero Project
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

/// Simple token queue.

#pragma once

//local headers

//third-party headers

//standard headers
#include <atomic>
#include <list>
#include <mutex>

//forward declarations


namespace async
{

enum class TokenQueueResult : unsigned char
{
    SUCCESS,
    QUEUE_FULL,
    QUEUE_EMPTY,
    TRY_LOCK_FAIL
};

/// async token queue
/// - does not include a force_pop() method for simplicity
template <typename TokenT>
class TokenQueue final
{
public:
//constructors
    /// resurrect default constructor
    TokenQueue() = default;

//member functions
    /// set the max queue size
    /// - we need a member function for this because it's not possible to allocate a vector of queues with anything
    ///   other than the default constructor (since queues are copy/move disabled thanks to the mutex)
    void set_max_queue_size(const std::uint16_t max_queue_size) noexcept { m_max_queue_size = max_queue_size; }

    /// try to add an element to the top
    template <typename T>
    TokenQueueResult try_push(T &&new_element)
    {
        std::unique_lock<std::mutex> lock{m_mutex, std::try_to_lock};
        if (!lock.owns_lock())
            return TokenQueueResult::TRY_LOCK_FAIL;
        if (m_queue.size() >= m_max_queue_size)
            return TokenQueueResult::QUEUE_FULL;

        m_queue.emplace_back(std::forward<T>(new_element));
        return TokenQueueResult::SUCCESS;
    }
    /// add an element to the top (always succeeds)
    template <typename T>
    void force_push(T &&new_element)
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        m_queue.emplace_back(std::forward<T>(new_element));
    }

    /// add an element to the top (always succeeds), then pop the element at the bottom
    template <typename T>
    TokenT force_push_pop(T &&new_element)
    {
        std::lock_guard<std::mutex> lock{m_mutex};

        // special case
        if (m_queue.size() == 0)
            return std::forward<T>(new_element);

        // push back
        m_queue.emplace_back(std::forward<T>(new_element));

        // pop front
        TokenT temp_token = std::move(m_queue.front());
        m_queue.pop_front();
        return temp_token;
    }

    /// try to remove an element from the bottom
    TokenQueueResult try_pop(TokenT &token_out)
    {
        // try to lock the queue, then check if there are any elements
        std::unique_lock<std::mutex> lock{m_mutex, std::try_to_lock};
        if (!lock.owns_lock())
            return TokenQueueResult::TRY_LOCK_FAIL;
        if (m_queue.size() == 0)
            return TokenQueueResult::QUEUE_EMPTY;

        // pop the bottom element
        token_out = std::move(m_queue.front());
        m_queue.pop_front();
        return TokenQueueResult::SUCCESS;
    }

private:
//member variables
    /// queue context
    std::list<TokenT> m_queue;
    std::mutex m_mutex;

    /// config
    std::uint32_t m_max_queue_size{0};
};

} //namespace asyc
