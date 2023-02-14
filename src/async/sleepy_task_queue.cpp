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

//paired header
#include "sleepy_task_queue.h"

//local headers

//third party headers

//standard headers
#include <atomic>
#include <chrono>
#include <mutex>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "async"

namespace async
{
//-------------------------------------------------------------------------------------------------------------------
void SleepyTaskQueue::force_push(SleepyTask &&task)
{
    std::lock_guard<std::mutex> lock{m_mutex};
    m_queue.insert({wake_time(task.m_wake_time).duration().count(), std::forward<SleepyTask>(task)});
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SleepyTaskQueue::try_push(SleepyTask &&task)
{
    std::lock_guard<std::mutex> lock{m_mutex, std::try_to_lock};
    if (!lock.owns_lock())
        return false;
    m_queue.insert({wake_time(task.m_wake_time).duration().count(), std::forward<SleepyTask>(task)});
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SleepyTaskQueue::try_swap(const unsigned char max_task_priority, SleepyTask* &task_inout)
{
    // initialize the current task's waketime (set to max if there is no task)
    auto current_task_waketime_count = 
        task_inout
        ? wake_time(task_inout->m_wake_time).duration().count()
        : std::chrono::time_point<std::chrono::steady_clock>::max().duration().count();

    // lock the queue
    std::lock_guard<std::mutex> lock{m_mutex, std::try_to_lock};
    if (!lock.owns_lock())
        return false;

    // try to find an unclaimed task that wakes up sooner than our input task
    for (auto &candidate_task : m_queue)
    {
        const SleepyTaskStatus candidate_status{candidate_task.second.m_status.load(std::memory_order_acquire)};

        // skip reserved and dead tasks
        if (candidate_status == SleepyTaskStatus::RESERVED ||
            candidate_status == SleepyTaskStatus::DEAD)
            continue;

        // skip tasks with too-high priority
        if (candidate_task.second.m_task.m_priority < max_task_priority)
            continue;

        // give up: the first unclaimed task does not wake up sooner than our input task
        if (current_task_waketime_count <= candidate_task.first)
            return false;

        // success
        // a. release our input task if we have one
        if (task_inout)
            unclaim_sleepy_task(*task_inout);

        // b. acquire this candidate
        task_inout = &(candidate_task.first);
        reserve_sleepy_task(*task_inout);
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
std::list<SleepyTask> SleepyTaskQueue::try_perform_maintenance()
{
    // current time
    auto now_count = std::chrono::steady_clock::now().duration().count();

    // lock the queue
    std::lock_guard<std::mutex> lock{m_mutex, std::try_to_lock};
    if (!lock.owns_lock())
        return {};

    // delete dead tasks and extract awake tasks until the lowest sleeping unclaimed task is encountered
    std::list<SleepyTask> awakened_tasks;

    for (auto queue_it = m_queue.begin(); queue_it != m_queue.end();)
    {
        const SleepyTaskStatus task_status{queue_it->second.m_status.load(std::memory_order_acquire)};

        // skip reserved tasks
        if (task_status == SleepyTaskStatus::RESERVED)
        {
            ++queue_it;
            continue;
        }

        // delete dead tasks
        if (task_status == SleepyTaskStatus::DEAD)
        {
            queue_it = m_queue.erase(queue_it);
            continue;
        }

        // extract awake unclaimed tasks
        if (queue_it->first <= now_count)
        {
            awakened_tasks.emplace_back(std::move(queue_it->second));
            queue_it = m_queue.erase(queue_it);
            continue;
        }

        // exit when we found an asleep unclaimed task
        break;
    }

    return awakened_tasks;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace async
