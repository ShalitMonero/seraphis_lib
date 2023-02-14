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

/// Task types for a threadpool

#pragma once

//local headers
#include "common/variant.h"

//third-party headers

//standard headers
#include <atomic>
#include <chrono>
#include <functional>
#include <future>

//forward declarations


namespace async
{

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

/// waketime
/// - waketime = start time + duration
/// - if 'start time == 0' when a task is received, then the start time will be set to the time at that moment
///   - this allows task-makers to specify either a task's waketime or its sleep duration from the moment it is
///     submitted, e.g. for task continuations that are defined well in advance of when they are submitted
struct WakeTime final
{
    std::chrono::time_point<std::chrono::steady_clock> start_time{
            std::chrono::time_point<std::chrono::steady_clock>::min()
        };
    std::chrono::nanoseconds duration{0};
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

/// possible statuses of a sleepy task in a sleepy queue
enum class SleepingTaskStatus : unsigned char
{
    /// task is waiting for a worker
    UNCLAIMED,
    /// task is reserved by a worker
    RESERVED,
    /// task has been consumed by a worker
    DEAD
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

struct SimpleTask;
struct SleepyTask;
class ScopedNotification;

/// task
//todo: std::packaged_task is inefficient, all we need is std::move_only_function (C++23)
using TaskVariant = tools::variant<SimpleTask, SleepyTask, ScopedNotification>;
using task_t      = std::packaged_task<TaskVariant()>;  //tasks auto-return their continuation (or an empty variant)

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

/// pending task
struct SimpleTask final
{
    unsigned char priority;
    task_t task;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

/// sleepy task
struct SleepyTask final
{
    SimpleTask simple_task;
    WakeTime wake_time;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

/// sleeping task
/// note: we need an extra type for sleeping tasks because SleepyTasks are not copy-constructible, and the atomic status
///       is not move-constructible, which means SleepingTasks are very hard to move around
struct SleepingTask final
{
    SleepyTask sleepy_task;
    std::atomic<SleepingTaskStatus> status{SleepingTaskStatus::UNCLAIMED};

    /// normal constructor (this struct is not movable or copyable, so it needs some help...)
    SleepingTask(SleepyTask &&sleepy_task, const SleepingTaskStatus status) :
        sleepy_task{std::move(sleepy_task)}, status{status}
    {}
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

/// scoped notification (notifies on destruction)
/// - only use this if you can GUARANTEE the lifetimes of any references in the notification function are longer
///   than the notification's lifetime
class ScopedNotification final
{
public:
//constructors
    /// normal constructor
    ScopedNotification(std::function<void()> notification_func) :
        m_notification_func{std::move(notification_func)}
    {}

    /// disable copies (this is a scoped manager)
    ScopedNotification(const ScopedNotification&)            = delete;
    ScopedNotification& operator=(const ScopedNotification&) = delete;

    /// moved-from notifications should have empty notification functions so they are not called in the destructor
    ScopedNotification(ScopedNotification &&other)
    {
        *this = std::move(other);
    }
    ScopedNotification& operator=(ScopedNotification &&other)
    {
        this->notify();
        this->m_notification_func = std::move(other).m_notification_func;
        other.m_notification_func = nullptr;  //nullify the moved-from function
        return *this;
    }

//destructor
    ~ScopedNotification()
    {
        this->notify();
    }

private:
//member functions
    void notify()
    {
        if (m_notification_func)
        {
            try { m_notification_func(); } catch (...) {}
        }
    }

//member variables
    std::function<void()> m_notification_func;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

/// make simple task
template <typename F>
SimpleTask make_simple_task(const unsigned char priority, F &&func)
{
    //todo: add an indirection to wrap functions that don't return TaskVariants so they return an empty variant
    static_assert(std::is_same<decltype(func()), TaskVariant>::value, "tasks must return task variants");
    return SimpleTask{
            .priority = priority,
            .task     = std::packaged_task<TaskVariant()>{std::forward<F>(func)}
        };
}

/// make sleepy task
template <typename F>
SleepyTask make_sleepy_task(const unsigned char priority, const WakeTime &waketime, F &&func)
{
    return {
            make_simple_task(priority, std::forward<F>(func)),
            waketime
        };
}
template <typename F>
SleepyTask make_sleepy_task(const unsigned char priority, const std::chrono::nanoseconds &duration, F &&func)
{
    // note: the start time is left undefined/zero until the task gets scheduled
    WakeTime waketime{};
    waketime.duration = duration;

    return {
            make_simple_task(priority, std::forward<F>(func)),
            waketime
        };
}
template <typename F>
SleepyTask make_sleepy_task(const unsigned char priority,
    const std::chrono::time_point<std::chrono::steady_clock> &waketime,
    F &&func)
{
    return {
            make_simple_task(priority, std::forward<F>(func)),
            WakeTime{ .start_time = waketime, .duration = std::chrono::nanoseconds{0} }
        };
}

//todo
std::chrono::time_point<std::chrono::steady_clock> wake_time(const WakeTime waketime);

//todo
bool sleepy_task_is_awake(const SleepyTask &task);
bool sleeping_task_is_unclaimed(const SleepingTask &task);
bool sleeping_task_is_dead(const SleepingTask &task);
void unclaim_sleeping_task(SleepingTask &sleeping_task_inout);
void reserve_sleeping_task(SleepingTask &sleeping_task_inout);
void kill_sleeping_task(SleepingTask &sleeping_task_inout);

} //namespace asyc
