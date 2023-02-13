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

/// threadpool

//local headers
#include "variant.h"

//third-party headers
#include <boost/container/map.hpp>
#include <boost/optional/optional.hpp>

//standard headers
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <list>
#include <memory>
#include <mutex>
#include <thread>

//forward declarations


namespace tools
{

/// waketime
/// - waketime = start time + duration
/// - if 'start time == 0' when a task is received, then the start time will be set to the time at that moment
///   - this allows task-makers to specify either a task's waketime or its sleep duration from the moment it is
///     submitted, e.g. for task continuations that are defined well in advance of when they are submitted
struct WakeTime final
{
    std::chrono::time_point<std::chrono::steady_clock> m_start_time{
            std::chrono::time_point<std::chrono::steady_clock>::min()
        };
    std::chrono::duration m_duration{0};
};

//todo
std::chrono::time_point<std::chrono::steady_clock> wake_time(const WakeTime waketime);

/// possible statuses of a sleepy task in a sleepy queue
enum class SleepyTaskStatus : unsigned char
{
    /// task is waiting for a worker
    UNCLAIMED,
    /// task is reserved by a worker
    RESERVED,
    /// task has been consumed by a worker
    DEAD
};

/// task declarations
struct SimpleTask;
struct SleepyTask;
struct ScopedNotification;

/// task
//todo: std::packaged_task is inefficient, all we need is std::move_only_function (C++23)
using TaskVariant = tools::variant<SimpleTask, SleepyTask, ScopedNotification>;
using task_t      = std::packaged_task<TaskVariant()>;  //tasks auto-return their continuation (or an empty variant)

/// pending task
struct SimpleTask final
{
    unsigned char m_priority;
    task_t m_task;
};

/// sleepy task
struct SleepyTask final
{
    SimpleTask m_task;
    WakeTime m_wake_time;
    std::atomic<SleepyTaskStatus> m_status{SleepyTaskStatus::UNCLAIMED};
};

//todo
void unclaim_sleepy_task(SleepyTask &sleepytask_inout);
void reserve_sleepy_task(SleepyTask &sleepytask_inout);
void kill_sleepy_task(SleepyTask &sleepytask_inout);
bool sleepy_task_is_awake(const SleepyTask &task);
bool sleepy_task_is_unclaimed(const SleepyTask &task);
bool sleepy_task_is_dead(const SleepyTask &task)

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

/// make simple task
template <typename F>
SimpleTask make_simple_task(const unsigned char priority, F &&func)
{
    //todo: add an indirection to wrap functions that don't return TaskVariants so they return an empty variant
    static_assert(std::is_same<decltype(func()), TaskVariant>::value, "tasks must return task variants");
    return SimpleTask{
            .m_priority = priority,
            .m_task     = std::forward<F>(func)
        };
}

/// make sleepy task
template <typename F>
SleepyTask make_sleepy_task(const unsigned char priority, const WakeTime &waketime, F &&func)
{
    return SleepyTask{
            .m_task      = make_simple_task(priority, std::forward<F>(func)),
            .m_wake_time = waketime
        };
}


/// async token queue
/// - does not include a force_pop() method for simplicity
template <typename TokenT>
class TokenQueue final
{
public:
//member types
    enum class Result : unsigned char
    {
        SUCCESS,
        QUEUE_FULL,
        QUEUE_EMPTY,
        TRY_LOCK_FAIL
    };

//constructors
    TokenQueue(const std::uint32_t max_queue_size) : m_max_queue_size{max_queue_size}
    {}

//member functions
    /// try to add an element to the top
    template <typename T>
    Result try_push(T &&new_element)
    {
        std::lock_guard<std::mutex> lock{m_mutex, std::try_to_lock};
        if (!lock.owns_lock())
            return Result::TRY_LOCK_FAIL;
        if (m_queue.size() >= m_max_queue_size)
            return Result::QUEUE_FULL;

        m_queue.emplace_back(std::forward<T>(new_element));
        return Result::SUCCESS;
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
    Result try_pop(TokenT &token_out)
    {
        // try to lock the queue, then check if there are any elements
        std::lock_guard<std::mutex> lock{m_mutex, std::try_to_lock};
        if (!lock.owns_lock())
            return Result::TRY_LOCK_FAIL;
        if (m_queue.size() == 0)
            return Result::QUEUE_EMPTY;

        // pop the bottom element
        token_out = std::move(m_queue.front());
        m_queue.pop_front();
        return Result::SUCCESS;
    }

private:
//member variables
    /// queue context
    std::queue<TokenT> m_queue;
    std::mutex m_mutex;

    /// config
    const std::uint32_t m_max_queue_size;
};


/// - PRECONDITION: a user of a sleepy task queue with a pointer/reference to a task in that queue should ONLY change
///   the task's status from RESERVED to UNCLAIMED/DEAD (and not any other direction)
///   - once a RESERVED task's status has been changed, the user should assume they no longer have valid access to the
///     task
///   - only change a task's status from RESERVED -> UNCLAIMED if its contents will be left in a valid state after the
///     change (e.g. the internal task shouldn't be in a moved-from state)
class SleepyTaskQueue final
{
public:
//member functions
    /// force push a sleepy task into the queue
    void force_push(SleepyTask &&task)
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        m_queue.insert({wake_time(task.m_wake_time).duration().count(), std::forward<SleepyTask>(task)});
        return true;
    }
    /// try to push a sleepy task into the queue
    bool try_push(SleepyTask &&task)
    {
        std::lock_guard<std::mutex> lock{m_mutex, std::try_to_lock};
        if (!lock.owns_lock())
            return false;
        m_queue.insert({wake_time(task.m_wake_time).duration().count(), std::forward<SleepyTask>(task)});
        return true;
    }

    /// try to swap an existing sleepy task with a task that wakes up sooner
    /// - this function does not add/remove elements from the queue; instead, it simply adjusts task statuses then
    ///   swaps pointers
    /// - if 'task_inout == nullptr', then we set it to the unclaimed task with the lowest waketime
    /// - the cost of this function may be higher than expected if there are many tasks with higher priority than our
    ///   allowed max
    bool try_swap(const unsigned char max_task_priority, SleepyTask* &task_inout)
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

    std::list<SleepyTask> try_perform_maintenance()
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

private:
//member variables
    /// queue context (sorted by waketime)
    boost::multimap<std::chrono::time_point<std::chrono::steady_clock>::rep, SleepyTask> m_queue;
    std::mutex m_mutex;
};


/// waiter manager
/// - performance will decrease significantly if multiple threads try to claim the same waiter index
/// - notify_one() prioritizes: normal waiters > sleepy waiters > conditional waiters
///   - this function has several race conditions that can mean no worker gets notified even if there are several actually
///     waiting (these are non-critical race conditions that marginally reduce throughput under low to moderate load)
///   - there is also a race condition where a conditional waiter gets notified but ends up detecting its condition was
///     triggered, implying it will go down some custom upstream control path instead of the normal path that
///     'notify_one()' is aimed at (e.g. 'go find a task to work on'); (this marginally reduces throughput under moderate
///     to high load)
/// - conditional waiting is designed so a conditional waiter will never wait after its condition is set if a conditional
///   notify is used to set the condition
///   - COST: the condition setting/checking is protected by a unique lock, so any real system WILL waste time fighting
///     over those locks (to maximize throughput, consider using large task graphs to avoid manual joining and other
///     mechanisms that use conditional waits)
/// - 'shutting down' the manager means
///   A) existing waiters will all be woken up
///   B) future waiters using 'ShutdownPolicy::EXIT_EARLY' will simply exit without waiting
class WaiterManager final
{
    struct ConditionalWaiterContext final
    {
        std::atomic<std::int32_t> num_waiting;
        std::condition_variable cond_var;
    };

    std::uint16_t clamp_waiter_index(const std::uint16_t nominal_index)
    {
        if (nominal_index >= m_num_managed_waiters)
            return m_num_managed_waiters - 1;
        return nominal_index;
    }

    /// wait
    /// - note: the order of result checks is intentional based on their assumed importance to the caller
    Result wait_impl(std::mutex &mutex_inout,
        std::condition_variable &condvar_inout,
        std::atomic<std::uint16_t> &counter_inout,
        const std::function<bool()> &condition_checker_func,
        const std::function<std::cv_status(std::condition_variable&, std::unique_lock<std::mutex>&)> &wait_func,
        const ShutdownPolicy shutdown_policy)
    {
        std::unique_lock<std::mutex> lock{mutex_inout};

        // pre-wait checks
        if (condition_checker_func)
        {
            try { if (condition_checker_func()) return Result::CONDITION_TRIGGERED; }
            catch (...)                       { return Result::CONDITION_TRIGGERED; }
        }
        if (shutdown_policy == ShutdownPolicy::EXIT_EARLY && this->is_shutting_down()) return Result::SHUTTING_DOWN;

        // wait
        // note: using a signed int for counters means underflow due to reordering of the decrement won't yield a value > 0
        counter_inout.fetch_add(1, std::memory_order_relaxed);
        const std::cv_status wait_status{wait_func(condvar_inout, lock)};
        counter_inout.fetch_sub(1, std::memory_order_relaxed);

        // post-wait checks
        if (condition_checker_func)
        {
            try { if (condition_checker_func()) return Result::CONDITION_TRIGGERED; }
            catch (...)                       { return Result::CONDITION_TRIGGERED; }
        }
        if (this->is_shutting_down())               return Result::SHUTTING_DOWN;
        if (wait_status == std::cv_status::timeout) return Result::TIMEOUT;

        return Result::DONE_WAITING;
    }

public:
    enum class ShutdownPolicy : unsigned char
    {
        WAIT,
        EXIT_EARLY
    };

    enum class Result : unsigned char
    {
        CONDITION_TRIGGERED,
        SHUTTING_DOWN,
        TIMEOUT,
        DONE_WAITING
    };

//constructors
    WaiterManager(const std::uint16_t num_managed_waiters) :
        //we always want at least one waiter slot to avoid UB
        m_num_managed_waiters{num_managed_waiters > 0 : num_managed_waiters : 1}
    {
        m_conditional_waiters.resize(m_num_managed_waiters);
        m_waiter_mutexes.resize(m_num_managed_waiters);
    }

//overloaded operators
    /// disable copy/moves so references to this object can't be invalidated until this object's lifetime ends
    WaiterManager& operator=(WaiterManager&&) = delete;

//member functions
    void notify_one()
    {
        // try to notify a normal waiter
        if (m_num_normal_waiters.load(std::memory_order_relaxed) > 0)
        {
            m_normal_shared_cond_var.notify_one();
            return;
        }

        // try to notify a sleepy waiter
        if (m_num_sleepy_waiters.load(std::memory_order_relaxed) > 0)
        {
            m_sleepy_shared_cond_var.notify_one();
            return;
        }

        // find a conditional waiter to notify
        for (ConditionalWaiterContext &conditional_waiter : m_conditional_waiters)
        {
            if (conditional_waiter.is_waiting.load(std::memory_order_relaxed) > 0)
            {
                conditional_waiter.cond_var.notify_one();
                break;
            }
        }
    }
    void notify_all()
    {
        m_normal_shared_cond_var.notify_all();
        m_sleepy_shared_cond_var.notify_all();
        for (ConditionalWaiterContext &conditional_waiter : m_conditional_waiters)
            conditional_waiter.cond_var.notify_all();
    }
    void notify_conditional_waiter(const std::uint16_t waiter_index, std::function<void()> condition_setter_func)
    {
        const std::uint16_t clamped_waiter_index{this->clamp_waiter_index(waiter_index)};
        if (condition_setter_func) try { condition_setter_func(); } catch (...) {}
        // tap the mutex here to synchronize with conditional waiters
        { const std::lock_guard<std::mutex> lock{m_waiter_mutexes[clamped_waiter_index]}; };
        // notify all because if there are multiple threads waiting on this index (not recommended, but possible),
        //   we don't know which one actually cares about this condition function
        m_conditional_waiters[clamped_waiter_index].cond_var.notify_all();
    }

    Result wait(const std::uint16_t waiter_index, const ShutdownPolicy shutdown_policy)
    {
        return this->wait_impl(m_waiter_mutexes[this->clamp_waiter_index(waiter_index)],
                m_normal_shared_cond_var,
                m_num_normal_waiters,
                nullptr,
                [](std::condition_variable &cv_inout, std::unique_lock<std::mutex> &lock) -> std::cv_status
                {
                    cv_inout.wait(lock);
                    return std::cv_status::no_timeout;
                },
                shutdown_policy
            );
    }
    Result wait_for(const std::uint16_t waiter_index,
        const std::chrono::duration &duration,
        const ShutdownPolicy shutdown_policy)
    {
        return this->wait_impl(m_waiter_mutexes[this->clamp_waiter_index(waiter_index)],
                m_sleepy_shared_cond_var,
                m_num_sleepy_waiters,
                nullptr,
                [&duration](std::condition_variable &cv_inout, std::unique_lock<std::mutex> &lock_inout) -> std::cv_status
                {
                    return cv_inout.wait_for(lock_inout, duration);
                },
                shutdown_policy
            );
    }
    Result wait_until(const std::uint16_t waiter_index,
        const std::time_point<std::chrono::steady_clock> &timepoint,
        const ShutdownPolicy shutdown_policy)
    {
        return this->wait_impl(m_waiter_mutexes[this->clamp_waiter_index(waiter_index)],
                m_sleepy_shared_cond_var,
                m_num_sleepy_waiters,
                nullptr,
                [&timepoint](std::condition_variable &cv_inout, std::unique_lock<std::mutex> &lock_inout) -> std::cv_status
                {
                    return cv_inout.wait_until(lock_inout, timepoint);
                },
                shutdown_policy
            );
    }
    Result conditional_wait(const std::uint16_t waiter_index,
        const std::function<bool()> &condition_checker_func,
        const ShutdownPolicy shutdown_policy)
    {
        const std::uint16_t clamped_waiter_index{this->clamp_waiter_index(waiter_index)};
        return this->wait_impl(m_waiter_mutexes[clamped_waiter_index],
                m_conditional_waiters[clamped_waiter_index].cond_var,
                m_conditional_waiters[clamped_waiter_index].num_waiting,
                condition_checker_func,
                [](std::condition_variable &cv_inout, std::unique_lock<std::mutex> &lock_inout) -> std::cv_status
                {
                    cv_inout.wait(lock_inout);
                    return std::cv_status::no_timeout;
                },
                shutdown_policy
            );
    }
    Result conditional_wait_for(const std::uint16_t waiter_index,
        const std::function<bool()> &condition_checker_func,
        const std::chrono::duration &duration,
        const ShutdownPolicy shutdown_policy)
    {
        const std::uint16_t clamped_waiter_index{this->clamp_waiter_index(waiter_index)};
        return this->wait_impl(m_waiter_mutexes[clamped_waiter_index],
                m_conditional_waiters[clamped_waiter_index].cond_var,
                m_conditional_waiters[clamped_waiter_index].num_waiting,
                condition_checker_func,
                [&duration](std::condition_variable &cv_inout, std::unique_lock<std::mutex> &lock_inout) -> std::cv_status
                {
                    return cv_inout.wait_for(lock_inout, duration);
                },
                shutdown_policy
            );
    }
    Result conditional_wait_until(const std::uint16_t waiter_index,
        const std::function<bool()> &condition_checker_func,
        const std::time_point<std::chrono::steady_clock> &timepoint,
        const ShutdownPolicy shutdown_policy)
    {
        const std::uint16_t clamped_waiter_index{this->clamp_waiter_index(waiter_index)};
        return this->wait_impl(m_waiter_mutexes[clamped_waiter_index],
                m_conditional_waiters[clamped_waiter_index].cond_var,
                m_conditional_waiters[clamped_waiter_index].num_waiting,
                condition_checker_func,
                [&timepoint](std::condition_variable &cv_inout, std::unique_lock<std::mutex> &lock_inout) -> std::cv_status
                {
                    return cv_inout.wait_until(lock_inout, timepoint);
                },
                shutdown_policy
            );
    }

    void shut_down()
    {
        // shut down
        m_shutting_down.store(true, std::memory_order_relaxed);

        // tap all the mutexes to synchronize with waiters
        for (std::mutex &mutex : m_waiter_mutexes)
            const std::lock_guard<std::mutex> lock{mutex};

        // notify all waiters
        this->notify_all();
    }

    bool is_shutting_down() const { return m_shutting_down.load(std::memory_order_relaxed); }

private:
//member variables
    /// config
    const std::uint16_t m_num_managed_waiters;

    /// manager status
    std::atomic<std::int32_t> m_num_normal_waiters{0};
    std::atomic<std::int32_t> m_num_sleepy_waiters{0};
    std::atomic<bool> m_shutting_down{false};

    /// synchronization
    std::vector<std::mutex> m_waiter_mutexes;
    std::condition_variable m_normal_shared_cond_var;
    std::condition_variable m_sleepy_shared_cond_var;

    /// conditional waiters
    std::vector<ConditionalWaiterContext> m_conditional_waiters;
};


/// thread pool
class ThreadPool final
{
public:
//constructors
    /// default constructor: disabled
    ThreadPool() = delete;
    /// normal constructor: from config
    ThreadPool(const unsigned char num_priority_levels,
        const std::uint16_t num_managed_workers,
        const std::uint32_t max_queue_size);

    /// disable copy/moves so references to this object can't be invalidated until this object's lifetime ends
    ThreadPool& operator=(ThreadPool&&) = delete;

//destructor
    ~ThreadPool();

//member functions
    /// submit a task
    void submit();

    /// run as a pool worker
    void run(const std::uint16_t worker_index);

    /// shut down the threadpool
    void shut_down();

    /// id of this threadpool
    std::uint64_t threadpool_id() const { return m_threadpool_id; }
    std::uint64_t threadpool_owner_id() const { return m_threadpool_owner_id; }

private:
//member variables
    /// config
    const std::uint64_t m_threadpool_id;  //unique identifier for this threadpool
    const std::uint64_t m_threadpool_owner_id;  //unique identifier for the thread that owns this threadpool
    const unsigned char m_max_priority_level;  //note: priority 0 is the 'highest' priority
    const std::uint16_t m_num_queues;  //num workers + 1 for the main thread
    const unsigned char m_num_submit_cycle_attempts;
    const std::uint32_t m_max_queue_size;
    const std::chrono::duration m_max_wait_duration;

    /// worker context
    std::vector<std::thread> m_workers;

    /// queues
    std::vector<std::vector<TokenQueue>> m_task_queues;  //outer vector: priorities, inner vector: workers
    std::vector<SleepyTokenQueue> m_sleepy_task_queues;   //vector: workers
    std::atomic<std::uint16_t> m_normal_queue_submission_counter{0};
    std::atomic<std::uint16_t> m_sleepy_queue_submission_counter{0};

    // waiter manager
    WaiterManager m_waiter_manager;
};

} //namespace tools
