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

// local headers
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "common/util.h"
#include "console_handler.h"
#include "crypto/chacha.h"
#include "key_container.h"
#include "math_helper.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/pair.h"
#include "serialization/string.h"
#include "wipeable_string.h"

#include "transaction_history_component.h"

// standard headers
#include <string>
#include <vector>

// forward declarations

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;
namespace jsw
{

class wallet3
{
    private:
    key_container_base m_key_container;  // Class that stores the private/public keys in memory
    transaction_history_manager m_thm;

    uint64_t m_kdf_rounds = 1;
    bool m_is_wallet3;
    std::string m_keys_file;
    std::string m_wallet_file;
    std::unique_ptr<tools::file_locker> m_keys_file_locker;
    struct keys_file_data
    {
        crypto::chacha_iv iv;
        std::string account_data;

        BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
        END_SERIALIZE()
    };

    public:
    SpEnoteStoreMockV1 m_enote_store{0, 0, 0};
    MockLedgerContext m_ledger_context{0, 10000};
    address_index_t m_current_index{make_address_index(0, 0)};
    wallet3();
    size_t m_wallet_type;
    std::atomic<time_t> m_last_activity_time;
    std::atomic<bool> m_locked;
    std::atomic<bool> m_in_command;
    epee::console_handlers_binder m_cmd_binder;
    uint32_t m_inactivity_lock_timeout;

    std::atomic<bool> m_idle_run;
    boost::thread m_idle_thread;
    boost::mutex m_idle_mutex;
    boost::condition_variable m_idle_cond;
    epee::math_helper::once_a_time_seconds<1> m_inactivity_checker;

    bool init();
    bool run();
    void stop();

    bool create_or_open_wallet(key_container_base &key_container);
    void create_new_keys_w3(std::string &wallet_path, const epee::wipeable_string &password,
                            key_container_base &key_container);
    void create_viewbalance(const epee::wipeable_string &password, key_container_base &key_container);

    void print_wallet_type();
    boost::optional<keys_file_data> get_keys_file_data(const epee::wipeable_string &password,
                                                       key_container_base &key_container);
    void do_prepare_file_names(const std::string &file_path, std::string &keys_file, std::string &wallet_file);
    bool prepare_file_names(const std::string &file_path);
    bool store_keys(const std::string &keys_file_name, const epee::wipeable_string &password,
                    key_container_base &key_container);

    std::string get_public_address_w3(key_container_base &key_container);

    void wallet_exists(const std::string &file_path, bool &keys_file_exists, bool &wallet_file_exists);
    bool wallet_valid_path_format(const std::string &file_path);

    bool save_to_file(const std::string &path_to_file, const std::string &raw, bool is_printable);
    bool load_keys_buf_w3(const std::string &keys_buf, const epee::wipeable_string &password,
                          boost::optional<crypto::chacha_key> &keys_to_encrypt, key_container_base &key_container_out);
    bool load_keys_w3(const std::string &keys_file_name, const epee::wipeable_string &password,
                      key_container_base &key_container);
    bool load_from_file(const std::string &path_to_file, std::string &target_str, size_t max_size = 1000000000);

    void setup_keys(const epee::wipeable_string &password, key_container_base &key_container);
    void encrypt_keys(const crypto::chacha_key &key, key_container_base &key_container);
    void decrypt_keys(const crypto::chacha_key &key, key_container_base &key_container);
    void encrypt_keys(const epee::wipeable_string &password, key_container_base &key_container);
    void decrypt_keys(const epee::wipeable_string &password, key_container_base &key_container);

    bool verify_password(const epee::wipeable_string &password);
    bool verify_password(const std::string &keys_file_name, const epee::wipeable_string &password, uint64_t kdf_rounds);

    bool is_keys_file_locked() const;
    bool unlock_keys_file();
    bool lock_keys_file();

    bool on_unknown_command(const std::vector<std::string> &args);
    bool on_empty_command();
    bool on_cancelled_command();
    bool on_command(bool (wallet3::*cmd)(const std::vector<std::string> &), const std::vector<std::string> &args);
    std::string get_prompt() const;
    bool get_command();
    uint32_t inactivity_lock_timeout() const { return m_inactivity_lock_timeout; }
    void inactivity_lock_timeout(uint32_t seconds) { m_inactivity_lock_timeout = seconds; }
    void set_wallet_type(size_t type);
    void check_for_inactivity_lock(bool user);
    void wallet_idle_thread();
    bool check_inactivity();
    bool close_wallet();

    boost::optional<tools::password_container> get_and_verify_password();
    std::string input_line(const std::string &prompt, bool yesno);
    tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default,
                                                bool bright = false);
    boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify);
    boost::optional<tools::password_container> default_password_prompter(bool verify);


    bool help(const std::vector<std::string> &args);
    bool save_viewbalance(const std::vector<std::string> &args);
    bool create_money(const std::vector<std::string> &args);
    bool show_balance(const std::vector<std::string> &args);
    bool show_address(const std::vector<std::string> &args);
    bool show_transfer(const std::vector<std::string> &args);
    bool transfer_mock_v1(const std::vector<std::string> &args);
    bool fake_txs(const std::vector<std::string> &args);

    void refresh_enote_store();
    void refresh_transaction_history();
    bool try_add_tx_to_tx_history(const rct::key &tx_id, const SpTxSquashedV1 tx, const std::vector<std::pair<std::string,rct::xmr_amount>> &dest);
};

}  // namespace jsw