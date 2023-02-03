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

    key_container_base m_key_container;  // Class that stores the private/public keys in memory

   public:
    SpEnoteStoreMockV1 m_enote_store{0, 0, 0};
    MockLedgerContext m_ledger_context{0, 10000};
    address_index_t m_current_index{make_address_index(0, 0)};

   public:
    // wallet3();
    bool init();
    bool run();
    void stop();

   private:
    struct keys_file_data
    {
        crypto::chacha_iv iv;
        std::string account_data;

        BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
        END_SERIALIZE()
    };

    uint64_t m_kdf_rounds = 1;
    bool m_is_wallet3;
    std::string m_keys_file;
    std::string m_wallet_file;
    std::unique_ptr<tools::file_locker> m_keys_file_locker;

    /////////////////////////////////////
    //////// Generate/Load/Store  ///////
    /////////////////////////////////////

    bool create_or_open_wallet(key_container_base &key_container);
    void generate_keys(key_container_base &key_container);
    void create_new_keys_w3(std::string &wallet_path, const epee::wipeable_string &password,
                            key_container_base &key_container);

    /**
     * Prepare the necessary info to save wallet to disk
     */
    boost::optional<keys_file_data> get_keys_file_data(const epee::wipeable_string &password, size_t wallet_type,
                                                       key_container_base &key_container);

    /**
     * Prepare wallet filename by adding .keys if necessary
     */
    void do_prepare_file_names(const std::string &file_path, std::string &keys_file, std::string &wallet_file);

    /**
     * Prepare wallet filename by storing at m_keys_file and m_wallet_file
     */
    bool prepare_file_names(const std::string &file_path);

    /**
     * Prepare the necessary info to save wallet to disk
     */
    bool store_keys(const std::string &keys_file_name, const epee::wipeable_string &password, bool watch_only,
                    key_container_base &key_container);

    //   std::string get_public_address_w2();
    std::string get_public_address_w3(key_container_base &key_container);
    // sp::jamtis::account_base get_account() {return m_account;}

    /**
     * Verify if the wallet exists
     */
    void wallet_exists(const std::string &file_path, bool &keys_file_exists, bool &wallet_file_exists);

    /**
     * Verify if the wallet path is valid
     */
    bool wallet_valid_path_format(const std::string &file_path);

    /**
     * Prepare the necessary info to save wallet to disk
     */
    bool save_to_file(const std::string &path_to_file, const std::string &raw, bool is_printable);

    /**
     * Prepare the necessary info to load wallet from disk
     */
    bool load_keys_buf_w3(const std::string &keys_buf, const epee::wipeable_string &password,
                          boost::optional<crypto::chacha_key> &keys_to_encrypt, key_container_base &key_container_out);

    /**
     * Prepare the necessary info to load wallet from disk
     */
    bool load_keys_w3(const std::string &keys_file_name, const epee::wipeable_string &password,
                      key_container_base &key_container);

    /**
     * Prepare the necessary info to load wallet from disk
     */
    bool load_from_file(const std::string &path_to_file, std::string &target_str, size_t max_size = 1000000000);

    void setup_keys(const epee::wipeable_string &password, key_container_base &key_container);

    /**
     * Encrypt keys in memory
     */
    void encrypt_keys(const crypto::chacha_key &key, key_container_base &key_container);

    /**
     * Decrypt keys from memory
     */
    void decrypt_keys(const crypto::chacha_key &key, key_container_base &key_container);

    /**
     * Encrypt keys in memory
     */
    void encrypt_keys(const epee::wipeable_string &password, key_container_base &key_container);

    /**
     * Decrypt keys from memory
     */
    void decrypt_keys(const epee::wipeable_string &password, key_container_base &key_container);

    bool verify_password(const epee::wipeable_string &password);
    bool verify_password(const std::string &keys_file_name, const epee::wipeable_string &password, uint64_t kdf_rounds);

    bool is_keys_file_locked() const;
    bool unlock_keys_file();
    bool lock_keys_file();

    /////////////////////////////////////
    //////// Command line handling  /////
    /////////////////////////////////////

    // variables
   public:
    wallet3();
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

    // methods
    bool on_unknown_command(const std::vector<std::string> &args);
    bool on_empty_command();
    bool on_cancelled_command();
    bool on_command(bool (wallet3::*cmd)(const std::vector<std::string> &), const std::vector<std::string> &args);
    std::string get_prompt() const;
    bool get_command();
    uint32_t inactivity_lock_timeout() const { return m_inactivity_lock_timeout; }
    void inactivity_lock_timeout(uint32_t seconds) { m_inactivity_lock_timeout = seconds; }


    void check_for_inactivity_lock(bool user);
    void wallet_idle_thread();
    bool check_inactivity();
    bool close_wallet();

    boost::optional<tools::password_container> get_and_verify_password();

    /**
     * read the command line
     * param: prompt the string being read
     * param: yesno Should I write Yes/No confirmation?
     */
    std::string input_line(const std::string &prompt, bool yesno);

    /**
     * Variation of scoped_message_writer...
     */
    tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default,
                                                bool bright = false);
    /**
     * password prompter...
     */
    boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify);

    /**
     * password prompter...
     */
    boost::optional<tools::password_container> default_password_prompter(bool verify);

    // Seraphis integration functions

    bool create_money(const std::vector<std::string> &args);
    bool show_balance(const std::vector<std::string> &args);
    bool transfer(const std::vector<std::string> &args);
};

}  // namespace jsw