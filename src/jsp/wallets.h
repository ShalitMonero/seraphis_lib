#pragma once

#include "cryptonote_basic/account.h"
#include "wallet/wallet2.h"
#include "IO_file.h"

namespace jsw {

// class w2 : public tools::i_wallet2_callback{

// public:
// //std::unique_ptr<tools::wallet2> m_wallet;

// };
class Wallet2_legacy {

public:
  jsw::IO_file m_file;
};

class Wallet3 {
  // Class with common methods and variables to create a wallet in the
  // jamtis/seraphis standards

public:
  // variables
  jsw::IO_file m_file;

  // methods

  /**
   * create_or_open_wallet
   * Responsible for creating a new wallet or loading an old one.
   */
};

}