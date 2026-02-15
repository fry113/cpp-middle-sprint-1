#pragma once

#include <experimental/propagate_const>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <string>

namespace CryptoGuard {

class CryptoGuardCtx {
private:  // types
    class Impl;

public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    bool isValid() const;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    const Impl *GetImpl() const;
    Impl *GetImpl();
    // std::unique_ptr<Impl> pImpl_;
    std::experimental::propagate_const<std::unique_ptr<Impl>> pImpl_;
};

}  // namespace CryptoGuard
