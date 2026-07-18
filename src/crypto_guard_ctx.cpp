#include "crypto_guard_ctx.h"
#include <array>
#include <iomanip>
#include <openssl/err.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
private:  // types
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;  // AES-256 key size
        static const size_t IV_SIZE = 16;   // AES block size (IV length)

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };
    using EVP_CIPHER_CTX_PTR = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx_ptr) {
                                                   if (ctx_ptr) {
                                                       EVP_CIPHER_CTX_free(ctx_ptr);
                                                   }
                                               })>;
    using EVP_MD_CTX_PTR = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx_ptr) {
                                               if (ctx_ptr) {
                                                   EVP_MD_CTX_free(ctx_ptr);
                                               }
                                           })>;

public:
    Impl();
    ~Impl() noexcept;
    void Encrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void Decrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    AesCipherParams CreateCipherParamsFromPassword(std::string_view password);
    void do_cipher(std::iostream &inStream, std::iostream &outStream);
    void throwOpenSSLerrors();

    AesCipherParams params;
};

CryptoGuardCtx::Impl::Impl() { OpenSSL_add_all_algorithms(); }

CryptoGuardCtx::Impl::~Impl() noexcept { EVP_cleanup(); }

void CryptoGuardCtx::Impl::throwOpenSSLerrors() {
    auto osslErrNum = ERR_get_error();
    std::string errtext = "OpenSSL error codes:";
    while (osslErrNum) {
        errtext += ' ';
        errtext += std::to_string(osslErrNum);
        osslErrNum = ERR_get_error();
    }
    throw std::runtime_error{errtext};
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    if (inStream.bad()) {
        throw std::runtime_error("Cannot read inStream");
    }
    std::vector<unsigned char> inBuf(32);
    std::vector<unsigned char> outBuf(32);

    // Инициализируем message digest
    EVP_MD_CTX_PTR ctx(EVP_MD_CTX_new());
    if (!EVP_DigestInit_ex(ctx.get(), EVP_get_digestbyname("SHA256"), nullptr)) {
        throwOpenSSLerrors();
    }

    // Обрабатываем входной поток
    uint inLen;
    uint outLen;
    inStream.seekg(0, std::ios::beg);
    while (true) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        inLen = inStream.gcount();
        if (!inLen) {
            break;
        }
        if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), inLen)) {
            throwOpenSSLerrors();
        }
        if (inStream.bad()) {
            throw std::runtime_error("inStream read error");
        }
    }
    if (inStream.eof()) {
        inStream.clear();
        inStream.seekg(0, std::ios::beg);
    }

    // Заканчиваем работу с digest
    if (!EVP_DigestFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throwOpenSSLerrors();
    }

    std::stringstream ss;
    for (size_t i = 0; i < outBuf.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(outBuf[i]);
    }
    return ss.str();
}

void CryptoGuardCtx::Impl::do_cipher(std::iostream &inStream, std::iostream &outStream) {
    if (&inStream == &outStream) {
        throw std::runtime_error("inStream is the same as outStream");
    }
    if (inStream.bad()) {
        throw std::runtime_error("Cannot read inStream");
    }
    if (outStream.bad()) {
        throw std::runtime_error("Cannot write outStream");
    }
    std::vector<unsigned char> inBuf(16);
    std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);

    // Инициализируем cipher
    EVP_CIPHER_CTX_PTR ctx(EVP_CIPHER_CTX_new());
    if (!EVP_CipherInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, params.key.data(), params.iv.data(),
                           params.encrypt)) {
        throwOpenSSLerrors();
    }

    // Обрабатываем входной поток
    int outLen;
    int inLen;
    inStream.seekg(0, std::ios::beg);
    outStream.seekp(0, std::ios::beg);
    while (true) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        inLen = inStream.gcount();
        if (!inLen) {
            break;
        }
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen)) {
            throwOpenSSLerrors();
        }
        if (inStream.bad()) {
            throw std::runtime_error("inStream read error");
        }
        if (!outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen)) {
            throw std::runtime_error("outStream write error");
        }
    }
    if (inStream.eof()) {
        inStream.clear();
        inStream.seekg(0, std::ios::beg);
    }

    // Заканчиваем работу с cipher
    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throwOpenSSLerrors();
    }
    if (outLen > outBuf.size()) {
        throw std::runtime_error("EVP_CipherFinal_ex exceeded return value size");
    }
    if (outLen > 0) {
        if (!outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen)) {
            throw std::runtime_error("outStream final write error");
        }
    }
}

void CryptoGuardCtx::Impl::Encrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (password.empty()) {
        throw std::runtime_error("Empty password");
    }
    params = CreateCipherParamsFromPassword(password);
    params.encrypt = 1;
    do_cipher(inStream, outStream);
}

void CryptoGuardCtx::Impl::Decrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (password.empty()) {
        throw std::runtime_error("Empty password");
    }
    params = CreateCipherParamsFromPassword(password);
    params.encrypt = 0;
    do_cipher(inStream, outStream);
}

CryptoGuardCtx::Impl::AesCipherParams CryptoGuardCtx::Impl::CreateCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

bool CryptoGuardCtx::isValid() const { return true; }

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    GetImpl()->Encrypt(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    GetImpl()->Decrypt(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return GetImpl()->CalculateChecksum(inStream);
}

const CryptoGuardCtx::Impl *CryptoGuardCtx::GetImpl() const { return pImpl_.get(); }

CryptoGuardCtx::Impl *CryptoGuardCtx::GetImpl() { return pImpl_.get(); }

}  // namespace CryptoGuard
