/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *      Overdding few APIs from mbedTLS based implementation of CHIP crypto primitives
 *      for using secure element on ESP32H2 SoC
 */

#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/CHIPSafeCasts.h>

#include <mbedtls/bignum.h>
// #include <mbedtls/ccm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <ecdsa/ecdsa_alt.h>
// #include <mbedtls/entropy.h>
// #include <mbedtls/error.h>
// #include <mbedtls/hkdf.h>
// #include <mbedtls/md.h>
// #include <mbedtls/pkcs5.h>
// #include <mbedtls/sha1.h>
// #include <mbedtls/sha256.h>

// In mbedTLS 3.0.0 direct access to structure fields was replaced with using MBEDTLS_PRIVATE macro.
#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
#define CHIP_CRYPTO_PAL_PRIVATE(x) MBEDTLS_PRIVATE(x)
#else
#define CHIP_CRYPTO_PAL_PRIVATE(x) x
#endif

namespace {

static int CryptoRNG(void * ctxt, uint8_t * out_buffer, size_t out_length)
{
    return (chip::Crypto::DRBG_get_bytes(out_buffer, out_length) == CHIP_NO_ERROR) ? 0 : 1;
}

static inline mbedtls_ecdsa_context * to_ecdsa_ctx(chip::Crypto::P256KeypairContext * context)
{
    return chip::SafePointerCast<mbedtls_ecdsa_context *>(context);
}

static inline const mbedtls_ecp_keypair * to_const_ecdsa_ctx(const chip::Crypto::P256KeypairContext * context)
{
    return chip::SafePointerCast<const mbedtls_ecdsa_context *>(context);
}

} // anonymous namespace

namespace chip {
namespace Crypto {

class ESP32P256Keypair : public P256Keypair
{
public:
    /**
     * @brief Initialize the keypair.
     * @return Returns a CHIP_ERROR on error, CHIP_NO_ERROR otherwise
     **/
    CHIP_ERROR Initialize(ECPKeyTarget keyTarget, int efuseBlock)
    {
        // TODO: Add error checks
        Clear();

        CHIP_ERROR error = CHIP_NO_ERROR;

        mbedtls_ecdsa_context * ecdsa_ctx = to_ecdsa_ctx(&mKeypair);
        mbedtls_ecdsa_init(ecdsa_ctx);

        mbedtls_ecp_group_load(&ecdsa_ctx->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);

        esp_ecdsa_privkey_load_mpi(&ecdsa_ctx->MBEDTLS_PRIVATE(d), efuseBlock);

        mInitialized = true;
        ecdsa_ctx = nullptr;
        return error;
    }

    CHIP_ERROR ECDSA_sign_msg(const uint8_t * msg, const size_t msg_length, P256ECDSASignature & out_signature) const override
    {
        VerifyOrReturnError(mInitialized, CHIP_ERROR_WELL_UNINITIALIZED);
        VerifyOrReturnError((msg != nullptr) && (msg_length > 0), CHIP_ERROR_INVALID_ARGUMENT);

        uint8_t digest[kSHA256_Hash_Length];
        memset(&digest[0], 0, sizeof(digest));
        ReturnErrorOnFailure(Hash_SHA256(msg, msg_length, &digest[0]));

#if defined(MBEDTLS_ECDSA_C)
        CHIP_ERROR error = CHIP_NO_ERROR;
        int result       = 0;
        mbedtls_mpi r, s;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        // mbedtls_mpi shall be stored rather than
        mbedtls_ecdsa_context * ecdsa_ctx = to_ecdsa_ctx(&mKeypair);

        result = mbedtls_ecdsa_sign(&ecdsa_ctx->CHIP_CRYPTO_PAL_PRIVATE(grp), &r, &s, &ecdsa_ctx->CHIP_CRYPTO_PAL_PRIVATE(d),
                                    Uint8::to_const_uchar(digest), sizeof(digest), CryptoRNG, nullptr);

        VerifyOrExit(result == 0, error = CHIP_ERROR_INTERNAL);

        VerifyOrExit((mbedtls_mpi_size(&r) <= kP256_FE_Length) && (mbedtls_mpi_size(&s) <= kP256_FE_Length),
                     error = CHIP_ERROR_INTERNAL);

        // Concatenate r and s to output. Sizes were checked above.
        result = mbedtls_mpi_write_binary(&r, out_signature.Bytes() + 0u, kP256_FE_Length);
        VerifyOrExit(result == 0, error = CHIP_ERROR_INTERNAL);

        result = mbedtls_mpi_write_binary(&s, out_signature.Bytes() + kP256_FE_Length, kP256_FE_Length);
        VerifyOrExit(result == 0, error = CHIP_ERROR_INTERNAL);

        VerifyOrExit(out_signature.SetLength(kP256_ECDSA_Signature_Length_Raw) == CHIP_NO_ERROR, error = CHIP_ERROR_INTERNAL);

    exit:
        ecdsa_ctx = nullptr;
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        return error;
#else
        return CHIP_ERROR_NOT_IMPLEMENTED;
#endif
    }

    void Clear()
    {
        if (mInitialized)
        {
            mbedtls_ecdsa_context * ecdsa_ctx = to_ecdsa_ctx(&mKeypair);
            mbedtls_ecdsa_free(ecdsa_ctx);
            mInitialized = false;
        }
    }
};

} // namespace Crypto
} // namespace chip
