/*
 * Definitions likely to be helpful to multiple AES implementations.
 */

/*
 * The 'extra' structure used by AES implementations is used to
 * include information about how to check if a given implementation is
 * available at run time, and whether we've already checked.
 */
struct aes_extra_mutable;
struct aes_extra {
    /* Function to check availability. Might be expensive, so we don't
     * want to call it more than once. */
    bool (*check_available)(void);

    /* Point to a writable substructure. */
    struct aes_extra_mutable *mut;

    /* Extra API function specific to AES, to encrypt a single block
     * in ECB mode without touching the IV. Used by AES-GCM MAC
     * setup. */
    void (*encrypt_ecb_block)(ssh_cipher *, void *);
};
struct aes_extra_mutable {
    bool checked_availability;
    bool is_available;
};
static inline bool check_availability(const struct aes_extra *extra)
{
    if (!extra->mut->checked_availability) {
        extra->mut->is_available = extra->check_available();
        extra->mut->checked_availability = true;
    }

    return extra->mut->is_available;
}

/* Shared stub function for all the AES-GCM vtables. */
void aesgcm_cipher_crypt_length(
    ssh_cipher *cipher, void *blk, int len, unsigned long seq);

/* External entry point for the encrypt_ecb_block function. */
static inline void aes_encrypt_ecb_block(ssh_cipher *ciph, void *blk)
{
    const struct aes_extra *extra = ciph->vt->extra;
    extra->encrypt_ecb_block(ciph, blk);
}

/*
 * Macros to define vtables for AES variants. There are a lot of
 * these, because of the cross product between cipher modes, key
 * sizes, and assorted HW/SW implementations, so it's worth spending
 * some effort here to reduce the boilerplate in the sub-files.
 */

#define AES_EXTRA_BITS(impl_c, bits)                                    \
    static struct aes_extra_mutable aes ## impl_c ## _extra_mut;        \
    static const struct aes_extra aes ## bits ## impl_c ## _extra = {   \
        .check_available = aes ## impl_c ## _available,                 \
        .mut = &aes ## impl_c ## _extra_mut,                            \
        .encrypt_ecb_block = &aes ## bits ## impl_c ## _encrypt_ecb_block, \
    }

#define AES_EXTRA(impl_c)                       \
    AES_EXTRA_BITS(impl_c, 128);                \
    AES_EXTRA_BITS(impl_c, 192);                \
    AES_EXTRA_BITS(impl_c, 256)

#define AES_CBC_VTABLE(impl_c, impl_display, bits)                      \
    const ssh_cipheralg ssh_aes ## bits ## _cbc ## impl_c = {           \
        .new = aes ## impl_c ## _new,                                   \
        .free = aes ## impl_c ## _free,                                 \
        .setiv = aes ## impl_c ## _setiv_cbc,                           \
        .setkey = aes ## impl_c ## _setkey,                             \
        .encrypt = aes ## bits ## impl_c ## _cbc_encrypt,               \
        .decrypt = aes ## bits ## impl_c ## _cbc_decrypt,               \
        .next_message = nullcipher_next_message,                        \
        .ssh2_id = "aes" #bits "-cbc",                                  \
        .blksize = 16,                                                  \
        .real_keybits = bits,                                           \
        .padded_keybytes = bits/8,                                      \
        .flags = SSH_CIPHER_IS_CBC,                                     \
        .text_name = "AES-" #bits " CBC (" impl_display ")",            \
        .extra = &aes ## bits ## impl_c ## _extra,                      \
    }

#define AES_SDCTR_VTABLE(impl_c, impl_display, bits)                    \
    const ssh_cipheralg ssh_aes ## bits ## _sdctr ## impl_c = {         \
        .new = aes ## impl_c ## _new,                                   \
        .free = aes ## impl_c ## _free,                                 \
        .setiv = aes ## impl_c ## _setiv_sdctr,                         \
        .setkey = aes ## impl_c ## _setkey,                             \
        .encrypt = aes ## bits ## impl_c ## _sdctr,                     \
        .decrypt = aes ## bits ## impl_c ## _sdctr,                     \
        .next_message = nullcipher_next_message,                        \
        .ssh2_id = "aes" #bits "-ctr",                                  \
        .blksize = 16,                                                  \
        .real_keybits = bits,                                           \
        .padded_keybytes = bits/8,                                      \
        .flags = 0,                                                     \
        .text_name = "AES-" #bits " SDCTR (" impl_display ")",          \
        .extra = &aes ## bits ## impl_c ## _extra,                      \
    }

#define AES_GCM_VTABLE(impl_c, impl_display, bits)                      \
    const ssh_cipheralg ssh_aes ## bits ## _gcm ## impl_c = {           \
        .new = aes ## impl_c ## _new,                                   \
        .free = aes ## impl_c ## _free,                                 \
        .setiv = aes ## impl_c ## _setiv_gcm,                           \
        .setkey = aes ## impl_c ## _setkey,                             \
        .encrypt = aes ## bits ## impl_c ## _gcm,                       \
        .decrypt = aes ## bits ## impl_c ## _gcm,                       \
        .encrypt_length = aesgcm_cipher_crypt_length,                   \
        .decrypt_length = aesgcm_cipher_crypt_length,                   \
        .next_message = aes ## impl_c ## _next_message_gcm,             \
        /* 192-bit AES-GCM is included only so that testcrypt can run   \
         * standard test vectors against it. OpenSSH doesn't define a   \
         * protocol id for it. So we set its ssh2_id to NULL. */        \
        .ssh2_id = bits==192 ? NULL : "aes" #bits "-gcm@openssh.com",   \
        .blksize = 16,                                                  \
        .real_keybits = bits,                                           \
        .padded_keybytes = bits/8,                                      \
        .flags = SSH_CIPHER_SEPARATE_LENGTH,                            \
        .text_name = "AES-" #bits " GCM (" impl_display ")",            \
        .required_mac = &ssh2_aesgcm_mac,                               \
        .extra = &aes ## bits ## impl_c ## _extra,                      \
    }

#define AES_ALL_VTABLES(impl_c, impl_display)           \
    AES_CBC_VTABLE(impl_c, impl_display, 128);          \
    AES_CBC_VTABLE(impl_c, impl_display, 192);          \
    AES_CBC_VTABLE(impl_c, impl_display, 256);          \
    AES_SDCTR_VTABLE(impl_c, impl_display, 128);        \
    AES_SDCTR_VTABLE(impl_c, impl_display, 192);        \
    AES_SDCTR_VTABLE(impl_c, impl_display, 256);        \
    AES_GCM_VTABLE(impl_c, impl_display, 128);          \
    AES_GCM_VTABLE(impl_c, impl_display, 192);          \
    AES_GCM_VTABLE(impl_c, impl_display, 256)

/*
 * Macros to repeat a piece of code particular numbers of times that
 * correspond to 1 fewer than the number of AES rounds. (Because the
 * last round is different.)
 */
#define REP2(x) x x
#define REP4(x) REP2(REP2(x))
#define REP8(x) REP2(REP4(x))
#define REP9(x) REP8(x) x
#define REP11(x) REP8(x) REP2(x) x
#define REP13(x) REP8(x) REP4(x) x

/*
 * The round constants used in key schedule expansion.
 */
extern const uint8_t aes_key_setup_round_constants[10];

/*
 * The largest number of round keys ever needed.
 */
#define MAXROUNDKEYS 15
