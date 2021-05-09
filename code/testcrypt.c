/*
 * testcrypt: a standalone test program that provides direct access to
 * PuTTY's cryptography and mp_int code.
 */

/*
 * This program speaks a line-oriented protocol on standard input and
 * standard output. It's a half-duplex protocol: it expects to read
 * one line of command, and then produce a fixed amount of output
 * (namely a line containing a decimal integer, followed by that many
 * lines each containing one return value).
 *
 * The protocol is human-readable enough to make it debuggable, but
 * verbose enough that you probably wouldn't want to speak it by hand
 * at any great length. The Python program test/testcrypt.py wraps it
 * to give a more useful user-facing API, by invoking this binary as a
 * subprocess.
 *
 * (I decided that was a better idea than making this program an
 * actual Python module, partly because you can rewrap the same binary
 * in another scripting language if you prefer, but mostly because
 * it's easy to attach a debugger to testcrypt or to run it under
 * sanitisers or valgrind or what have you.)
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "defs.h"
#include "ssh.h"
#include "sshkeygen.h"
#include "misc.h"
#include "mpint.h"
#include "ecc.h"

static NORETURN PRINTF_LIKE(1, 2) void fatal_error(const char *p, ...)
{
    va_list ap;
    fprintf(stderr, "testcrypt: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void out_of_memory(void) { fatal_error("out of memory"); }

/* For platforms where getticks is defined within this code base */
unsigned long (getticks)(void)
{ unreachable("this is a stub needed to link, and should never be called"); }

FILE *f_open(const struct Filename *fn, char const *mode, bool private)
{ unreachable("f_open should never be called by this test program"); }

static bool old_keyfile_warning_given;
void old_keyfile_warning(void) { old_keyfile_warning_given = true; }

static bufchain random_data_queue;
static prng *test_prng;
void random_read(void *buf, size_t size)
{
    if (test_prng) {
        prng_read(test_prng, buf, size);
    } else {
        if (!bufchain_try_fetch_consume(&random_data_queue, buf, size))
            fatal_error("No random data in queue");
    }
}

uint64_t prng_reseed_time_ms(void)
{
    static uint64_t previous_time = 0;
    return previous_time += 200;
}

#define VALUE_TYPES(X)                                                  \
    X(string, strbuf *, strbuf_free(v))                                 \
    X(mpint, mp_int *, mp_free(v))                                      \
    X(modsqrt, ModsqrtContext *, modsqrt_free(v))                       \
    X(monty, MontyContext *, monty_free(v))                             \
    X(wcurve, WeierstrassCurve *, ecc_weierstrass_curve_free(v))        \
    X(wpoint, WeierstrassPoint *, ecc_weierstrass_point_free(v))        \
    X(mcurve, MontgomeryCurve *, ecc_montgomery_curve_free(v))          \
    X(mpoint, MontgomeryPoint *, ecc_montgomery_point_free(v))          \
    X(ecurve, EdwardsCurve *, ecc_edwards_curve_free(v))                \
    X(epoint, EdwardsPoint *, ecc_edwards_point_free(v))                \
    X(hash, ssh_hash *, ssh_hash_free(v))                               \
    X(key, ssh_key *, ssh_key_free(v))                                  \
    X(cipher, ssh_cipher *, ssh_cipher_free(v))                         \
    X(mac, ssh2_mac *, ssh2_mac_free(v))                                \
    X(dh, dh_ctx *, dh_cleanup(v))                                      \
    X(ecdh, ecdh_key *, ssh_ecdhkex_freekey(v))                         \
    X(rsakex, RSAKey *, ssh_rsakex_freekey(v))                          \
    X(rsa, RSAKey *, rsa_free(v))                                       \
    X(prng, prng *, prng_free(v))                                       \
    X(keycomponents, key_components *, key_components_free(v))          \
    X(pcs, PrimeCandidateSource *, pcs_free(v))                         \
    X(pgc, PrimeGenerationContext *, primegen_free_context(v))          \
    X(pockle, Pockle *, pockle_free(v))                                 \
    /* end of list */

typedef struct Value Value;

enum ValueType {
#define VALTYPE_ENUM(n,t,f) VT_##n,
    VALUE_TYPES(VALTYPE_ENUM)
#undef VALTYPE_ENUM
};

typedef enum ValueType ValueType;

static const char *const type_names[] = {
#define VALTYPE_NAME(n,t,f) #n,
    VALUE_TYPES(VALTYPE_NAME)
#undef VALTYPE_NAME
};

#define VALTYPE_TYPEDEF(n,t,f)                  \
    typedef t TD_val_##n;                       \
    typedef t *TD_out_val_##n;
VALUE_TYPES(VALTYPE_TYPEDEF)
#undef VALTYPE_TYPEDEF

struct Value {
    /*
     * Protocol identifier assigned to this value when it was created.
     * Lives in the same malloced block as this Value object itself.
     */
    ptrlen id;

    /*
     * Type of the value.
     */
    ValueType type;

    /*
     * Union of all the things it could hold.
     */
    union {
#define VALTYPE_UNION(n,t,f) t vu_##n;
        VALUE_TYPES(VALTYPE_UNION)
#undef VALTYPE_UNION

        char *bare_string;
    };
};

static int valuecmp(void *av, void *bv)
{
    Value *a = (Value *)av, *b = (Value *)bv;
    return ptrlen_strcmp(a->id, b->id);
}

static int valuefind(void *av, void *bv)
{
    ptrlen *a = (ptrlen *)av;
    Value *b = (Value *)bv;
    return ptrlen_strcmp(*a, b->id);
}

static tree234 *values;

static Value *value_new(ValueType vt)
{
    static uint64_t next_index = 0;

    char *name = dupprintf("%s%"PRIu64, type_names[vt], next_index++);
    size_t namelen = strlen(name);

    Value *val = snew_plus(Value, namelen+1);
    memcpy(snew_plus_get_aux(val), name, namelen+1);
    val->id.ptr = snew_plus_get_aux(val);
    val->id.len = namelen;
    val->type = vt;

    Value *added = add234(values, val);
    assert(added == val);

    sfree(name);

    return val;
}

#define VALTYPE_RETURNFN(n,t,f)                                 \
    void return_val_##n(strbuf *out, t v) {                     \
        Value *val = value_new(VT_##n);                         \
        val->vu_##n = v;                                        \
        put_datapl(out, val->id);                               \
        put_byte(out, '\n');                                    \
    }
VALUE_TYPES(VALTYPE_RETURNFN)
#undef VALTYPE_RETURNFN

static ptrlen get_word(BinarySource *in)
{
    ptrlen toret;
    toret.ptr = get_ptr(in);
    toret.len = 0;
    while (get_avail(in) && get_byte(in) != ' ')
        toret.len++;
    return toret;
}

static const ssh_hashalg *get_hashalg(BinarySource *in)
{
    static const struct {
        const char *key;
        const ssh_hashalg *value;
    } algs[] = {
        {"md5", &ssh_md5},
        {"sha1", &ssh_sha1},
        {"sha1_sw", &ssh_sha1_sw},
        {"sha1_hw", &ssh_sha1_hw},
        {"sha256", &ssh_sha256},
        {"sha256_sw", &ssh_sha256_sw},
        {"sha256_hw", &ssh_sha256_hw},
        {"sha384", &ssh_sha384},
        {"sha384_sw", &ssh_sha384_sw},
        {"sha384_hw", &ssh_sha384_hw},
        {"sha512", &ssh_sha512},
        {"sha512_sw", &ssh_sha512_sw},
        {"sha512_hw", &ssh_sha512_hw},
        {"sha3_224", &ssh_sha3_224},
        {"sha3_256", &ssh_sha3_256},
        {"sha3_384", &ssh_sha3_384},
        {"sha3_512", &ssh_sha3_512},
        {"shake256_114bytes", &ssh_shake256_114bytes},
        {"blake2b", &ssh_blake2b},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value;

    fatal_error("hashalg '%.*s': not found", PTRLEN_PRINTF(name));
}

static const ssh2_macalg *get_macalg(BinarySource *in)
{
    static const struct {
        const char *key;
        const ssh2_macalg *value;
    } algs[] = {
        {"hmac_md5", &ssh_hmac_md5},
        {"hmac_sha1", &ssh_hmac_sha1},
        {"hmac_sha1_buggy", &ssh_hmac_sha1_buggy},
        {"hmac_sha1_96", &ssh_hmac_sha1_96},
        {"hmac_sha1_96_buggy", &ssh_hmac_sha1_96_buggy},
        {"hmac_sha256", &ssh_hmac_sha256},
        {"poly1305", &ssh2_poly1305},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value;

    fatal_error("macalg '%.*s': not found", PTRLEN_PRINTF(name));
}

static const ssh_keyalg *get_keyalg(BinarySource *in)
{
    static const struct {
        const char *key;
        const ssh_keyalg *value;
    } algs[] = {
        {"dsa", &ssh_dss},
        {"rsa", &ssh_rsa},
        {"ed25519", &ssh_ecdsa_ed25519},
        {"ed448", &ssh_ecdsa_ed448},
        {"p256", &ssh_ecdsa_nistp256},
        {"p384", &ssh_ecdsa_nistp384},
        {"p521", &ssh_ecdsa_nistp521},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value;

    fatal_error("keyalg '%.*s': not found", PTRLEN_PRINTF(name));
}

static const ssh_cipheralg *get_cipheralg(BinarySource *in)
{
    static const struct {
        const char *key;
        const ssh_cipheralg *value;
    } algs[] = {
        {"3des_ctr", &ssh_3des_ssh2_ctr},
        {"3des_ssh2", &ssh_3des_ssh2},
        {"3des_ssh1", &ssh_3des_ssh1},
        {"des_cbc", &ssh_des},
        {"aes256_ctr", &ssh_aes256_sdctr},
        {"aes256_ctr_hw", &ssh_aes256_sdctr_hw},
        {"aes256_ctr_sw", &ssh_aes256_sdctr_sw},
        {"aes256_cbc", &ssh_aes256_cbc},
        {"aes256_cbc_hw", &ssh_aes256_cbc_hw},
        {"aes256_cbc_sw", &ssh_aes256_cbc_sw},
        {"aes192_ctr", &ssh_aes192_sdctr},
        {"aes192_ctr_hw", &ssh_aes192_sdctr_hw},
        {"aes192_ctr_sw", &ssh_aes192_sdctr_sw},
        {"aes192_cbc", &ssh_aes192_cbc},
        {"aes192_cbc_hw", &ssh_aes192_cbc_hw},
        {"aes192_cbc_sw", &ssh_aes192_cbc_sw},
        {"aes128_ctr", &ssh_aes128_sdctr},
        {"aes128_ctr_hw", &ssh_aes128_sdctr_hw},
        {"aes128_ctr_sw", &ssh_aes128_sdctr_sw},
        {"aes128_cbc", &ssh_aes128_cbc},
        {"aes128_cbc_hw", &ssh_aes128_cbc_hw},
        {"aes128_cbc_sw", &ssh_aes128_cbc_sw},
        {"blowfish_ctr", &ssh_blowfish_ssh2_ctr},
        {"blowfish_ssh2", &ssh_blowfish_ssh2},
        {"blowfish_ssh1", &ssh_blowfish_ssh1},
        {"arcfour256", &ssh_arcfour256_ssh2},
        {"arcfour128", &ssh_arcfour128_ssh2},
        {"chacha20_poly1305", &ssh2_chacha20_poly1305},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value;

    fatal_error("cipheralg '%.*s': not found", PTRLEN_PRINTF(name));
}

static const ssh_kex *get_dh_group(BinarySource *in)
{
    static const struct {
        const char *key;
        const ssh_kexes *value;
    } algs[] = {
        {"group1", &ssh_diffiehellman_group1},
        {"group14", &ssh_diffiehellman_group14},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value->list[0];

    fatal_error("dh_group '%.*s': not found", PTRLEN_PRINTF(name));
}

static const ssh_kex *get_ecdh_alg(BinarySource *in)
{
    static const struct {
        const char *key;
        const ssh_kex *value;
    } algs[] = {
        {"curve25519", &ssh_ec_kex_curve25519},
        {"curve448", &ssh_ec_kex_curve448},
        {"nistp256", &ssh_ec_kex_nistp256},
        {"nistp384", &ssh_ec_kex_nistp384},
        {"nistp521", &ssh_ec_kex_nistp521},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value;

    fatal_error("ecdh_alg '%.*s': not found", PTRLEN_PRINTF(name));
}

static RsaSsh1Order get_rsaorder(BinarySource *in)
{
    static const struct {
        const char *key;
        RsaSsh1Order value;
    } orders[] = {
        {"exponent_first", RSA_SSH1_EXPONENT_FIRST},
        {"modulus_first", RSA_SSH1_MODULUS_FIRST},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(orders); i++)
        if (ptrlen_eq_string(name, orders[i].key))
            return orders[i].value;

    fatal_error("rsaorder '%.*s': not found", PTRLEN_PRINTF(name));
}

static const PrimeGenerationPolicy *get_primegenpolicy(BinarySource *in)
{
    static const struct {
        const char *key;
        const PrimeGenerationPolicy *value;
    } algs[] = {
        {"probabilistic", &primegen_probabilistic},
        {"provable_fast", &primegen_provable_fast},
        {"provable_maurer_simple", &primegen_provable_maurer_simple},
        {"provable_maurer_complex", &primegen_provable_maurer_complex},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value;

    fatal_error("primegenpolicy '%.*s': not found", PTRLEN_PRINTF(name));
}

static Argon2Flavour get_argon2flavour(BinarySource *in)
{
    static const struct {
        const char *key;
        Argon2Flavour value;
    } algs[] = {
        {"d", Argon2d},
        {"i", Argon2i},
        {"id", Argon2id},
        /* I expect to forget which spelling I chose, so let's support many */
        {"argon2d", Argon2d},
        {"argon2i", Argon2i},
        {"argon2id", Argon2id},
        {"Argon2d", Argon2d},
        {"Argon2i", Argon2i},
        {"Argon2id", Argon2id},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(algs); i++)
        if (ptrlen_eq_string(name, algs[i].key))
            return algs[i].value;

    fatal_error("Argon2 flavour '%.*s': not found", PTRLEN_PRINTF(name));
}

static FingerprintType get_fptype(BinarySource *in)
{
    static const struct {
        const char *key;
        FingerprintType value;
    } ids[] = {
        {"md5", SSH_FPTYPE_MD5},
        {"sha256", SSH_FPTYPE_SHA256},
    };

    ptrlen name = get_word(in);
    for (size_t i = 0; i < lenof(ids); i++)
        if (ptrlen_eq_string(name, ids[i].key))
            return ids[i].value;

    fatal_error("fingerprint type '%.*s': not found", PTRLEN_PRINTF(name));
}

static uintmax_t get_uint(BinarySource *in)
{
    ptrlen word = get_word(in);
    char *string = mkstr(word);
    uintmax_t toret = strtoumax(string, NULL, 0);
    sfree(string);
    return toret;
}

static bool get_boolean(BinarySource *in)
{
    return ptrlen_eq_string(get_word(in), "true");
}

static Value *lookup_value(ptrlen word)
{
    Value *val = find234(values, &word, valuefind);
    if (!val)
        fatal_error("id '%.*s': not found", PTRLEN_PRINTF(word));
    return val;
}

static Value *get_value(BinarySource *in)
{
    return lookup_value(get_word(in));
}

typedef void (*finaliser_fn_t)(strbuf *out, void *ctx);
struct finaliser {
    finaliser_fn_t fn;
    void *ctx;
};

static struct finaliser *finalisers;
static size_t nfinalisers, finalisersize;

static void add_finaliser(finaliser_fn_t fn, void *ctx)
{
    sgrowarray(finalisers, finalisersize, nfinalisers);
    finalisers[nfinalisers].fn = fn;
    finalisers[nfinalisers].ctx = ctx;
    nfinalisers++;
}

static void run_finalisers(strbuf *out)
{
    for (size_t i = 0; i < nfinalisers; i++)
        finalisers[i].fn(out, finalisers[i].ctx);
    nfinalisers = 0;
}

static void finaliser_return_value(strbuf *out, void *ctx)
{
    Value *val = (Value *)ctx;
    put_datapl(out, val->id);
    put_byte(out, '\n');
}

static void finaliser_sfree(strbuf *out, void *ctx)
{
    sfree(ctx);
}

#define VALTYPE_GETFN(n,t,f)                                            \
    static Value *unwrap_value_##n(Value *val) {                        \
        ValueType expected = VT_##n;                                    \
        if (expected != val->type)                                      \
            fatal_error("id '%.*s': expected %s, got %s",             \
                          PTRLEN_PRINTF(val->id),                       \
                          type_names[expected], type_names[val->type]); \
        return val;                                                     \
    }                                                                   \
    static Value *get_value_##n(BinarySource *in) {                     \
        return unwrap_value_##n(get_value(in));                         \
    }                                                                   \
    static t get_val_##n(BinarySource *in) {                            \
        return get_value_##n(in)->vu_##n;                               \
    }
VALUE_TYPES(VALTYPE_GETFN)
#undef VALTYPE_GETFN

static ptrlen get_val_string_ptrlen(BinarySource *in)
{
    return ptrlen_from_strbuf(get_val_string(in));
}

static char *get_val_string_asciz(BinarySource *in)
{
    return get_val_string(in)->s;
}

static strbuf *get_opt_val_string(BinarySource *in);

static char *get_opt_val_string_asciz(BinarySource *in)
{
    strbuf *sb = get_opt_val_string(in);
    return sb ? sb->s : NULL;
}

static mp_int **get_out_val_mpint(BinarySource *in)
{
    Value *val = value_new(VT_mpint);
    add_finaliser(finaliser_return_value, val);
    return &val->vu_mpint;
}

struct mpint_list {
    size_t n;
    mp_int **integers;
};

static struct mpint_list get_mpint_list(BinarySource *in)
{
    size_t n = get_uint(in);

    struct mpint_list mpl;
    mpl.n = n;

    mpl.integers = snewn(n, mp_int *);
    for (size_t i = 0; i < n; i++)
        mpl.integers[i] = get_val_mpint(in);

    add_finaliser(finaliser_sfree, mpl.integers);
    return mpl;
}

static void finaliser_return_uint(strbuf *out, void *ctx)
{
    unsigned *uval = (unsigned *)ctx;
    strbuf_catf(out, "%u\n", *uval);
    sfree(uval);
}

static unsigned *get_out_uint(BinarySource *in)
{
    unsigned *uval = snew(unsigned);
    add_finaliser(finaliser_return_uint, uval);
    return uval;
}

static BinarySink *get_out_val_string_binarysink(BinarySource *in)
{
    Value *val = value_new(VT_string);
    val->vu_string = strbuf_new();
    add_finaliser(finaliser_return_value, val);
    return BinarySink_UPCAST(val->vu_string);
}

static void return_val_string_asciz_const(strbuf *out, const char *s);
static void return_val_string_asciz(strbuf *out, char *s);

static void finaliser_return_opt_string_asciz(strbuf *out, void *ctx)
{
    char **valp = (char **)ctx;
    char *val = *valp;
    sfree(valp);
    if (!val)
        strbuf_catf(out, "NULL\n");
    else
        return_val_string_asciz(out, val);
}

static char **get_out_opt_val_string_asciz(BinarySource *in)
{
    char **valp = snew(char *);
    *valp = NULL;
    add_finaliser(finaliser_return_opt_string_asciz, valp);
    return valp;
}

static void finaliser_return_opt_string_asciz_const(strbuf *out, void *ctx)
{
    const char **valp = (const char **)ctx;
    const char *val = *valp;
    sfree(valp);
    if (!val)
        strbuf_catf(out, "NULL\n");
    else
        return_val_string_asciz_const(out, val);
}

static const char **get_out_opt_val_string_asciz_const(BinarySource *in)
{
    const char **valp = snew(const char *);
    *valp = NULL;
    add_finaliser(finaliser_return_opt_string_asciz_const, valp);
    return valp;
}

static BinarySource *get_val_string_binarysource(BinarySource *in)
{
    strbuf *sb = get_val_string(in);
    BinarySource *src = snew(BinarySource);
    BinarySource_BARE_INIT(src, sb->u, sb->len);
    add_finaliser(finaliser_sfree, src);
    return src;
}

#define GET_CONSUMED_FN(type)                                           \
    typedef TD_val_##type TD_consumed_val_##type;                       \
    static TD_val_##type get_consumed_val_##type(BinarySource *in)      \
    {                                                                   \
        Value *val = get_value_##type(in);                              \
        TD_val_##type toret = val->vu_##type;                           \
        del234(values, val);                                            \
        sfree(val);                                                     \
        return toret;                                                   \
    }
GET_CONSUMED_FN(hash)
GET_CONSUMED_FN(pcs)

static void return_int(strbuf *out, intmax_t u)
{
    strbuf_catf(out, "%"PRIdMAX"\n", u);
}

static void return_uint(strbuf *out, uintmax_t u)
{
    strbuf_catf(out, "0x%"PRIXMAX"\n", u);
}

static void return_boolean(strbuf *out, bool b)
{
    strbuf_catf(out, "%s\n", b ? "true" : "false");
}

static void return_pocklestatus(strbuf *out, PockleStatus status)
{
    switch (status) {
      default:
        strbuf_catf(out, "POCKLE_BAD_STATUS_VALUE\n");
        break;

#define STATUS_CASE(id)                         \
      case id:                                  \
        strbuf_catf(out, "%s\n", #id);          \
        break;

        POCKLE_STATUSES(STATUS_CASE);

#undef STATUS_CASE

    }
}

static void return_val_string_asciz_const(strbuf *out, const char *s)
{
    strbuf *sb = strbuf_new();
    put_data(sb, s, strlen(s));
    return_val_string(out, sb);
}

static void return_val_string_asciz(strbuf *out, char *s)
{
    return_val_string_asciz_const(out, s);
    sfree(s);
}

#define NULLABLE_RETURN_WRAPPER(type_name, c_type)                      \
    static void return_opt_##type_name(strbuf *out, c_type ptr)         \
    {                                                                   \
        if (!ptr)                                                       \
            strbuf_catf(out, "NULL\n");                                 \
        else                                                            \
            return_##type_name(out, ptr);                               \
    }

NULLABLE_RETURN_WRAPPER(val_string, strbuf *)
NULLABLE_RETURN_WRAPPER(val_string_asciz, char *)
NULLABLE_RETURN_WRAPPER(val_string_asciz_const, const char *)
NULLABLE_RETURN_WRAPPER(val_cipher, ssh_cipher *)
NULLABLE_RETURN_WRAPPER(val_hash, ssh_hash *)
NULLABLE_RETURN_WRAPPER(val_key, ssh_key *)
NULLABLE_RETURN_WRAPPER(val_mpint, mp_int *)

static void handle_hello(BinarySource *in, strbuf *out)
{
    strbuf_catf(out, "hello, world\n");
}

static void rsa_free(RSAKey *rsa)
{
    freersakey(rsa);
    sfree(rsa);
}

static void free_value(Value *val)
{
    switch (val->type) {
#define VALTYPE_FREE(n,t,f) case VT_##n: { t v = val->vu_##n; (f); break; }
        VALUE_TYPES(VALTYPE_FREE)
#undef VALTYPE_FREE
    }
    sfree(val);
}

static void handle_free(BinarySource *in, strbuf *out)
{
    Value *val = get_value(in);
    del234(values, val);
    free_value(val);
}

static void handle_newstring(BinarySource *in, strbuf *out)
{
    strbuf *sb = strbuf_new();
    while (get_avail(in)) {
        char c = get_byte(in);
        if (c == '%') {
            char hex[3];
            hex[0] = get_byte(in);
            if (hex[0] != '%') {
                hex[1] = get_byte(in);
                hex[2] = '\0';
                c = strtoul(hex, NULL, 16);
            }
        }
        put_byte(sb, c);
    }
    return_val_string(out, sb);
}

static void handle_getstring(BinarySource *in, strbuf *out)
{
    strbuf *sb = get_val_string(in);
    for (size_t i = 0; i < sb->len; i++) {
        char c = sb->s[i];
        if (c > ' ' && c < 0x7F && c != '%') {
            put_byte(out, c);
        } else {
            strbuf_catf(out, "%%%02X", 0xFFU & (unsigned)c);
        }
    }
    put_byte(out, '\n');
}

static void handle_mp_literal(BinarySource *in, strbuf *out)
{
    ptrlen pl = get_word(in);
    char *str = mkstr(pl);
    mp_int *mp = mp__from_string_literal(str);
    sfree(str);
    return_val_mpint(out, mp);
}

static void handle_mp_dump(BinarySource *in, strbuf *out)
{
    mp_int *mp = get_val_mpint(in);
    for (size_t i = mp_max_bytes(mp); i-- > 0 ;)
        strbuf_catf(out, "%02X", mp_get_byte(mp, i));
    put_byte(out, '\n');
}

static void random_queue(ptrlen pl)
{
    bufchain_add(&random_data_queue, pl.ptr, pl.len);
}

static size_t random_queue_len(void)
{
    return bufchain_size(&random_data_queue);
}

static void random_clear(void)
{
    if (test_prng) {
        prng_free(test_prng);
        test_prng = NULL;
    }

    bufchain_clear(&random_data_queue);
}

static void random_make_prng(const ssh_hashalg *hashalg, ptrlen seed)
{
    random_clear();

    test_prng = prng_new(hashalg);
    prng_seed_begin(test_prng);
    put_datapl(test_prng, seed);
    prng_seed_finish(test_prng);
}

mp_int *monty_identity_wrapper(MontyContext *mc)
{
    return mp_copy(monty_identity(mc));
}
#define monty_identity monty_identity_wrapper

mp_int *monty_modulus_wrapper(MontyContext *mc)
{
    return mp_copy(monty_modulus(mc));
}
#define monty_modulus monty_modulus_wrapper

strbuf *ssh_hash_digest_wrapper(ssh_hash *h)
{
    strbuf *sb = strbuf_new();
    void *p = strbuf_append(sb, ssh_hash_alg(h)->hlen);
    ssh_hash_digest(h, p);
    return sb;
}
#undef ssh_hash_digest
#define ssh_hash_digest ssh_hash_digest_wrapper

strbuf *ssh_hash_final_wrapper(ssh_hash *h)
{
    strbuf *sb = strbuf_new();
    void *p = strbuf_append(sb, ssh_hash_alg(h)->hlen);
    ssh_hash_final(h, p);
    return sb;
}
#undef ssh_hash_final
#define ssh_hash_final ssh_hash_final_wrapper

void ssh_cipher_setiv_wrapper(ssh_cipher *c, ptrlen key)
{
    if (key.len != ssh_cipher_alg(c)->blksize)
        fatal_error("ssh_cipher_setiv: needs exactly %d bytes",
                    ssh_cipher_alg(c)->blksize);
    ssh_cipher_setiv(c, key.ptr);
}
#undef ssh_cipher_setiv
#define ssh_cipher_setiv ssh_cipher_setiv_wrapper

void ssh_cipher_setkey_wrapper(ssh_cipher *c, ptrlen key)
{
    if (key.len != ssh_cipher_alg(c)->padded_keybytes)
        fatal_error("ssh_cipher_setkey: needs exactly %d bytes",
                    ssh_cipher_alg(c)->padded_keybytes);
    ssh_cipher_setkey(c, key.ptr);
}
#undef ssh_cipher_setkey
#define ssh_cipher_setkey ssh_cipher_setkey_wrapper

strbuf *ssh_cipher_encrypt_wrapper(ssh_cipher *c, ptrlen input)
{
    if (input.len % ssh_cipher_alg(c)->blksize)
        fatal_error("ssh_cipher_encrypt: needs a multiple of %d bytes",
                    ssh_cipher_alg(c)->blksize);
    strbuf *sb = strbuf_new();
    put_datapl(sb, input);
    ssh_cipher_encrypt(c, sb->u, sb->len);
    return sb;
}
#undef ssh_cipher_encrypt
#define ssh_cipher_encrypt ssh_cipher_encrypt_wrapper

strbuf *ssh_cipher_decrypt_wrapper(ssh_cipher *c, ptrlen input)
{
    if (input.len % ssh_cipher_alg(c)->blksize)
        fatal_error("ssh_cipher_decrypt: needs a multiple of %d bytes",
                    ssh_cipher_alg(c)->blksize);
    strbuf *sb = strbuf_new();
    put_datapl(sb, input);
    ssh_cipher_decrypt(c, sb->u, sb->len);
    return sb;
}
#undef ssh_cipher_decrypt
#define ssh_cipher_decrypt ssh_cipher_decrypt_wrapper

strbuf *ssh_cipher_encrypt_length_wrapper(ssh_cipher *c, ptrlen input,
                                           unsigned long seq)
{
    if (input.len != 4)
        fatal_error("ssh_cipher_encrypt_length: needs exactly 4 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, input);
    ssh_cipher_encrypt_length(c, sb->u, sb->len, seq);
    return sb;
}
#undef ssh_cipher_encrypt_length
#define ssh_cipher_encrypt_length ssh_cipher_encrypt_length_wrapper

strbuf *ssh_cipher_decrypt_length_wrapper(ssh_cipher *c, ptrlen input,
                                           unsigned long seq)
{
    if (input.len % ssh_cipher_alg(c)->blksize)
        fatal_error("ssh_cipher_decrypt_length: needs exactly 4 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, input);
    ssh_cipher_decrypt_length(c, sb->u, sb->len, seq);
    return sb;
}
#undef ssh_cipher_decrypt_length
#define ssh_cipher_decrypt_length ssh_cipher_decrypt_length_wrapper

strbuf *ssh2_mac_genresult_wrapper(ssh2_mac *m)
{
    strbuf *sb = strbuf_new();
    void *u = strbuf_append(sb, ssh2_mac_alg(m)->len);
    ssh2_mac_genresult(m, u);
    return sb;
}
#undef ssh2_mac_genresult
#define ssh2_mac_genresult ssh2_mac_genresult_wrapper

bool dh_validate_f_wrapper(dh_ctx *dh, mp_int *f)
{
    return dh_validate_f(dh, f) == NULL;
}
#define dh_validate_f dh_validate_f_wrapper

void ssh_hash_update(ssh_hash *h, ptrlen pl)
{
    put_datapl(h, pl);
}

void ssh2_mac_update(ssh2_mac *m, ptrlen pl)
{
    put_datapl(m, pl);
}

static RSAKey *rsa_new(void)
{
    RSAKey *rsa = snew(RSAKey);
    memset(rsa, 0, sizeof(RSAKey));
    return rsa;
}

strbuf *rsa_ssh1_encrypt_wrapper(ptrlen input, RSAKey *key)
{
    /* Fold the boolean return value in C into the string return value
     * for this purpose, by returning NULL on failure */
    strbuf *sb = strbuf_new();
    put_datapl(sb, input);
    put_padding(sb, key->bytes - input.len, 0);
    if (!rsa_ssh1_encrypt(sb->u, input.len, key)) {
        strbuf_free(sb);
        return NULL;
    }
    return sb;
}
#define rsa_ssh1_encrypt rsa_ssh1_encrypt_wrapper

strbuf *rsa_ssh1_decrypt_pkcs1_wrapper(mp_int *input, RSAKey *key)
{
    /* Again, return "" on failure */
    strbuf *sb = strbuf_new();
    if (!rsa_ssh1_decrypt_pkcs1(input, key, sb))
        strbuf_clear(sb);
    return sb;
}
#define rsa_ssh1_decrypt_pkcs1 rsa_ssh1_decrypt_pkcs1_wrapper

strbuf *des_encrypt_xdmauth_wrapper(ptrlen key, ptrlen data)
{
    if (key.len != 7)
        fatal_error("des_encrypt_xdmauth: key must be 7 bytes long");
    if (data.len % 8 != 0)
        fatal_error("des_encrypt_xdmauth: data must be a multiple of 8 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    des_encrypt_xdmauth(key.ptr, sb->u, sb->len);
    return sb;
}
#define des_encrypt_xdmauth des_encrypt_xdmauth_wrapper

strbuf *des_decrypt_xdmauth_wrapper(ptrlen key, ptrlen data)
{
    if (key.len != 7)
        fatal_error("des_decrypt_xdmauth: key must be 7 bytes long");
    if (data.len % 8 != 0)
        fatal_error("des_decrypt_xdmauth: data must be a multiple of 8 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    des_decrypt_xdmauth(key.ptr, sb->u, sb->len);
    return sb;
}
#define des_decrypt_xdmauth des_decrypt_xdmauth_wrapper

strbuf *des3_encrypt_pubkey_wrapper(ptrlen key, ptrlen data)
{
    if (key.len != 16)
        fatal_error("des3_encrypt_pubkey: key must be 16 bytes long");
    if (data.len % 8 != 0)
        fatal_error("des3_encrypt_pubkey: data must be a multiple of 8 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    des3_encrypt_pubkey(key.ptr, sb->u, sb->len);
    return sb;
}
#define des3_encrypt_pubkey des3_encrypt_pubkey_wrapper

strbuf *des3_decrypt_pubkey_wrapper(ptrlen key, ptrlen data)
{
    if (key.len != 16)
        fatal_error("des3_decrypt_pubkey: key must be 16 bytes long");
    if (data.len % 8 != 0)
        fatal_error("des3_decrypt_pubkey: data must be a multiple of 8 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    des3_decrypt_pubkey(key.ptr, sb->u, sb->len);
    return sb;
}
#define des3_decrypt_pubkey des3_decrypt_pubkey_wrapper

strbuf *des3_encrypt_pubkey_ossh_wrapper(ptrlen key, ptrlen iv, ptrlen data)
{
    if (key.len != 24)
        fatal_error("des3_encrypt_pubkey_ossh: key must be 24 bytes long");
    if (iv.len != 8)
        fatal_error("des3_encrypt_pubkey_ossh: iv must be 8 bytes long");
    if (data.len % 8 != 0)
        fatal_error("des3_encrypt_pubkey_ossh: data must be a multiple of 8 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    des3_encrypt_pubkey_ossh(key.ptr, iv.ptr, sb->u, sb->len);
    return sb;
}
#define des3_encrypt_pubkey_ossh des3_encrypt_pubkey_ossh_wrapper

strbuf *des3_decrypt_pubkey_ossh_wrapper(ptrlen key, ptrlen iv, ptrlen data)
{
    if (key.len != 24)
        fatal_error("des3_decrypt_pubkey_ossh: key must be 24 bytes long");
    if (iv.len != 8)
        fatal_error("des3_encrypt_pubkey_ossh: iv must be 8 bytes long");
    if (data.len % 8 != 0)
        fatal_error("des3_decrypt_pubkey_ossh: data must be a multiple of 8 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    des3_decrypt_pubkey_ossh(key.ptr, iv.ptr, sb->u, sb->len);
    return sb;
}
#define des3_decrypt_pubkey_ossh des3_decrypt_pubkey_ossh_wrapper

strbuf *aes256_encrypt_pubkey_wrapper(ptrlen key, ptrlen iv, ptrlen data)
{
    if (key.len != 32)
        fatal_error("aes256_encrypt_pubkey: key must be 32 bytes long");
    if (iv.len != 16)
        fatal_error("aes256_encrypt_pubkey: iv must be 16 bytes long");
    if (data.len % 16 != 0)
        fatal_error("aes256_encrypt_pubkey: data must be a multiple of 16 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    aes256_encrypt_pubkey(key.ptr, iv.ptr, sb->u, sb->len);
    return sb;
}
#define aes256_encrypt_pubkey aes256_encrypt_pubkey_wrapper

strbuf *aes256_decrypt_pubkey_wrapper(ptrlen key, ptrlen iv, ptrlen data)
{
    if (key.len != 32)
        fatal_error("aes256_decrypt_pubkey: key must be 32 bytes long");
    if (iv.len != 16)
        fatal_error("aes256_encrypt_pubkey: iv must be 16 bytes long");
    if (data.len % 16 != 0)
        fatal_error("aes256_decrypt_pubkey: data must be a multiple of 16 bytes");
    strbuf *sb = strbuf_new();
    put_datapl(sb, data);
    aes256_decrypt_pubkey(key.ptr, iv.ptr, sb->u, sb->len);
    return sb;
}
#define aes256_decrypt_pubkey aes256_decrypt_pubkey_wrapper

strbuf *prng_read_wrapper(prng *pr, size_t size)
{
    strbuf *sb = strbuf_new();
    prng_read(pr, strbuf_append(sb, size), size);
    return sb;
}
#define prng_read prng_read_wrapper

void prng_seed_update(prng *pr, ptrlen data)
{
    put_datapl(pr, data);
}

bool crcda_detect(ptrlen packet, ptrlen iv)
{
    if (iv.len != 0 && iv.len != 8)
        fatal_error("crcda_detect: iv must be empty or 8 bytes long");
    if (packet.len % 8 != 0)
        fatal_error("crcda_detect: packet must be a multiple of 8 bytes");
    struct crcda_ctx *ctx = crcda_make_context();
    bool toret = detect_attack(ctx, packet.ptr, packet.len,
                               iv.len ? iv.ptr : NULL);
    crcda_free_context(ctx);
    return toret;
}

ssh_key *ppk_load_s_wrapper(BinarySource *src, char **comment,
                            const char *passphrase, const char **errorstr)
{
    ssh2_userkey *uk = ppk_load_s(src, passphrase, errorstr);
    if (uk == SSH2_WRONG_PASSPHRASE) {
        /* Fudge this special return value */
        *errorstr = "SSH2_WRONG_PASSPHRASE";
        return NULL;
    }
    if (uk == NULL)
        return NULL;
    ssh_key *toret = uk->key;
    *comment = uk->comment;
    sfree(uk);
    return toret;
}
#define ppk_load_s ppk_load_s_wrapper

int rsa1_load_s_wrapper(BinarySource *src, RSAKey *rsa, char **comment,
                        const char *passphrase, const char **errorstr)
{
    int toret = rsa1_load_s(src, rsa, passphrase, errorstr);
    *comment = rsa->comment;
    rsa->comment = NULL;
    return toret;
}
#define rsa1_load_s rsa1_load_s_wrapper

strbuf *ppk_save_sb_wrapper(
    ssh_key *key, const char *comment, const char *passphrase,
    unsigned fmt_version, Argon2Flavour flavour,
    uint32_t mem, uint32_t passes, uint32_t parallel)
{
    /*
     * For repeatable testing purposes, we never want a timing-dependent
     * choice of password hashing parameters, so this is easy.
     */
    ppk_save_parameters save_params;
    memset(&save_params, 0, sizeof(save_params));
    save_params.fmt_version = fmt_version;
    save_params.argon2_flavour = flavour;
    save_params.argon2_mem = mem;
    save_params.argon2_passes_auto = false;
    save_params.argon2_passes = passes;
    save_params.argon2_parallelism = parallel;

    ssh2_userkey uk;
    uk.key = key;
    uk.comment = dupstr(comment);
    strbuf *toret = ppk_save_sb(&uk, passphrase, &save_params);
    sfree(uk.comment);
    return toret;
}
#define ppk_save_sb ppk_save_sb_wrapper

strbuf *rsa1_save_sb_wrapper(RSAKey *key, const char *comment,
                             const char *passphrase)
{
    key->comment = dupstr(comment);
    strbuf *toret = rsa1_save_sb(key, passphrase);
    sfree(key->comment);
    key->comment = NULL;
    return toret;
}
#define rsa1_save_sb rsa1_save_sb_wrapper

#define return_void(out, expression) (expression)

static ProgressReceiver null_progress = { .vt = &null_progress_vt };

mp_int *primegen_generate_wrapper(
    PrimeGenerationContext *ctx, PrimeCandidateSource *pcs)
{
    return primegen_generate(ctx, pcs, &null_progress);
}
#define primegen_generate primegen_generate_wrapper

RSAKey *rsa1_generate(int bits, bool strong, PrimeGenerationContext *pgc)
{
    RSAKey *rsakey = snew(RSAKey);
    rsa_generate(rsakey, bits, strong, pgc, &null_progress);
    rsakey->comment = NULL;
    return rsakey;
}

ssh_key *rsa_generate_wrapper(int bits, bool strong,
                              PrimeGenerationContext *pgc)
{
    return &rsa1_generate(bits, strong, pgc)->sshk;
}
#define rsa_generate rsa_generate_wrapper

ssh_key *dsa_generate_wrapper(int bits, PrimeGenerationContext *pgc)
{
    struct dss_key *dsskey = snew(struct dss_key);
    dsa_generate(dsskey, bits, pgc, &null_progress);
    return &dsskey->sshk;
}
#define dsa_generate dsa_generate_wrapper

ssh_key *ecdsa_generate_wrapper(int bits)
{
    struct ecdsa_key *ek = snew(struct ecdsa_key);
    if (!ecdsa_generate(ek, bits)) {
        sfree(ek);
        return NULL;
    }
    return &ek->sshk;
}
#define ecdsa_generate ecdsa_generate_wrapper

ssh_key *eddsa_generate_wrapper(int bits)
{
    struct eddsa_key *ek = snew(struct eddsa_key);
    if (!eddsa_generate(ek, bits)) {
        sfree(ek);
        return NULL;
    }
    return &ek->sshk;
}
#define eddsa_generate eddsa_generate_wrapper

size_t key_components_count(key_components *kc) { return kc->ncomponents; }
const char *key_components_nth_name(key_components *kc, size_t n)
{
    return (n >= kc->ncomponents ? NULL :
            kc->components[n].name);
}
const char *key_components_nth_str(key_components *kc, size_t n)
{
    return (n >= kc->ncomponents ? NULL :
            kc->components[n].is_mp_int ? NULL :
            kc->components[n].text);
}
mp_int *key_components_nth_mp(key_components *kc, size_t n)
{
    return (n >= kc->ncomponents ? NULL :
            !kc->components[n].is_mp_int ? NULL :
            mp_copy(kc->components[n].mp));
}

PockleStatus pockle_add_prime_wrapper(Pockle *pockle, mp_int *p,
                                      struct mpint_list mpl, mp_int *witness)
{
    return pockle_add_prime(pockle, p, mpl.integers, mpl.n, witness);
}
#define pockle_add_prime pockle_add_prime_wrapper

strbuf *argon2_wrapper(Argon2Flavour flavour, uint32_t mem, uint32_t passes,
                       uint32_t parallel, uint32_t taglen,
                       ptrlen P, ptrlen S, ptrlen K, ptrlen X)
{
    strbuf *out = strbuf_new();
    argon2(flavour, mem, passes, parallel, taglen, P, S, K, X, out);
    return out;
}
#define argon2 argon2_wrapper

#define OPTIONAL_PTR_FUNC(type)                                         \
    typedef TD_val_##type TD_opt_val_##type;                            \
    static TD_opt_val_##type get_opt_val_##type(BinarySource *in) {     \
        ptrlen word = get_word(in);                                     \
        if (ptrlen_eq_string(word, "NULL"))                             \
            return NULL;                                                \
        return unwrap_value_##type(lookup_value(word))->vu_##type;      \
    }
OPTIONAL_PTR_FUNC(cipher)
OPTIONAL_PTR_FUNC(mpint)
OPTIONAL_PTR_FUNC(string)

typedef uintmax_t TD_uint;
typedef bool TD_boolean;
typedef ptrlen TD_val_string_ptrlen;
typedef char *TD_val_string_asciz;
typedef BinarySource *TD_val_string_binarysource;
typedef unsigned *TD_out_uint;
typedef BinarySink *TD_out_val_string_binarysink;
typedef const char *TD_opt_val_string_asciz;
typedef char **TD_out_val_string_asciz;
typedef char **TD_out_opt_val_string_asciz;
typedef const char **TD_out_opt_val_string_asciz_const;
typedef ssh_hash *TD_consumed_val_hash;
typedef const ssh_hashalg *TD_hashalg;
typedef const ssh2_macalg *TD_macalg;
typedef const ssh_keyalg *TD_keyalg;
typedef const ssh_cipheralg *TD_cipheralg;
typedef const ssh_kex *TD_dh_group;
typedef const ssh_kex *TD_ecdh_alg;
typedef RsaSsh1Order TD_rsaorder;
typedef key_components *TD_keycomponents;
typedef const PrimeGenerationPolicy *TD_primegenpolicy;
typedef struct mpint_list TD_mpint_list;
typedef PockleStatus TD_pocklestatus;
typedef Argon2Flavour TD_argon2flavour;
typedef FingerprintType TD_fptype;

#define FUNC0(rettype, function)                                        \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        return_##rettype(out, function());                              \
    }

#define FUNC1(rettype, function, type1)                                 \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        return_##rettype(out, function(arg1));                          \
    }

#define FUNC2(rettype, function, type1, type2)                          \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        return_##rettype(out, function(arg1, arg2));                    \
    }

#define FUNC3(rettype, function, type1, type2, type3)                   \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        TD_##type3 arg3 = get_##type3(in);                              \
        return_##rettype(out, function(arg1, arg2, arg3));              \
    }

#define FUNC4(rettype, function, type1, type2, type3, type4)            \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        TD_##type3 arg3 = get_##type3(in);                              \
        TD_##type4 arg4 = get_##type4(in);                              \
        return_##rettype(out, function(arg1, arg2, arg3, arg4));        \
    }

#define FUNC5(rettype, function, type1, type2, type3, type4, type5)     \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        TD_##type3 arg3 = get_##type3(in);                              \
        TD_##type4 arg4 = get_##type4(in);                              \
        TD_##type5 arg5 = get_##type5(in);                              \
        return_##rettype(out, function(arg1, arg2, arg3, arg4, arg5));  \
    }

#define FUNC6(rettype, function, type1, type2, type3, type4, type5,     \
              type6)                                                    \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        TD_##type3 arg3 = get_##type3(in);                              \
        TD_##type4 arg4 = get_##type4(in);                              \
        TD_##type5 arg5 = get_##type5(in);                              \
        TD_##type6 arg6 = get_##type6(in);                              \
        return_##rettype(out, function(arg1, arg2, arg3, arg4, arg5,    \
                                       arg6));                          \
    }

#define FUNC7(rettype, function, type1, type2, type3, type4, type5,     \
              type6, type7)                                             \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        TD_##type3 arg3 = get_##type3(in);                              \
        TD_##type4 arg4 = get_##type4(in);                              \
        TD_##type5 arg5 = get_##type5(in);                              \
        TD_##type6 arg6 = get_##type6(in);                              \
        TD_##type7 arg7 = get_##type7(in);                              \
        return_##rettype(out, function(arg1, arg2, arg3, arg4, arg5,    \
                                       arg6, arg7));                    \
    }

#define FUNC8(rettype, function, type1, type2, type3, type4, type5,     \
              type6, type7, type8)                                      \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        TD_##type3 arg3 = get_##type3(in);                              \
        TD_##type4 arg4 = get_##type4(in);                              \
        TD_##type5 arg5 = get_##type5(in);                              \
        TD_##type6 arg6 = get_##type6(in);                              \
        TD_##type7 arg7 = get_##type7(in);                              \
        TD_##type8 arg8 = get_##type8(in);                              \
        return_##rettype(out, function(arg1, arg2, arg3, arg4, arg5,    \
                                       arg6, arg7, arg8));              \
    }

#define FUNC9(rettype, function, type1, type2, type3, type4, type5,     \
              type6, type7, type8, type9)                               \
    static void handle_##function(BinarySource *in, strbuf *out) {      \
        TD_##type1 arg1 = get_##type1(in);                              \
        TD_##type2 arg2 = get_##type2(in);                              \
        TD_##type3 arg3 = get_##type3(in);                              \
        TD_##type4 arg4 = get_##type4(in);                              \
        TD_##type5 arg5 = get_##type5(in);                              \
        TD_##type6 arg6 = get_##type6(in);                              \
        TD_##type7 arg7 = get_##type7(in);                              \
        TD_##type8 arg8 = get_##type8(in);                              \
        TD_##type9 arg9 = get_##type9(in);                              \
        return_##rettype(out, function(arg1, arg2, arg3, arg4, arg5,    \
                                       arg6, arg7, arg8, arg9));        \
    }

#include "testcrypt.h"

#undef FUNC9
#undef FUNC8
#undef FUNC7
#undef FUNC6
#undef FUNC5
#undef FUNC4
#undef FUNC3
#undef FUNC2
#undef FUNC1
#undef FUNC0

static void process_line(BinarySource *in, strbuf *out)
{
    ptrlen id = get_word(in);

#define DISPATCH_INTERNAL(cmdname, handler) do {        \
        if (ptrlen_eq_string(id, cmdname)) {            \
            handler(in, out);                           \
            return;                                     \
        }                                               \
    } while (0)

#define DISPATCH_COMMAND(cmd) DISPATCH_INTERNAL(#cmd, handle_##cmd)
    DISPATCH_COMMAND(hello);
    DISPATCH_COMMAND(free);
    DISPATCH_COMMAND(newstring);
    DISPATCH_COMMAND(getstring);
    DISPATCH_COMMAND(mp_literal);
    DISPATCH_COMMAND(mp_dump);
#undef DISPATCH_COMMAND

#define FUNC0(ret,fn)                   DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC1(ret,fn,x)                 DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC2(ret,fn,x,y)               DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC3(ret,fn,x,y,z)             DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC4(ret,fn,x,y,z,v)           DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC5(ret,fn,x,y,z,v,w)         DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC6(ret,fn,x,y,z,v,w,u)       DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC7(ret,fn,x,y,z,v,w,u,t)     DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC8(ret,fn,x,y,z,v,w,u,t,s)   DISPATCH_INTERNAL(#fn,handle_##fn);
#define FUNC9(ret,fn,x,y,z,v,w,u,t,s,r) DISPATCH_INTERNAL(#fn,handle_##fn);

#include "testcrypt.h"

#undef FUNC9
#undef FUNC8
#undef FUNC7
#undef FUNC6
#undef FUNC5
#undef FUNC4
#undef FUNC3
#undef FUNC2
#undef FUNC1
#undef FUNC0

#undef DISPATCH_INTERNAL

    fatal_error("command '%.*s': unrecognised", PTRLEN_PRINTF(id));
}

static void free_all_values(void)
{
    for (Value *val; (val = delpos234(values, 0)) != NULL ;)
        free_value(val);
    freetree234(values);
}

void dputs(const char *buf)
{
    fputs(buf, stderr);
}

int main(int argc, char **argv)
{
    const char *infile = NULL, *outfile = NULL;
    bool doing_opts = true;

    while (--argc > 0) {
        char *p = *++argv;

        if (p[0] == '-' && doing_opts) {
            if (!strcmp(p, "-o")) {
                if (--argc <= 0) {
                    fprintf(stderr, "'-o' expects a filename\n");
                    return 1;
                }
                outfile = *++argv;
            } else if (!strcmp(p, "--")) {
                doing_opts = false;
            } else if (!strcmp(p, "--help")) {
                printf("usage: testcrypt [INFILE] [-o OUTFILE]\n");
                printf(" also: testcrypt --help       display this text\n");
                return 0;
            } else {
                fprintf(stderr, "unknown command line option '%s'\n", p);
                return 1;
            }
        } else if (!infile) {
            infile = p;
        } else {
            fprintf(stderr, "can only handle one input file name\n");
            return 1;
        }
    }

    FILE *infp = stdin;
    if (infile) {
        infp = fopen(infile, "r");
        if (!infp) {
            fprintf(stderr, "%s: open: %s\n", infile, strerror(errno));
            return 1;
        }
    }

    FILE *outfp = stdout;
    if (outfile) {
        outfp = fopen(outfile, "w");
        if (!outfp) {
            fprintf(stderr, "%s: open: %s\n", outfile, strerror(errno));
            return 1;
        }
    }

    values = newtree234(valuecmp);

    atexit(free_all_values);

    for (char *line; (line = chomp(fgetline(infp))) != NULL ;) {
        BinarySource src[1];
        BinarySource_BARE_INIT(src, line, strlen(line));
        strbuf *sb = strbuf_new();
        process_line(src, sb);
        run_finalisers(sb);
        size_t lines = 0;
        for (size_t i = 0; i < sb->len; i++)
            if (sb->s[i] == '\n')
                lines++;
        fprintf(outfp, "%"SIZEu"\n%s", lines, sb->s);
        fflush(outfp);
        strbuf_free(sb);
        sfree(line);
    }

    if (infp != stdin)
        fclose(infp);
    if (outfp != stdin)
        fclose(outfp);

    return 0;
}
