/*
 * A simple deterministic PRNG, without any of the Fortuna
 * complexities, for use in test programs. Generates test inputs in a
 * way that's repeatable between runs of the program.
 *
 * Even if only a subset of test cases is run.
 */

#include "putty.h"
#include "ssh.h"
#include "test.h"

static uint64_t random_counter = 0;
static const char *random_seedstr = NULL;
static uint8_t random_buf[MAX_HASH_LEN];
static size_t random_buf_limit = 0;
static ssh_hash *random_hash;

void testrandom_init(void)
{
    random_hash = ssh_hash_new(&ssh_sha256);
}

void testrandom_cleanup(void)
{
    ssh_hash_free(random_hash);
    random_hash = NULL;
}

void testrandom_seed(const char *seedstr)
{
    random_seedstr = seedstr;
    random_counter = 0;
    random_buf_limit = 0;
}

void testrandom_advance_counter(void)
{
    ssh_hash_reset(random_hash);
    put_asciz(random_hash, random_seedstr);
    put_uint64(random_hash, random_counter);
    random_counter++;
    random_buf_limit = ssh_hash_alg(random_hash)->hlen;
    ssh_hash_digest(random_hash, random_buf);
}

struct testrandom_state testrandom_get_state(void)
{
    struct testrandom_state st;
    st.seedstr = random_seedstr;
    st.counter = random_counter;
    st.limit = random_buf_limit;
    memcpy(st.buf, random_buf, sizeof(st.buf));
    return st;
}

void testrandom_set_state(struct testrandom_state st)
{
    random_seedstr = st.seedstr;
    random_counter = st.counter;
    random_buf_limit = st.limit;
    memcpy(random_buf, st.buf, sizeof(random_buf));
}

int random_active = 0;
void random_ref(void) { random_active++; }
void random_unref(void) { random_active--; }

void random_add_noise(NoiseSourceId source, const void *noise, int length) {}
void random_setup_custom(const ssh_hashalg *hash) {}
void random_get_savedata(void **data, int *len) {
    assert(false && "random_get_savedata can't do anything");
}

void random_save_seed(void) {}
void random_clear(void) {}
void random_reseed(ptrlen seed) {}
size_t random_seed_bits(void) { return 64; }

void random_read(void *vbuf, size_t size)
{
    assert(random_seedstr);
    uint8_t *buf = (uint8_t *)vbuf;
    while (size-- > 0) {
        if (random_buf_limit == 0)
            testrandom_advance_counter();
        *buf++ = random_buf[random_buf_limit--];
    }
}

