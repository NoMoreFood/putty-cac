/*
 * Declarations for functions only used by test programs.
 */

struct testrandom_state {
    const char *seedstr;
    uint64_t counter;
    size_t limit;
    uint8_t buf[MAX_HASH_LEN];
};

void testrandom_init(void);
void testrandom_cleanup(void);
void testrandom_seed(const char *seedstr);
void testrandom_advance_counter(void);
struct testrandom_state testrandom_get_state(void);
void testrandom_set_state(struct testrandom_state st);
