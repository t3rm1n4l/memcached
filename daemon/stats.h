/* stats */
void stats_prefix_init(void);
void stats_prefix_clear(void);
void stats_prefix_record_get(const char *key, const size_t nkey, const bool is_hit);
void stats_prefix_record_delete(const char *key, const size_t nkey);
void stats_prefix_record_set(const char *key, const size_t nkey);
/*@null@*/
char *stats_prefix_dump(int *length);

#define MAX_MEMCACHED_STATS     5

#define MIN_NW_BYTES     100

#define NW_READ_STAT    1
#define NW_WRITE_STAT   2


typedef struct _memcache_stats_t {

    uint64_t op_start_time; // The time at which the current operation (get/set/delete) was started
    char *cmd_str;                  // A human readable representation of the command (get, set etc)
    short num_keys;      // number of keys in the command, applicable only for get with multiple keys
    char extension_str[20]; // if this is an extensionm command, this will be set instead of cmd_str
}memcache_stats_t;
