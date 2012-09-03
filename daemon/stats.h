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
    uint64_t nw_start_time; // the time when the network read/write started
    uint64_t nw_bytes;      // how many bytes read/written since nw_start_time (maintains the running count)
    uint64_t nw_read_time;    // How much time was taken
    uint64_t nw_read_bytes;   // to read how many bytes
    uint64_t nw_write_time;   // How much time was taken
    uint64_t nw_write_bytes;  // to write how many bytes
    char *cmd_str;                  // A human readable representation of the command (get, set etc)
    short num_keys;      // number of keys in the command, applicable only for get with multiple keys
    bool monitor_nw_time;   // set to true to indicate that we are interested in monotoring nw time
    char extension_str[20]; // if this is an extensionm command, this will be set instead of cmd_str
}memcache_stats_t;
