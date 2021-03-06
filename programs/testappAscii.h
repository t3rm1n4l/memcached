#define PROTOCOL_CMD_STAT "stats"
#define PROTOCOL_CMD_APPEND "append"
#define PROTOCOL_CMD_PREPEND "prepend"
#define PROTOCOL_CMD_ADD "add"
#define PROTOCOL_CMD_FLUSH "flush_all"
#define PROTOCOL_CMD_QUIT "quit"
#define PROTOCOL_CMD_REPLACE "replace"
#define PROTOCOL_CMD_INCREMENT "incr"
#define PROTOCOL_CMD_VERSION "version"
#define PROTOCOL_CMD_CAS "cas"
#define PROTOCOL_CMD_GET "get"
#define PROTOCOL_CMD_SET "set"
#define PROTOCOL_CMD_DELETE "delete"
#define PROTOCOL_CMD_DECREMENT "decr"
#define PROTOCOL_CMD_VERBOSITY "verbosity"
#define PROTOCOL_CMD_GETS "gets"


#define PROTOCOL_CMD_STAT_CODE 1
#define PROTOCOL_CMD_APPEND_CODE 2
#define PROTOCOL_CMD_PREPEND_CODE 3
#define PROTOCOL_CMD_ADD_CODE 4
#define PROTOCOL_CMD_FLUSH_CODE 5
#define PROTOCOL_CMD_QUIT_CODE 6
#define PROTOCOL_CMD_REPLACE_CODE 7
#define PROTOCOL_CMD_INCREMENT_CODE 8
#define PROTOCOL_CMD_VERSION_CODE 9
#define PROTOCOL_CMD_CAS_CODE 10
#define PROTOCOL_CMD_GET_CODE 11
#define PROTOCOL_CMD_SET_CODE 12
#define PROTOCOL_CMD_DELETE_CODE	13
#define PROTOCOL_CMD_DECREMENT_CODE	14
#define PROTOCOL_CMD_VERBOSITY_CODE 15



enum {
    PROTOCOL_RESPONSE_SUCCESS=1,
    PROTOCOL_RESPONSE_KEY_EEXISTS,
    PROTOCOL_RESPONSE_KEY_ENOENT,
    PROTOCOL_RESPONSE_NOT_STORED,
    PROTOCOL_RESPONSE_KEY_ENOSTORED,
}response_from_memcache;

