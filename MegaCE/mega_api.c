#include <string.h>
#include <stdio.h>
#include <windows.h>
#include "mega_api.h"
#include "mega_crypto.h"
#include "mega_hashcash.h"

#define MEGA_API_HOST "g.api.mega.co.nz"
#define MEGA_API_PORT 443
#define MEGA_MAX_NODE_NAME 96
#define MEGA_UPLOAD_CHUNK_BASE 131072UL
#define MEGA_UPLOAD_CHUNK_MAX 1048576UL
#define MEGA_UPLOAD_CRC_SIZE 12
#define MEGA_FINGERPRINT_MAXFULL 8192UL
#define MEGA_FINGERPRINT_SPARSE_BLOCK 64UL
#define MEGA_FINGERPRINT_SPARSE_BLOCKS 32UL
#define MEGA_FINGERPRINT_SPARSE_DENOM 127UL

static int g_mega_request_id = 1;
static int g_mega_login_key_valid;
static unsigned char g_mega_login_key[16];

typedef int (*wm_mega_rsa_decrypt_session_fn)(
    const unsigned char *mega_privk,
    unsigned int mega_privk_len,
    const unsigned char *mega_csid,
    unsigned int mega_csid_len,
    unsigned char *sid,
    unsigned int sid_len
);

typedef struct mega_session_state {
    int logged_in;
    int account_version;
    int master_key_valid;
    int sid_valid;
    char user_handle[32];
    char sid[80];
    char csid[1024];
    char tsid[128];
    char privk[1024];
    char sek[64];
    unsigned char master_key[16];
} mega_session_state;

typedef struct mega_node_entry {
    char handle[16];
    char parent[16];
    int type;
    unsigned __int64 size;
    unsigned int mtime;
    char name[MEGA_MAX_NODE_NAME];
    int file_key_valid;
    unsigned char file_key[32];
} mega_node_entry;

typedef struct mega_saved_session_file {
    char magic[8];
    unsigned int version;
    unsigned int account_version;
    unsigned int sid_valid;
    char sid[80];
    char user_handle[32];
    unsigned char master_key[16];
} mega_saved_session_file;

static mega_session_state g_mega_session;
static mega_node_entry *g_mega_nodes;
static int g_mega_node_count;
static int g_mega_node_capacity;

static void
mega_nodes_reset(void)
{
    if (g_mega_nodes != 0 && g_mega_node_capacity > 0) {
        mega_crypto_zero(g_mega_nodes,
            sizeof(mega_node_entry) * (unsigned int)g_mega_node_capacity);
    }
    g_mega_node_count = 0;
}

static void
mega_nodes_free(void)
{
    if (g_mega_nodes != 0) {
        mega_crypto_zero(g_mega_nodes,
            sizeof(mega_node_entry) * (unsigned int)g_mega_node_capacity);
        LocalFree((HLOCAL)g_mega_nodes);
    }
    g_mega_nodes = 0;
    g_mega_node_count = 0;
    g_mega_node_capacity = 0;
}

static int
mega_nodes_ensure_capacity(int required)
{
    mega_node_entry *grown;
    int new_capacity;

    if (required <= g_mega_node_capacity) {
        return 1;
    }

    new_capacity = g_mega_node_capacity == 0 ? 256 : g_mega_node_capacity;
    while (new_capacity < required) {
        if (new_capacity > 0x3fffffff) {
            return 0;
        }
        new_capacity *= 2;
    }

    if (g_mega_nodes == 0) {
        grown = (mega_node_entry *)LocalAlloc(LPTR,
            sizeof(mega_node_entry) * (unsigned int)new_capacity);
    } else {
        grown = (mega_node_entry *)LocalAlloc(LPTR,
            sizeof(mega_node_entry) * (unsigned int)new_capacity);
        if (grown != 0) {
            memcpy(grown, g_mega_nodes,
                sizeof(mega_node_entry) * (unsigned int)g_mega_node_count);
            mega_crypto_zero(g_mega_nodes,
                sizeof(mega_node_entry) * (unsigned int)g_mega_node_capacity);
            LocalFree((HLOCAL)g_mega_nodes);
        }
    }
    if (grown == 0) {
        return 0;
    }

    g_mega_nodes = grown;
    g_mega_node_capacity = new_capacity;
    return 1;
}

int
mega_api_has_login_key(void)
{
    return g_mega_login_key_valid;
}

void
mega_api_clear_login_key(void)
{
    mega_crypto_zero(g_mega_login_key, sizeof(g_mega_login_key));
    g_mega_login_key_valid = 0;
}

int
mega_api_has_session(void)
{
    return g_mega_session.logged_in;
}

void
mega_api_clear_session(void)
{
    mega_crypto_zero(&g_mega_session, sizeof(g_mega_session));
    mega_nodes_free();
}

int
mega_api_get_session_status(char *status, unsigned int status_size)
{
    const char *session_type;

    if (status == 0 || status_size == 0) {
        return 0;
    }

    if (!g_mega_session.logged_in) {
        _snprintf(status, status_size, "Session: not logged in.");
        status[status_size - 1] = '\0';
        return 1;
    }

    session_type = "none";
    if (g_mega_session.csid[0] != '\0') {
        session_type = "csid";
    } else if (g_mega_session.tsid[0] != '\0') {
        session_type = "tsid";
    } else if (g_mega_session.sid_valid) {
        session_type = "saved";
    }

    _snprintf(status, status_size,
        "Session: logged in\r\n"
        "Account version: v%d\r\n"
        "User handle: %s\r\n"
        "Master key: %s\r\n"
        "API session: %s\r\n"
        "Session type: %s\r\n"
        "Private key: %s\r\n"
        "Session key: %s",
        g_mega_session.account_version,
        g_mega_session.user_handle[0] != '\0' ? "present" : "missing",
        g_mega_session.master_key_valid ? "decrypted" : "missing",
        g_mega_session.sid_valid ? "ready" : "missing",
        session_type,
        g_mega_session.privk[0] != '\0' ? "present" : "missing",
        g_mega_session.sek[0] != '\0' ? "present" : "missing");
    status[status_size - 1] = '\0';
    return 1;
}

int
mega_api_save_session_file(const WCHAR *path)
{
    mega_saved_session_file file_data;
    HANDLE file;
    DWORD written;
    int ok;

    if (path == 0 || !g_mega_session.logged_in
        || !g_mega_session.sid_valid
        || !g_mega_session.master_key_valid)
    {
        return 0;
    }

    memset(&file_data, 0, sizeof(file_data));
    memcpy(file_data.magic, "MCESES1", 7);
    file_data.version = 1;
    file_data.account_version = (unsigned int)g_mega_session.account_version;
    file_data.sid_valid = (unsigned int)g_mega_session.sid_valid;
    memcpy(file_data.sid, g_mega_session.sid, sizeof(file_data.sid));
    memcpy(file_data.user_handle, g_mega_session.user_handle,
        sizeof(file_data.user_handle));
    memcpy(file_data.master_key, g_mega_session.master_key,
        sizeof(file_data.master_key));

    file = CreateFile(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        mega_crypto_zero(&file_data, sizeof(file_data));
        return 0;
    }

    written = 0;
    ok = WriteFile(file, &file_data, sizeof(file_data), &written, 0)
        && written == sizeof(file_data);
    CloseHandle(file);
    mega_crypto_zero(&file_data, sizeof(file_data));
    return ok ? 1 : 0;
}

int
mega_api_load_session_file(const WCHAR *path)
{
    mega_saved_session_file file_data;
    HANDLE file;
    DWORD read_bytes;

    if (path == 0) {
        return 0;
    }

    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }

    read_bytes = 0;
    memset(&file_data, 0, sizeof(file_data));
    if (!ReadFile(file, &file_data, sizeof(file_data), &read_bytes, 0)
        || read_bytes != sizeof(file_data))
    {
        CloseHandle(file);
        mega_crypto_zero(&file_data, sizeof(file_data));
        return 0;
    }
    CloseHandle(file);

    if (memcmp(file_data.magic, "MCESES1", 7) != 0
        || file_data.version != 1
        || file_data.sid[0] == '\0')
    {
        mega_crypto_zero(&file_data, sizeof(file_data));
        return 0;
    }

    mega_api_clear_session();
    g_mega_session.logged_in = 1;
    g_mega_session.account_version = (int)file_data.account_version;
    g_mega_session.master_key_valid = 1;
    g_mega_session.sid_valid = 1;
    memcpy(g_mega_session.sid, file_data.sid, sizeof(g_mega_session.sid));
    memcpy(g_mega_session.user_handle, file_data.user_handle,
        sizeof(g_mega_session.user_handle));
    memcpy(g_mega_session.master_key, file_data.master_key,
        sizeof(g_mega_session.master_key));

    mega_crypto_zero(&file_data, sizeof(file_data));
    return 1;
}

static void
mega_api_clear_result(mega_api_result *result)
{
    if (result != 0) {
        memset(result, 0, sizeof(*result));
    }
}

static void
mega_api_set_error(mega_api_result *result, const char *message)
{
    if (result != 0 && message != 0) {
        _snprintf(result->error, sizeof(result->error), "%s", message);
        result->error[sizeof(result->error) - 1] = '\0';
    }
}

static void
mega_api_set_diagnostic(mega_api_result *result, const char *message)
{
    if (result != 0 && message != 0) {
        _snprintf(result->diagnostic, sizeof(result->diagnostic), "%s", message);
        result->diagnostic[sizeof(result->diagnostic) - 1] = '\0';
    }
}

static void
mega_ascii_lower_copy(const char *src, char *dst, unsigned int dst_size)
{
    unsigned int used;

    if (dst == 0 || dst_size == 0) {
        return;
    }

    used = 0;
    while (src != 0 && *src != '\0' && used + 1 < dst_size) {
        char ch;

        ch = *src++;
        if (ch >= 'A' && ch <= 'Z') {
            ch = (char)(ch - 'A' + 'a');
        }
        dst[used++] = ch;
    }
    dst[used] = '\0';
}

static int
mega_json_escape_string(
    const char *src,
    char *dst,
    unsigned int dst_size
)
{
    unsigned int used;

    if (src == 0 || dst == 0 || dst_size == 0) {
        return 0;
    }

    used = 0;
    while (*src != '\0') {
        char ch;

        ch = *src++;
        if (ch == '"' || ch == '\\') {
            if (used + 2 >= dst_size) {
                return 0;
            }
            dst[used++] = '\\';
            dst[used++] = ch;
        } else if ((unsigned char)ch < 0x20) {
            return 0;
        } else {
            if (used + 1 >= dst_size) {
                return 0;
            }
            dst[used++] = ch;
        }
    }

    dst[used] = '\0';
    return 1;
}

static int
mega_parse_prelogin_response(
    const char *response_body,
    int *version,
    char *salt,
    unsigned int salt_size
)
{
    const char *v;
    const char *s;
    const char *end;
    unsigned int len;

    if (version != 0) {
        *version = 0;
    }
    if (salt != 0 && salt_size > 0) {
        salt[0] = '\0';
    }

    if (response_body == 0 || version == 0) {
        return 0;
    }

    v = strstr(response_body, "\"v\"");
    if (v == 0) {
        return 0;
    }
    v = strchr(v, ':');
    if (v == 0) {
        return 0;
    }
    v++;
    while (*v == ' ' || *v == '\t') {
        v++;
    }
    *version = atoi(v);

    s = strstr(response_body, "\"s\"");
    if (s == 0 || salt == 0 || salt_size == 0) {
        return 1;
    }
    s = strchr(s, ':');
    if (s == 0) {
        return 1;
    }
    s++;
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    if (*s != '"') {
        return 1;
    }
    s++;
    end = strchr(s, '"');
    if (end == 0) {
        return 1;
    }

    len = (unsigned int)(end - s);
    if (len >= salt_size) {
        len = salt_size - 1;
    }
    memcpy(salt, s, len);
    salt[len] = '\0';
    return 1;
}

static int
mega_json_extract_string(
    const char *json,
    const char *name,
    char *out,
    unsigned int out_size
)
{
    char pattern[32];
    const char *p;
    const char *end;
    unsigned int len;

    if (json == 0 || name == 0 || out == 0 || out_size == 0) {
        return 0;
    }

    out[0] = '\0';
    _snprintf(pattern, sizeof(pattern), "\"%s\"", name);
    pattern[sizeof(pattern) - 1] = '\0';

    p = strstr(json, pattern);
    if (p == 0) {
        return 0;
    }
    p += strlen(pattern);
    p = strchr(p, ':');
    if (p == 0) {
        return 0;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        p++;
    }
    if (*p != '"') {
        return 0;
    }
    p++;
    end = strchr(p, '"');
    if (end == 0) {
        return 0;
    }

    len = (unsigned int)(end - p);
    if (len >= out_size) {
        return 0;
    }
    memcpy(out, p, len);
    out[len] = '\0';
    return 1;
}

static int mega_api_decrypt_session_id(void);

static int
mega_api_store_login_session(
    const char *response_body,
    int account_version,
    const unsigned char *login_key
)
{
    char master_key_b64[64];
    unsigned char encrypted_key[32];
    int decoded;

    mega_api_clear_session();

    if (!mega_json_extract_string(response_body, "k",
        master_key_b64, sizeof(master_key_b64)))
    {
        return 0;
    }

    decoded = mega_crypto_base64url_decode(master_key_b64, encrypted_key,
        sizeof(encrypted_key));
    if (decoded != 16 || login_key == 0) {
        mega_crypto_zero(encrypted_key, sizeof(encrypted_key));
        mega_crypto_zero(master_key_b64, sizeof(master_key_b64));
        return 0;
    }

    if (!mega_crypto_aes128_decrypt_block(login_key, encrypted_key)) {
        mega_crypto_zero(encrypted_key, sizeof(encrypted_key));
        mega_crypto_zero(master_key_b64, sizeof(master_key_b64));
        return 0;
    }

    g_mega_session.logged_in = 1;
    g_mega_session.account_version = account_version;
    g_mega_session.master_key_valid = 1;
    memcpy(g_mega_session.master_key, encrypted_key,
        sizeof(g_mega_session.master_key));

    mega_json_extract_string(response_body, "u",
        g_mega_session.user_handle, sizeof(g_mega_session.user_handle));
    mega_json_extract_string(response_body, "csid",
        g_mega_session.csid, sizeof(g_mega_session.csid));
    mega_json_extract_string(response_body, "tsid",
        g_mega_session.tsid, sizeof(g_mega_session.tsid));
    mega_json_extract_string(response_body, "privk",
        g_mega_session.privk, sizeof(g_mega_session.privk));
    mega_json_extract_string(response_body, "sek",
        g_mega_session.sek, sizeof(g_mega_session.sek));

    if (g_mega_session.csid[0] != '\0' && !mega_api_decrypt_session_id()) {
        mega_api_clear_session();
        mega_crypto_zero(encrypted_key, sizeof(encrypted_key));
        mega_crypto_zero(master_key_b64, sizeof(master_key_b64));
        return 0;
    }

    mega_crypto_zero(encrypted_key, sizeof(encrypted_key));
    mega_crypto_zero(master_key_b64, sizeof(master_key_b64));
    return 1;
}

static int
mega_api_decrypt_session_id(void)
{
    unsigned char privk_bin[1024];
    unsigned char csid_bin[1024];
    unsigned char sid_bin[43];
    HMODULE dll;
    wm_mega_rsa_decrypt_session_fn decrypt_session;
    int privk_len;
    int csid_len;
    int i;
    int ok;

    if (!g_mega_session.master_key_valid
        || g_mega_session.privk[0] == '\0'
        || g_mega_session.csid[0] == '\0')
    {
        return 0;
    }

    privk_len = mega_crypto_base64url_decode(g_mega_session.privk,
        privk_bin, sizeof(privk_bin));
    csid_len = mega_crypto_base64url_decode(g_mega_session.csid,
        csid_bin, sizeof(csid_bin));
    if (privk_len <= 0 || csid_len <= 0 || (privk_len & 15) != 0) {
        mega_crypto_zero(privk_bin, sizeof(privk_bin));
        mega_crypto_zero(csid_bin, sizeof(csid_bin));
        return 0;
    }

    for (i = 0; i < privk_len; i += 16) {
        if (!mega_crypto_aes128_decrypt_block(g_mega_session.master_key,
            privk_bin + i))
        {
            mega_crypto_zero(privk_bin, sizeof(privk_bin));
            mega_crypto_zero(csid_bin, sizeof(csid_bin));
            return 0;
        }
    }

    dll = LoadLibrary(TEXT("wm_https.dll"));
    if (dll == 0) {
        mega_crypto_zero(privk_bin, sizeof(privk_bin));
        mega_crypto_zero(csid_bin, sizeof(csid_bin));
        return 0;
    }

    decrypt_session = (wm_mega_rsa_decrypt_session_fn)GetProcAddressA(dll,
        "wm_mega_rsa_decrypt_session");
    if (decrypt_session == 0) {
        FreeLibrary(dll);
        mega_crypto_zero(privk_bin, sizeof(privk_bin));
        mega_crypto_zero(csid_bin, sizeof(csid_bin));
        return 0;
    }

    memset(sid_bin, 0, sizeof(sid_bin));
    ok = decrypt_session(privk_bin, (unsigned int)privk_len,
        csid_bin, (unsigned int)csid_len,
        sid_bin, sizeof(sid_bin));
    FreeLibrary(dll);

    if (ok) {
        ok = mega_crypto_base64url_encode(sid_bin, sizeof(sid_bin),
            g_mega_session.sid, sizeof(g_mega_session.sid));
        g_mega_session.sid_valid = ok ? 1 : 0;
    }

    mega_crypto_zero(privk_bin, sizeof(privk_bin));
    mega_crypto_zero(csid_bin, sizeof(csid_bin));
    mega_crypto_zero(sid_bin, sizeof(sid_bin));
    return ok;
}

static int
mega_response_is_login_success(const char *response_body)
{
    if (response_body == 0 || response_body[0] != '[') {
        return 0;
    }

    return strstr(response_body, "\"k\"") != 0
        && (strstr(response_body, "\"csid\"") != 0
            || strstr(response_body, "\"tsid\"") != 0);
}

int
mega_api_command(
    const char *json_commands,
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
)
{
    char path[64];
    int request_id;
    int ok;

    mega_api_clear_result(result);

    if (json_commands == 0 || response_body == 0 || response_body_size < 2) {
        mega_api_set_error(result, "invalid MEGA API arguments");
        return 0;
    }

    request_id = g_mega_request_id++;
    if (g_mega_request_id <= 0) {
        g_mega_request_id = 1;
    }

    _snprintf(path, sizeof(path), "/cs?id=%d", request_id);
    path[sizeof(path) - 1] = '\0';

    ok = mega_http_post(MEGA_API_HOST, MEGA_API_PORT, path,
        json_commands, (unsigned int)strlen(json_commands),
        response_body, response_body_size,
        result != 0 ? &result->http : 0);

    if (result != 0 && result->http.status_code == 402) {
        char hashcash_token[80];
        char hashcash_prefix[16];
        char hashcash_header[128];
        unsigned int hashcash_easiness;

        if (mega_hashcash_parse_header(result->http.headers,
            hashcash_token, sizeof(hashcash_token), &hashcash_easiness))
        {
            mega_http_progress_message("Solving MEGA Hashcash...");
            if (mega_hashcash_solve(hashcash_token, hashcash_easiness,
                hashcash_prefix, sizeof(hashcash_prefix)))
            {
                _snprintf(hashcash_header, sizeof(hashcash_header),
                    "X-Hashcash: 1:%s:%s\r\n",
                    hashcash_token, hashcash_prefix);
                hashcash_header[sizeof(hashcash_header) - 1] = '\0';

                mega_http_progress_message("Retrying with MEGA Hashcash...");
                ok = mega_http_post_ex(MEGA_API_HOST, MEGA_API_PORT, path,
                    hashcash_header,
                    json_commands, (unsigned int)strlen(json_commands),
                    response_body, response_body_size,
                    &result->http);
                mega_crypto_zero(hashcash_header, sizeof(hashcash_header));
                mega_crypto_zero(hashcash_prefix, sizeof(hashcash_prefix));
            } else {
                mega_api_set_error(result, "could not solve MEGA Hashcash");
            }
            mega_crypto_zero(hashcash_token, sizeof(hashcash_token));
        }
    }

    if (result != 0) {
        result->request_id = request_id;
        result->ok = ok;
        if (!ok) {
            if (result->http.error[0] != '\0') {
                mega_api_set_error(result, result->http.error);
            } else {
                mega_api_set_error(result, "MEGA API request failed");
            }
        }
    }

    return ok;
}

static int
mega_api_session_command(
    const char *json_commands,
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
)
{
    char path[128];
    int request_id;
    int ok;

    mega_api_clear_result(result);

    if (!g_mega_session.logged_in || !g_mega_session.sid_valid
        || g_mega_session.sid[0] == '\0')
    {
        mega_api_set_error(result, "not logged in with a usable API session");
        return 0;
    }

    if (json_commands == 0 || response_body == 0 || response_body_size < 2) {
        mega_api_set_error(result, "invalid MEGA API arguments");
        return 0;
    }

    request_id = g_mega_request_id++;
    if (g_mega_request_id <= 0) {
        g_mega_request_id = 1;
    }

    _snprintf(path, sizeof(path), "/cs?id=%d&sid=%s",
        request_id, g_mega_session.sid);
    path[sizeof(path) - 1] = '\0';

    ok = mega_http_post(MEGA_API_HOST, MEGA_API_PORT, path,
        json_commands, (unsigned int)strlen(json_commands),
        response_body, response_body_size,
        result != 0 ? &result->http : 0);

    if (result != 0 && result->http.status_code == 402) {
        char hashcash_token[80];
        char hashcash_prefix[16];
        char hashcash_header[128];
        unsigned int hashcash_easiness;

        if (mega_hashcash_parse_header(result->http.headers,
            hashcash_token, sizeof(hashcash_token), &hashcash_easiness))
        {
            mega_http_progress_message("Solving MEGA Hashcash...");
            if (mega_hashcash_solve(hashcash_token, hashcash_easiness,
                hashcash_prefix, sizeof(hashcash_prefix)))
            {
                _snprintf(hashcash_header, sizeof(hashcash_header),
                    "X-Hashcash: 1:%s:%s\r\n",
                    hashcash_token, hashcash_prefix);
                hashcash_header[sizeof(hashcash_header) - 1] = '\0';

                mega_http_progress_message("Retrying with MEGA Hashcash...");
                ok = mega_http_post_ex(MEGA_API_HOST, MEGA_API_PORT, path,
                    hashcash_header,
                    json_commands, (unsigned int)strlen(json_commands),
                    response_body, response_body_size,
                    &result->http);
                mega_crypto_zero(hashcash_header, sizeof(hashcash_header));
                mega_crypto_zero(hashcash_prefix, sizeof(hashcash_prefix));
            } else {
                mega_api_set_error(result, "could not solve MEGA Hashcash");
            }
            mega_crypto_zero(hashcash_token, sizeof(hashcash_token));
        }
    }

    if (result != 0) {
        result->request_id = request_id;
        result->ok = ok;
        if (!ok) {
            if (result->http.error[0] != '\0') {
                mega_api_set_error(result, result->http.error);
            } else {
                mega_api_set_error(result, "MEGA API request failed");
            }
        }
    }

    return ok;
}

static int
mega_api_session_command_file(
    const char *json_commands,
    const WCHAR *response_file_path,
    mega_api_result *result
)
{
    char path[128];
    int request_id;
    int ok;

    mega_api_clear_result(result);

    if (!g_mega_session.logged_in || !g_mega_session.sid_valid
        || g_mega_session.sid[0] == '\0')
    {
        mega_api_set_error(result, "not logged in with a usable API session");
        return 0;
    }

    if (json_commands == 0 || response_file_path == 0) {
        mega_api_set_error(result, "invalid MEGA API file arguments");
        return 0;
    }

    request_id = g_mega_request_id++;
    if (g_mega_request_id <= 0) {
        g_mega_request_id = 1;
    }

    _snprintf(path, sizeof(path), "/cs?id=%d&sid=%s",
        request_id, g_mega_session.sid);
    path[sizeof(path) - 1] = '\0';

    ok = mega_http_post_file_ex(MEGA_API_HOST, MEGA_API_PORT, path, 0,
        json_commands, (unsigned int)strlen(json_commands),
        response_file_path, result != 0 ? &result->http : 0);

    if (result != 0 && result->http.status_code == 402) {
        char hashcash_token[80];
        char hashcash_prefix[16];
        char hashcash_header[128];
        unsigned int hashcash_easiness;

        if (mega_hashcash_parse_header(result->http.headers,
            hashcash_token, sizeof(hashcash_token), &hashcash_easiness))
        {
            mega_http_progress_message("Solving MEGA Hashcash...");
            if (mega_hashcash_solve(hashcash_token, hashcash_easiness,
                hashcash_prefix, sizeof(hashcash_prefix)))
            {
                _snprintf(hashcash_header, sizeof(hashcash_header),
                    "X-Hashcash: 1:%s:%s\r\n",
                    hashcash_token, hashcash_prefix);
                hashcash_header[sizeof(hashcash_header) - 1] = '\0';

                mega_http_progress_message("Retrying with MEGA Hashcash...");
                ok = mega_http_post_file_ex(MEGA_API_HOST, MEGA_API_PORT, path,
                    hashcash_header,
                    json_commands, (unsigned int)strlen(json_commands),
                    response_file_path,
                    result != 0 ? &result->http : 0);
                mega_crypto_zero(hashcash_header, sizeof(hashcash_header));
                mega_crypto_zero(hashcash_prefix, sizeof(hashcash_prefix));
            } else {
                mega_api_set_error(result, "could not solve MEGA Hashcash");
            }
            mega_crypto_zero(hashcash_token, sizeof(hashcash_token));
        }
    }

    if (result != 0) {
        result->request_id = request_id;
        result->ok = ok;
        if (!ok) {
            if (result->http.error[0] != '\0') {
                mega_api_set_error(result, result->http.error);
            } else {
                mega_api_set_error(result, "MEGA API request failed");
            }
        }
    }

    return ok;
}

int
mega_api_probe(
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
)
{
    return mega_api_command("[]", response_body, response_body_size, result);
}

int
mega_api_get_user_salt(
    const char *email,
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
)
{
    char normalized_email[256];
    char escaped_email[256];
    char command[384];

    mega_api_clear_result(result);

    if (email == 0 || email[0] == '\0') {
        mega_api_set_error(result, "enter an email address");
        return 0;
    }

    mega_ascii_lower_copy(email, normalized_email, sizeof(normalized_email));

    if (!mega_json_escape_string(normalized_email, escaped_email, sizeof(escaped_email))) {
        mega_api_set_error(result, "email address is too long or invalid");
        return 0;
    }

    _snprintf(command, sizeof(command),
        "[{\"a\":\"us0\",\"user\":\"%s\"}]",
        escaped_email);
    command[sizeof(command) - 1] = '\0';

    return mega_api_command(command, response_body, response_body_size, result);
}

int
mega_api_login_v1(
    const char *email,
    const char *password,
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
)
{
    char normalized_email[256];
    char escaped_email[256];
    char prelogin_body[1024];
    char account_salt[128];
    char user_hash[32];
    unsigned char session_key[16];
    char session_key_b64[32];
    unsigned char derived_key[32];
    unsigned char login_key[16];
    char command[512];
    int account_version;
    int ok;

    mega_api_clear_result(result);
    mega_api_clear_session();
    mega_api_clear_login_key();

    if (email == 0 || email[0] == '\0') {
        mega_api_set_error(result, "enter an email address");
        return 0;
    }

    if (password == 0 || password[0] == '\0') {
        mega_api_set_error(result, "enter a password");
        return 0;
    }

    mega_ascii_lower_copy(email, normalized_email, sizeof(normalized_email));

    if (!mega_json_escape_string(normalized_email, escaped_email, sizeof(escaped_email))) {
        mega_api_set_error(result, "email address is too long or invalid");
        return 0;
    }

    prelogin_body[0] = '\0';
    account_salt[0] = '\0';
    memset(login_key, 0, sizeof(login_key));
    if (!mega_api_get_user_salt(normalized_email, prelogin_body,
        sizeof(prelogin_body), result))
    {
        return 0;
    }

    account_version = 0;
    if (!mega_parse_prelogin_response(prelogin_body, &account_version,
        account_salt, sizeof(account_salt)))
    {
        mega_api_set_error(result, "could not parse MEGA prelogin response");
        return 0;
    }
    if (result != 0) {
        result->account_version = account_version;
    }

    if (!mega_crypto_random_bytes(session_key, sizeof(session_key))
        || !mega_crypto_base64url_encode(session_key, sizeof(session_key),
            session_key_b64, sizeof(session_key_b64)))
    {
        mega_crypto_zero(user_hash, sizeof(user_hash));
        mega_crypto_zero(session_key, sizeof(session_key));
        mega_api_set_error(result, "could not create session key");
        return 0;
    }

    if (account_version == 1) {
        if (!mega_crypto_v1_user_hash(normalized_email, password,
            user_hash, sizeof(user_hash)))
        {
            mega_crypto_zero(session_key, sizeof(session_key));
            mega_crypto_zero(session_key_b64, sizeof(session_key_b64));
            mega_api_set_error(result, "could not derive v1 login hash");
            return 0;
        }
    } else if (account_version == 2) {
        if (account_salt[0] == '\0'
            || !mega_crypto_v2_derive_key(password, account_salt,
                derived_key, sizeof(derived_key))
            || !mega_crypto_base64url_encode(derived_key + 16, 16,
                user_hash, sizeof(user_hash)))
        {
            mega_crypto_zero(session_key, sizeof(session_key));
            mega_crypto_zero(session_key_b64, sizeof(session_key_b64));
            mega_crypto_zero(derived_key, sizeof(derived_key));
            mega_api_set_error(result, "could not derive v2 login hash");
            return 0;
        }
        memcpy(login_key, derived_key, sizeof(login_key));
        mega_crypto_zero(derived_key, sizeof(derived_key));
    } else {
        mega_crypto_zero(session_key, sizeof(session_key));
        mega_crypto_zero(session_key_b64, sizeof(session_key_b64));
        mega_api_set_error(result, "unsupported MEGA account version");
        return 0;
    }

    _snprintf(command, sizeof(command),
        "[{\"a\":\"us\",\"user\":\"%s\",\"uh\":\"%s\",\"sek\":\"%s\"}]",
        escaped_email, user_hash, session_key_b64);
    command[sizeof(command) - 1] = '\0';

    ok = mega_api_command(command, response_body, response_body_size, result);
    if (result != 0) {
        result->account_version = account_version;
    }
    mega_api_set_diagnostic(result,
        account_version == 2
            ? "login v2 command: user+uh+sek PBKDF2-SHA512"
            : "login v1 command: user+uh+sek sdk bytes");

    if (result != 0 && ok && mega_response_is_login_success(response_body)) {
        result->login_success = 1;
        result->sensitive_response = 1;
        if (mega_api_store_login_session(response_body, account_version,
            account_version == 2 ? login_key : 0))
        {
            mega_api_clear_login_key();
        } else {
            result->login_success = 0;
            result->sensitive_response = 1;
            mega_api_set_error(result, "could not decrypt MEGA session key");
        }
    }

    mega_crypto_zero(user_hash, sizeof(user_hash));
    mega_crypto_zero(login_key, sizeof(login_key));
    mega_crypto_zero(session_key, sizeof(session_key));
    mega_crypto_zero(session_key_b64, sizeof(session_key_b64));
    mega_crypto_zero(command, sizeof(command));

    return ok;
}

static int
mega_count_token(const char *text, const char *token)
{
    int count;
    const char *p;
    unsigned int len;

    if (text == 0 || token == 0 || token[0] == '\0') {
        return 0;
    }

    count = 0;
    p = text;
    len = (unsigned int)strlen(token);
    while ((p = strstr(p, token)) != 0) {
        count++;
        p += len;
    }
    return count;
}

static int
mega_json_extract_int(const char *json, const char *name, int *out)
{
    char pattern[32];
    const char *p;

    if (json == 0 || name == 0 || out == 0) {
        return 0;
    }

    _snprintf(pattern, sizeof(pattern), "\"%s\"", name);
    pattern[sizeof(pattern) - 1] = '\0';
    p = strstr(json, pattern);
    if (p == 0) {
        return 0;
    }
    p = strchr(p, ':');
    if (p == 0) {
        return 0;
    }
    p++;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    *out = atoi(p);
    return 1;
}

static int
mega_json_extract_uint64(const char *json, const char *name, unsigned __int64 *out)
{
    char pattern[32];
    const char *p;
    unsigned __int64 value;

    if (json == 0 || name == 0 || out == 0) {
        return 0;
    }

    _snprintf(pattern, sizeof(pattern), "\"%s\"", name);
    pattern[sizeof(pattern) - 1] = '\0';
    p = strstr(json, pattern);
    if (p == 0) {
        return 0;
    }
    p = strchr(p, ':');
    if (p == 0) {
        return 0;
    }
    p++;
    while (*p == ' ' || *p == '\t') {
        p++;
    }

    value = 0;
    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (unsigned int)(*p - '0');
        p++;
    }
    *out = value;
    return 1;
}

static int
mega_json_extract_uint(const char *json, const char *name, unsigned int *out)
{
    unsigned __int64 value;

    if (out == 0) {
        return 0;
    }
    value = 0;
    if (!mega_json_extract_uint64(json, name, &value)) {
        return 0;
    }
    *out = (unsigned int)value;
    return 1;
}

static int
mega_find_object_end(const char *start, const char **end)
{
    const char *p;
    int in_string;
    int escape;
    int depth;

    if (start == 0 || end == 0 || *start != '{') {
        return 0;
    }

    in_string = 0;
    escape = 0;
    depth = 1;
    for (p = start + 1; *p != '\0'; ++p) {
        if (escape) {
            escape = 0;
        } else if (*p == '\\') {
            escape = in_string;
        } else if (*p == '"') {
            in_string = !in_string;
        } else if (!in_string && *p == '{') {
            depth++;
        } else if (!in_string && *p == '}') {
            depth--;
            if (depth == 0) {
                *end = p + 1;
                return 1;
            }
        }
    }

    return 0;
}

static int
mega_find_array_end(const char *start, const char **end)
{
    const char *p;
    int in_string;
    int escape;
    int depth;

    if (start == 0 || end == 0 || *start != '[') {
        return 0;
    }

    in_string = 0;
    escape = 0;
    depth = 1;
    for (p = start + 1; *p != '\0'; ++p) {
        if (escape) {
            escape = 0;
        } else if (*p == '\\') {
            escape = in_string;
        } else if (*p == '"') {
            in_string = !in_string;
        } else if (!in_string && *p == '[') {
            depth++;
        } else if (!in_string && *p == ']') {
            depth--;
            if (depth == 0) {
                *end = p + 1;
                return 1;
            }
        }
    }

    return 0;
}

static int
mega_hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int
mega_json_copy_string_value(const char *src, char *dst, unsigned int dst_size)
{
    unsigned int out;

    if (src == 0 || dst == 0 || dst_size == 0) {
        return 0;
    }

    dst[0] = '\0';
    if (*src != '"') {
        return 0;
    }
    src++;
    out = 0;
    while (*src != '\0' && *src != '"') {
        unsigned int ch;

        if (out >= dst_size - 1) {
            return 0;
        }

        if (*src != '\\') {
            dst[out++] = *src++;
            continue;
        }

        src++;
        if (*src == '\0') {
            return 0;
        }

        switch (*src) {
        case '"':
        case '\\':
        case '/':
            dst[out++] = *src++;
            break;
        case 'b':
            dst[out++] = '\b';
            src++;
            break;
        case 'f':
            dst[out++] = '\f';
            src++;
            break;
        case 'n':
            dst[out++] = '\n';
            src++;
            break;
        case 'r':
            dst[out++] = '\r';
            src++;
            break;
        case 't':
            dst[out++] = '\t';
            src++;
            break;
        case 'u':
        {
            int h0;
            int h1;
            int h2;
            int h3;

            h0 = mega_hex_digit(src[1]);
            h1 = mega_hex_digit(src[2]);
            h2 = mega_hex_digit(src[3]);
            h3 = mega_hex_digit(src[4]);
            if (h0 < 0 || h1 < 0 || h2 < 0 || h3 < 0) {
                return 0;
            }
            ch = (unsigned int)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
            if (ch < 0x80) {
                dst[out++] = (char)ch;
            } else if (ch < 0x800) {
                if (out + 2 >= dst_size) {
                    return 0;
                }
                dst[out++] = (char)(0xc0 | (ch >> 6));
                dst[out++] = (char)(0x80 | (ch & 0x3f));
            } else {
                if (out + 3 >= dst_size) {
                    return 0;
                }
                dst[out++] = (char)(0xe0 | (ch >> 12));
                dst[out++] = (char)(0x80 | ((ch >> 6) & 0x3f));
                dst[out++] = (char)(0x80 | (ch & 0x3f));
            }
            src += 5;
            break;
        }
        default:
            return 0;
        }
    }

    if (*src != '"') {
        return 0;
    }
    dst[out] = '\0';
    return 1;
}

static int
mega_decrypt_node_key_part(
    const char *key_part,
    int node_type,
    unsigned char *attr_key,
    unsigned int attr_key_size,
    unsigned char *raw_key,
    unsigned int raw_key_size,
    int *raw_key_len
)
{
    unsigned char key_bin[64];
    int key_len;
    int i;

    if (raw_key_len != 0) {
        *raw_key_len = 0;
    }

    if (key_part == 0 || key_part[0] == '\0'
        || attr_key == 0 || attr_key_size < 16
        || !g_mega_session.master_key_valid)
    {
        return 0;
    }

    key_len = mega_crypto_base64url_decode(key_part, key_bin, sizeof(key_bin));
    if (key_len < 16 || (key_len & 15) != 0) {
        mega_crypto_zero(key_bin, sizeof(key_bin));
        return 0;
    }

    for (i = 0; i < key_len; i += 16) {
        if (!mega_crypto_aes128_decrypt_block(g_mega_session.master_key,
            key_bin + i))
        {
            mega_crypto_zero(key_bin, sizeof(key_bin));
            return 0;
        }
    }

    if (raw_key != 0 && raw_key_size >= (unsigned int)key_len) {
        memcpy(raw_key, key_bin, key_len);
        if (raw_key_len != 0) {
            *raw_key_len = key_len;
        }
    }

    if (node_type == 0 && key_len >= 32) {
        for (i = 0; i < 16; ++i) {
            attr_key[i] = (unsigned char)(key_bin[i] ^ key_bin[i + 16]);
        }
    } else {
        memcpy(attr_key, key_bin, 16);
    }

    mega_crypto_zero(key_bin, sizeof(key_bin));
    return 1;
}

static int
mega_decrypt_attr_name(
    const char *attr_text,
    const unsigned char *attr_key,
    char *name,
    unsigned int name_size
)
{
    unsigned char attr_bin[1024];
    unsigned char prev[16];
    unsigned char cur[16];
    char *plain;
    char *n;
    int attr_len;
    int i;
    int b;

    if (attr_text == 0 || attr_key == 0 || name == 0 || name_size == 0) {
        return 0;
    }
    name[0] = '\0';

    attr_len = mega_crypto_base64url_decode(attr_text, attr_bin,
        sizeof(attr_bin) - 1);
    if (attr_len <= 0 || (attr_len & 15) != 0) {
        mega_crypto_zero(attr_bin, sizeof(attr_bin));
        return 0;
    }

    memset(prev, 0, sizeof(prev));
    for (i = 0; i < attr_len; i += 16) {
        memcpy(cur, attr_bin + i, 16);
        if (!mega_crypto_aes128_decrypt_block(attr_key, attr_bin + i)) {
            mega_crypto_zero(attr_bin, sizeof(attr_bin));
            return 0;
        }
        for (b = 0; b < 16; ++b) {
            attr_bin[i + b] ^= prev[b];
        }
        memcpy(prev, cur, 16);
    }
    attr_bin[attr_len] = '\0';

    plain = (char *)attr_bin;
    if (strncmp(plain, "MEGA", 4) != 0) {
        mega_crypto_zero(attr_bin, sizeof(attr_bin));
        return 0;
    }

    n = strstr(plain, "\"n\"");
    if (n == 0) {
        mega_crypto_zero(attr_bin, sizeof(attr_bin));
        return 0;
    }
    n = strchr(n, ':');
    if (n == 0) {
        mega_crypto_zero(attr_bin, sizeof(attr_bin));
        return 0;
    }
    n++;
    while (*n == ' ' || *n == '\t') {
        n++;
    }
    if (*n != '"') {
        mega_crypto_zero(attr_bin, sizeof(attr_bin));
        return 0;
    }
    if (!mega_json_copy_string_value(n, name, name_size)) {
        mega_crypto_zero(attr_bin, sizeof(attr_bin));
        return 0;
    }

    mega_crypto_zero(attr_bin, sizeof(attr_bin));
    return 1;
}

static int
mega_try_decrypt_node_name(
    const char *key_text,
    const char *attr_text,
    int node_type,
    char *name,
    unsigned int name_size,
    unsigned char *raw_key,
    unsigned int raw_key_size,
    int *raw_key_len
)
{
    const char *segment;

    if (raw_key_len != 0) {
        *raw_key_len = 0;
    }
    if (key_text == 0 || attr_text == 0 || name == 0 || name_size == 0) {
        return 0;
    }
    name[0] = '\0';

    segment = key_text;
    while (*segment != '\0') {
        const char *segment_end;
        const char *key_part;
        const char *colon;
        char candidate[512];
        unsigned int candidate_len;
        unsigned char attr_key[16];
        unsigned char candidate_raw_key[32];
        int candidate_raw_len;

        segment_end = strchr(segment, '/');
        if (segment_end == 0) {
            segment_end = segment + strlen(segment);
        }

        colon = segment;
        key_part = segment;
        while (colon < segment_end) {
            if (*colon == ':') {
                key_part = colon + 1;
                break;
            }
            colon++;
        }

        candidate_len = (unsigned int)(segment_end - key_part);
        if (candidate_len > 0 && candidate_len < sizeof(candidate)) {
            memcpy(candidate, key_part, candidate_len);
            candidate[candidate_len] = '\0';
            memset(attr_key, 0, sizeof(attr_key));
            memset(candidate_raw_key, 0, sizeof(candidate_raw_key));
            candidate_raw_len = 0;
            if (mega_decrypt_node_key_part(candidate, node_type,
                attr_key, sizeof(attr_key),
                candidate_raw_key, sizeof(candidate_raw_key),
                &candidate_raw_len)
                && mega_decrypt_attr_name(attr_text, attr_key, name, name_size))
            {
                if (raw_key != 0 && raw_key_size >= (unsigned int)candidate_raw_len) {
                    memcpy(raw_key, candidate_raw_key, candidate_raw_len);
                }
                if (raw_key_len != 0) {
                    *raw_key_len = candidate_raw_len;
                }
                mega_crypto_zero(attr_key, sizeof(attr_key));
                mega_crypto_zero(candidate_raw_key, sizeof(candidate_raw_key));
                return 1;
            }
            mega_crypto_zero(attr_key, sizeof(attr_key));
            mega_crypto_zero(candidate_raw_key, sizeof(candidate_raw_key));
        }

        if (*segment_end == '\0') {
            break;
        }
        segment = segment_end + 1;
    }

    return 0;
}

static void
mega_summary_add_name(mega_fetch_nodes_summary *summary, const char *name)
{
    unsigned int used;
    unsigned int len;

    if (summary == 0 || name == 0 || name[0] == '\0') {
        return;
    }
    used = (unsigned int)strlen(summary->first_names);
    if (used >= sizeof(summary->first_names) - 4) {
        return;
    }
    if (used != 0) {
        summary->first_names[used++] = ',';
        summary->first_names[used++] = ' ';
        summary->first_names[used] = '\0';
    }
    len = (unsigned int)strlen(name);
    if (used + len >= sizeof(summary->first_names)) {
        len = sizeof(summary->first_names) - used - 1;
    }
    memcpy(summary->first_names + used, name, len);
    summary->first_names[used + len] = '\0';
}

static void
mega_parse_fetch_node_object(const char *object, mega_fetch_nodes_summary *summary)
{
    mega_node_entry *node;
    char key_text[512];
    char attr_text[1024];
    int raw_key_len;

    if (object == 0 || summary == 0) {
        return;
    }

    if (!mega_nodes_ensure_capacity(g_mega_node_count + 1)) {
        summary->truncated = 1;
        return;
    }

    node = &g_mega_nodes[g_mega_node_count];
    memset(node, 0, sizeof(*node));
    if (!mega_json_extract_string(object, "h", node->handle,
        sizeof(node->handle)))
    {
        return;
    }

    mega_json_extract_string(object, "p", node->parent, sizeof(node->parent));
    mega_json_extract_int(object, "t", &node->type);
    mega_json_extract_uint64(object, "s", &node->size);
    mega_json_extract_uint(object, "ts", &node->mtime);

    if (node->type == 0) {
        summary->file_count++;
    } else if (node->type == 1) {
        summary->folder_count++;
    } else if (node->type == 2) {
        summary->root_count++;
    } else if (node->type == 3) {
        summary->incoming_count++;
    } else if (node->type == 4) {
        summary->rubbish_count++;
    }

    key_text[0] = '\0';
    attr_text[0] = '\0';
    raw_key_len = 0;
    if (mega_json_extract_string(object, "k", key_text, sizeof(key_text))
        && mega_json_extract_string(object, "a", attr_text, sizeof(attr_text))
        && mega_try_decrypt_node_name(key_text, attr_text, node->type,
            node->name, sizeof(node->name),
            node->file_key, sizeof(node->file_key), &raw_key_len))
    {
        summary->decrypted_names++;
        node->file_key_valid = (node->type == 0 && raw_key_len == 32)
            || (node->type != 0 && raw_key_len == 16);
        if (summary->decrypted_names <= 5) {
            mega_summary_add_name(summary, node->name);
        }
    } else if (node->type == 0) {
        summary->undecrypted_files++;
    } else if (node->type == 1) {
        summary->undecrypted_folders++;
    } else {
        summary->undecrypted_specials++;
    }

    g_mega_node_count++;
}

static int
mega_object_append_char(char **object, unsigned int *used, unsigned int *capacity, char c)
{
    char *grown;
    unsigned int new_capacity;

    if (object == 0 || used == 0 || capacity == 0) {
        return 0;
    }

    if (*used + 2 >= *capacity) {
        new_capacity = *capacity == 0 ? 1024 : *capacity * 2;
        if (new_capacity < *capacity) {
            return 0;
        }
        grown = (char *)LocalAlloc(LPTR, new_capacity);
        if (grown == 0) {
            return 0;
        }
        if (*object != 0) {
            memcpy(grown, *object, *used);
            mega_crypto_zero(*object, *capacity);
            LocalFree((HLOCAL)*object);
        }
        *object = grown;
        *capacity = new_capacity;
    }

    (*object)[(*used)++] = c;
    (*object)[*used] = '\0';
    return 1;
}

static void
mega_parse_fetch_nodes_file_body(const WCHAR *response_file_path, mega_fetch_nodes_summary *summary)
{
    HANDLE file;
    char buffer[2048];
    DWORD read_bytes;
    int found_f_key;
    int in_f_array;
    int in_string;
    int escape;
    int object_depth;
    char match[3];
    int match_len;
    char *object;
    unsigned int object_used;
    unsigned int object_capacity;

    mega_nodes_reset();

    if (response_file_path == 0 || summary == 0) {
        return;
    }

    file = CreateFile(response_file_path, GENERIC_READ, FILE_SHARE_READ,
        0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        summary->truncated = 1;
        return;
    }

    found_f_key = 0;
    in_f_array = 0;
    in_string = 0;
    escape = 0;
    object_depth = 0;
    match[0] = '\0';
    match[1] = '\0';
    match[2] = '\0';
    match_len = 0;
    object = 0;
    object_used = 0;
    object_capacity = 0;

    while (ReadFile(file, buffer, sizeof(buffer), &read_bytes, 0)
        && read_bytes > 0)
    {
        DWORD i;

        for (i = 0; i < read_bytes; ++i) {
            char c;

            c = buffer[i];

            if (object_depth > 0) {
                if (!mega_object_append_char(&object, &object_used,
                    &object_capacity, c))
                {
                    summary->truncated = 1;
                    goto done;
                }

                if (escape) {
                    escape = 0;
                } else if (c == '\\') {
                    escape = in_string;
                } else if (c == '"') {
                    in_string = !in_string;
                } else if (!in_string && c == '{') {
                    object_depth++;
                } else if (!in_string && c == '}') {
                    object_depth--;
                    if (object_depth == 0) {
                        mega_parse_fetch_node_object(object, summary);
                        object_used = 0;
                        if (object != 0) {
                            object[0] = '\0';
                        }
                        in_string = 0;
                        escape = 0;
                    }
                }
                continue;
            }

            if (!in_f_array) {
                if (!found_f_key) {
                    if (match_len == 0 && c == '"') {
                        match[match_len++] = c;
                    } else if (match_len == 1 && c == 'f') {
                        match[match_len++] = c;
                    } else if (match_len == 2 && c == '"') {
                        found_f_key = 1;
                        match_len = 0;
                    } else {
                        match_len = c == '"' ? 1 : 0;
                        if (match_len == 1) {
                            match[0] = c;
                        }
                    }
                } else if (c == '[') {
                    in_f_array = 1;
                }
                continue;
            }

            if (c == ']') {
                goto done;
            }
            if (c == '{') {
                object_depth = 1;
                in_string = 0;
                escape = 0;
                object_used = 0;
                if (!mega_object_append_char(&object, &object_used,
                    &object_capacity, c))
                {
                    summary->truncated = 1;
                    goto done;
                }
            }
        }
    }

done:
    if (object != 0) {
        LocalFree((HLOCAL)object);
    }
    CloseHandle(file);
    summary->parsed_nodes = g_mega_node_count;
    summary->node_count = g_mega_node_count;
}

static void
mega_parse_fetch_nodes(const char *response_body, mega_fetch_nodes_summary *summary)
{
    const char *array;
    const char *array_end;
    const char *p;

    mega_nodes_reset();

    if (response_body == 0 || summary == 0) {
        return;
    }

    array = strstr(response_body, "\"f\"");
    if (array == 0) {
        return;
    }
    array = strchr(array, '[');
    if (array == 0) {
        return;
    }
    if (!mega_find_array_end(array, &array_end)) {
        array_end = response_body + strlen(response_body);
        summary->truncated = 1;
    }

    p = array + 1;
    while (p < array_end
        && (p = strchr(p, '{')) != 0
        && p < array_end)
    {
        const char *end;
        char object[8192];
        unsigned int object_len;

        if (!mega_find_object_end(p, &end)) {
            break;
        }
        object_len = (unsigned int)(end - p);
        if (object_len >= sizeof(object)) {
            p = end;
            continue;
        }
        memcpy(object, p, object_len);
        object[object_len] = '\0';
        mega_parse_fetch_node_object(object, summary);
        p = end;
    }

    summary->parsed_nodes = g_mega_node_count;
}

int
mega_api_fetch_nodes(
    char *response_body,
    unsigned int response_body_size,
    mega_fetch_nodes_summary *summary,
    mega_api_result *result
)
{
    int ok;

    if (summary != 0) {
        memset(summary, 0, sizeof(*summary));
    }

    ok = mega_api_session_command("[{\"a\":\"f\",\"c\":1,\"r\":1}]",
        response_body, response_body_size, result);

    if (summary != 0 && response_body != 0 && response_body[0] != '\0') {
        summary->node_count = mega_count_token(response_body, "\"h\"");
        summary->root_count = mega_count_token(response_body, "\"t\":2");
        summary->incoming_count = mega_count_token(response_body, "\"t\":3");
        summary->rubbish_count = mega_count_token(response_body, "\"t\":4");
        summary->users_count = mega_count_token(response_body, "\"u\"");
        if (result != 0
            && result->http.body_bytes >= (int)response_body_size - 1)
        {
            summary->truncated = 1;
        }
        mega_parse_fetch_nodes(response_body, summary);
    }

    return ok;
}

int
mega_api_fetch_nodes_file(
    const WCHAR *response_file_path,
    mega_fetch_nodes_summary *summary,
    mega_api_result *result
)
{
    int ok;

    if (summary != 0) {
        memset(summary, 0, sizeof(*summary));
    }

    ok = mega_api_session_command_file("[{\"a\":\"f\",\"c\":1,\"r\":1}]",
        response_file_path, result);

    if (ok && summary != 0) {
        mega_parse_fetch_nodes_file_body(response_file_path, summary);
    }

    return ok;
}

int
mega_api_get_node_count(void)
{
    return g_mega_node_count;
}

int
mega_api_get_node(int index, mega_node_info *node)
{
    if (node == 0 || index < 0 || index >= g_mega_node_count) {
        return 0;
    }

    memset(node, 0, sizeof(*node));
    memcpy(node->handle, g_mega_nodes[index].handle, sizeof(node->handle));
    memcpy(node->parent, g_mega_nodes[index].parent, sizeof(node->parent));
    node->type = g_mega_nodes[index].type;
    node->size = g_mega_nodes[index].size;
    node->mtime = g_mega_nodes[index].mtime;
    memcpy(node->name, g_mega_nodes[index].name, sizeof(node->name));
    node->file_key_valid = g_mega_nodes[index].file_key_valid;
    memcpy(node->file_key, g_mega_nodes[index].file_key,
        sizeof(node->file_key));
    return 1;
}

int
mega_api_find_root_node(void)
{
    int i;

    for (i = 0; i < g_mega_node_count; ++i) {
        if (g_mega_nodes[i].type == 2) {
            return i;
        }
    }
    return -1;
}

int
mega_api_find_node_by_handle(const char *handle)
{
    int i;

    if (handle == 0 || handle[0] == '\0') {
        return -1;
    }

    for (i = 0; i < g_mega_node_count; ++i) {
        if (strcmp(g_mega_nodes[i].handle, handle) == 0) {
            return i;
        }
    }
    return -1;
}

int
mega_api_get_child_node(const char *parent, int child_offset, mega_node_info *node)
{
    int i;
    int seen;

    if (parent == 0 || parent[0] == '\0' || child_offset < 0) {
        return 0;
    }

    seen = 0;
    for (i = 0; i < g_mega_node_count; ++i) {
        if (strcmp(g_mega_nodes[i].parent, parent) == 0) {
            if (seen == child_offset) {
                return mega_api_get_node(i, node);
            }
            seen++;
        }
    }
    return 0;
}

static unsigned int
mega_api_current_unix_time(void)
{
    SYSTEMTIME st;
    FILETIME ft;
    unsigned __int64 ticks;

    GetSystemTime(&st);
    if (!SystemTimeToFileTime(&st, &ft)) {
        return 0;
    }
    ticks = ((unsigned __int64)ft.dwHighDateTime << 32)
        | (unsigned __int64)ft.dwLowDateTime;
    if (ticks < 116444736000000000Ui64) {
        return 0;
    }
    return (unsigned int)((ticks - 116444736000000000Ui64) / 10000000Ui64);
}

int
mega_api_add_local_folder_node(
    const char *handle,
    const char *parent,
    const char *name
)
{
    mega_node_entry *node;

    if (handle == 0 || handle[0] == '\0'
        || parent == 0 || parent[0] == '\0'
        || name == 0 || name[0] == '\0')
    {
        return 0;
    }
    if (mega_api_find_node_by_handle(handle) >= 0) {
        return mega_api_rename_local_node(handle, name);
    }
    if (!mega_nodes_ensure_capacity(g_mega_node_count + 1)) {
        return 0;
    }

    node = &g_mega_nodes[g_mega_node_count];
    memset(node, 0, sizeof(*node));
    _snprintf(node->handle, sizeof(node->handle), "%s", handle);
    node->handle[sizeof(node->handle) - 1] = '\0';
    _snprintf(node->parent, sizeof(node->parent), "%s", parent);
    node->parent[sizeof(node->parent) - 1] = '\0';
    _snprintf(node->name, sizeof(node->name), "%s", name);
    node->name[sizeof(node->name) - 1] = '\0';
    node->type = 1;
    node->mtime = mega_api_current_unix_time();
    g_mega_node_count++;
    return 1;
}

int
mega_api_rename_local_node(const char *handle, const char *new_name)
{
    int index;

    if (handle == 0 || handle[0] == '\0'
        || new_name == 0 || new_name[0] == '\0')
    {
        return 0;
    }
    index = mega_api_find_node_by_handle(handle);
    if (index < 0) {
        return 0;
    }
    _snprintf(g_mega_nodes[index].name, sizeof(g_mega_nodes[index].name),
        "%s", new_name);
    g_mega_nodes[index].name[sizeof(g_mega_nodes[index].name) - 1] = '\0';
    g_mega_nodes[index].mtime = mega_api_current_unix_time();
    return 1;
}

int
mega_api_remove_local_node(const char *handle)
{
    unsigned char *remove_flags;
    int read_index;
    int write_index;
    int removed;
    int changed;

    if (handle == 0 || handle[0] == '\0') {
        return 0;
    }

    remove_flags = (unsigned char *)LocalAlloc(LPTR,
        (unsigned int)g_mega_node_count);
    if (remove_flags == 0) {
        return 0;
    }

    for (read_index = 0; read_index < g_mega_node_count; ++read_index) {
        if (strcmp(g_mega_nodes[read_index].handle, handle) == 0) {
            remove_flags[read_index] = 1;
        }
    }

    do {
        changed = 0;
        for (read_index = 0; read_index < g_mega_node_count; ++read_index) {
            int parent_index;

            if (remove_flags[read_index]
                || g_mega_nodes[read_index].parent[0] == '\0')
            {
                continue;
            }
            parent_index = mega_api_find_node_by_handle(
                g_mega_nodes[read_index].parent);
            if (parent_index >= 0 && remove_flags[parent_index]) {
                remove_flags[read_index] = 1;
                changed = 1;
            }
        }
    } while (changed);

    write_index = 0;
    removed = 0;
    for (read_index = 0; read_index < g_mega_node_count; ++read_index) {
        if (remove_flags[read_index]) {
            mega_crypto_zero(&g_mega_nodes[read_index],
                sizeof(g_mega_nodes[read_index]));
            removed++;
            continue;
        }
        if (write_index != read_index) {
            memcpy(&g_mega_nodes[write_index], &g_mega_nodes[read_index],
                sizeof(g_mega_nodes[write_index]));
            mega_crypto_zero(&g_mega_nodes[read_index],
                sizeof(g_mega_nodes[read_index]));
        }
        write_index++;
    }
    g_mega_node_count = write_index;
    LocalFree((HLOCAL)remove_flags);
    return removed > 0;
}

static void
mega_set_counter_be64(unsigned char *dst, unsigned __int64 value)
{
    int i;

    for (i = 7; i >= 0; --i) {
        dst[i] = (unsigned char)(value & 0xff);
        value >>= 8;
    }
}

static int
mega_get_local_file_size(const WCHAR *path, unsigned __int64 *size)
{
    HANDLE file;
    DWORD high;
    DWORD low;

    if (size != 0) {
        *size = 0;
    }
    if (path == 0 || size == 0) {
        return 0;
    }
    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    high = 0;
    low = GetFileSize(file, &high);
    CloseHandle(file);
    *size = (((unsigned __int64)high) << 32) | (unsigned __int64)low;
    return 1;
}

static int
mega_set_file_pointer_u64(HANDLE file, unsigned __int64 offset)
{
    LONG high;
    DWORD low;

    high = (LONG)(offset >> 32);
    SetLastError(NO_ERROR);
    low = SetFilePointer(file, (LONG)(offset & 0xffffffffUL), &high,
        FILE_BEGIN);
    if (low == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        return 0;
    }
    return 1;
}

static int
mega_read_exact_at(
    HANDLE file,
    unsigned __int64 offset,
    unsigned char *buffer,
    unsigned int bytes
)
{
    DWORD read_bytes;

    if (!mega_set_file_pointer_u64(file, offset)) {
        return 0;
    }
    read_bytes = 0;
    return ReadFile(file, buffer, bytes, &read_bytes, 0)
        && read_bytes == bytes;
}

static unsigned int
mega_crc32_update(
    unsigned int crc,
    const unsigned char *data,
    unsigned int data_len
)
{
    unsigned int i;
    unsigned int bit;

    for (i = 0; i < data_len; ++i) {
        crc ^= data[i];
        for (bit = 0; bit < 8; ++bit) {
            if ((crc & 1U) != 0) {
                crc = (crc >> 1) ^ 0xedb88320UL;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

static void
mega_store_be32(unsigned char *dst, unsigned int value)
{
    dst[0] = (unsigned char)((value >> 24) & 0xff);
    dst[1] = (unsigned char)((value >> 16) & 0xff);
    dst[2] = (unsigned char)((value >> 8) & 0xff);
    dst[3] = (unsigned char)(value & 0xff);
}

static int mega_encrypt_attr_json(
    const char *json,
    const unsigned char *key,
    char *attr_b64,
    unsigned int attr_b64_size
);

static int
mega_encrypt_attr_name(
    const char *name,
    const unsigned char *key,
    char *attr_b64,
    unsigned int attr_b64_size
)
{
    char escaped[192];
    char json[256];

    if (name == 0 || key == 0 || attr_b64 == 0 || attr_b64_size == 0) {
        return 0;
    }
    if (!mega_json_escape_string(name, escaped, sizeof(escaped))) {
        return 0;
    }
    _snprintf(json, sizeof(json), "MEGA{\"n\":\"%s\"}", escaped);
    json[sizeof(json) - 1] = '\0';
    return mega_encrypt_attr_json(json, key, attr_b64, attr_b64_size);
}

static int
mega_encrypt_attr_json(
    const char *json,
    const unsigned char *key,
    char *attr_b64,
    unsigned int attr_b64_size
)
{
    unsigned char attr[512];
    unsigned char prev[16];
    unsigned int plain_len;
    unsigned int padded_len;
    unsigned int i;
    unsigned int b;

    if (json == 0 || key == 0 || attr_b64 == 0 || attr_b64_size == 0) {
        return 0;
    }

    plain_len = (unsigned int)strlen(json);
    if (plain_len >= sizeof(attr)) {
        return 0;
    }
    memcpy(attr, json, plain_len + 1);
    padded_len = (plain_len + 15) & ~15U;
    if (padded_len > sizeof(attr)) {
        return 0;
    }
    memset(attr + plain_len, 0, padded_len - plain_len);
    memset(prev, 0, sizeof(prev));

    for (i = 0; i < padded_len; i += 16) {
        for (b = 0; b < 16; ++b) {
            attr[i + b] ^= prev[b];
        }
        if (!mega_crypto_aes128_encrypt_block(key, attr + i)) {
            mega_crypto_zero(attr, sizeof(attr));
            return 0;
        }
        memcpy(prev, attr + i, 16);
    }

    i = mega_crypto_base64url_encode(attr, (int)padded_len,
        attr_b64, attr_b64_size);
    mega_crypto_zero(attr, sizeof(attr));
    mega_crypto_zero(prev, sizeof(prev));
    return i;
}

static int
mega_encrypt_upload_attrs(
    const char *name,
    const char *fingerprint,
    const unsigned char *key,
    char *attr_b64,
    unsigned int attr_b64_size
)
{
    char escaped[192];
    char escaped_fp[96];
    char json[384];

    if (name == 0 || key == 0 || attr_b64 == 0 || attr_b64_size == 0) {
        return 0;
    }
    if (!mega_json_escape_string(name, escaped, sizeof(escaped))) {
        return 0;
    }
    if (fingerprint != 0 && fingerprint[0] != '\0') {
        if (!mega_json_escape_string(fingerprint, escaped_fp,
            sizeof(escaped_fp)))
        {
            return 0;
        }
        _snprintf(json, sizeof(json), "MEGA{\"n\":\"%s\",\"c\":\"%s\"}",
            escaped, escaped_fp);
    } else {
        _snprintf(json, sizeof(json), "MEGA{\"n\":\"%s\"}", escaped);
    }
    json[sizeof(json) - 1] = '\0';
    return mega_encrypt_attr_json(json, key, attr_b64, attr_b64_size);
}

static void
mega_make_node_attr_key(
    int node_type,
    const unsigned char *raw_key,
    unsigned char *attr_key
)
{
    int i;

    if (node_type == 0) {
        for (i = 0; i < 16; ++i) {
            attr_key[i] = (unsigned char)(raw_key[i] ^ raw_key[i + 16]);
        }
    } else {
        memcpy(attr_key, raw_key, 16);
    }
}

static int
mega_encrypt_node_key(
    const unsigned char *raw_key,
    int raw_key_len,
    char *key_b64,
    unsigned int key_b64_size
)
{
    unsigned char encrypted_key[32];
    int i;

    if (raw_key == 0 || key_b64 == 0
        || (raw_key_len != 16 && raw_key_len != 32)
        || !g_mega_session.master_key_valid)
    {
        return 0;
    }
    memcpy(encrypted_key, raw_key, (unsigned int)raw_key_len);
    for (i = 0; i < raw_key_len; i += 16) {
        if (!mega_crypto_aes128_encrypt_block(g_mega_session.master_key,
            encrypted_key + i))
        {
            mega_crypto_zero(encrypted_key, sizeof(encrypted_key));
            return 0;
        }
    }
    i = mega_crypto_base64url_encode(encrypted_key, raw_key_len,
        key_b64, key_b64_size);
    mega_crypto_zero(encrypted_key, sizeof(encrypted_key));
    return i;
}

static int
mega_response_error_code(const char *response_body)
{
    const char *p;
    int sign;
    int value;

    if (response_body == 0 || response_body[0] != '[') {
        return 0;
    }
    p = response_body + 1;
    sign = 1;
    if (*p == '-') {
        sign = -1;
        p++;
    }
    if (*p < '0' || *p > '9') {
        return 0;
    }
    value = 0;
    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        p++;
    }
    return value * sign;
}

static int
mega_api_check_command_response(const char *response_body, mega_api_result *result)
{
    int code;

    code = mega_response_error_code(response_body);
    if (code < 0) {
        char line[64];

        _snprintf(line, sizeof(line), "MEGA API error: %d", code);
        line[sizeof(line) - 1] = '\0';
        mega_api_set_error(result, line);
        return 0;
    }
    return 1;
}

static int
mega_read_file_chunk(
    HANDLE file,
    unsigned char *buffer,
    unsigned int chunk_size
)
{
    unsigned int total;
    DWORD read_bytes;

    total = 0;
    while (total < chunk_size) {
        read_bytes = 0;
        if (!ReadFile(file, buffer + total, chunk_size - total,
            &read_bytes, 0))
        {
            return 0;
        }
        if (read_bytes == 0) {
            return 0;
        }
        total += read_bytes;
    }
    return 1;
}

static void
mega_upload_crc_update(
    unsigned char *upload_crc,
    const unsigned char *data,
    unsigned int data_len,
    unsigned __int64 offset
)
{
    unsigned int i;

    for (i = 0; i < data_len; ++i) {
        upload_crc[(unsigned int)((offset + i) % MEGA_UPLOAD_CRC_SIZE)]
            ^= data[i];
    }
}

static int
mega_encrypt_upload_chunk(
    const unsigned char *transfer_key,
    const unsigned char *iv,
    unsigned char *buffer,
    unsigned int chunk_size,
    unsigned __int64 chunk_start,
    unsigned char *chunk_mac
)
{
    unsigned int padded_len;
    unsigned int offset;
    unsigned int b;

    memcpy(chunk_mac, iv, 8);
    memcpy(chunk_mac + 8, iv, 8);
    padded_len = (chunk_size + 15U) & ~15U;
    if (padded_len > chunk_size) {
        memset(buffer + chunk_size, 0, padded_len - chunk_size);
    }

    for (offset = 0; offset < padded_len; offset += 16) {
        for (b = 0; b < 16; ++b) {
            chunk_mac[b] ^= buffer[offset + b];
        }
        if (!mega_crypto_aes128_encrypt_block(transfer_key, chunk_mac)) {
            return 0;
        }
    }

    for (offset = 0; offset < chunk_size; offset += 16) {
        unsigned char stream[16];
        unsigned int available;

        available = chunk_size - offset;
        if (available > 16) {
            available = 16;
        }
        memcpy(stream, iv, 8);
        mega_set_counter_be64(stream + 8, (chunk_start + offset) / 16);
        if (!mega_crypto_aes128_encrypt_block(transfer_key, stream)) {
            mega_crypto_zero(stream, sizeof(stream));
            return 0;
        }
        for (b = 0; b < available; ++b) {
            buffer[offset + b] ^= stream[b];
        }
        mega_crypto_zero(stream, sizeof(stream));
    }

    return 1;
}

static int
mega_encrypt_upload_file(
    const WCHAR *plain_path,
    const WCHAR *encrypted_path,
    unsigned char *raw_key,
    unsigned int raw_key_size,
    unsigned __int64 *plain_size,
    char *upload_crc_b64,
    unsigned int upload_crc_b64_size
)
{
    HANDLE in_file;
    HANDLE out_file;
    unsigned char transfer_key[16];
    unsigned char iv[8];
    unsigned char fold_mac[16];
    unsigned char upload_crc[MEGA_UPLOAD_CRC_SIZE];
    unsigned char *buffer;
    unsigned __int64 remaining;
    unsigned __int64 position;
    unsigned long next_chunk_size;
    int ok;
    int i;

    if (plain_path == 0 || encrypted_path == 0 || raw_key == 0
        || raw_key_size < 32 || upload_crc_b64 == 0
        || upload_crc_b64_size == 0)
    {
        return 0;
    }
    upload_crc_b64[0] = '\0';
    if (!mega_get_local_file_size(plain_path, plain_size)) {
        return 0;
    }
    if (!mega_crypto_random_bytes(transfer_key, sizeof(transfer_key))
        || !mega_crypto_random_bytes(iv, sizeof(iv)))
    {
        return 0;
    }

    memset(fold_mac, 0, sizeof(fold_mac));
    memset(upload_crc, 0, sizeof(upload_crc));
    buffer = (unsigned char *)LocalAlloc(LPTR, MEGA_UPLOAD_CHUNK_MAX + 16);
    if (buffer == 0) {
        mega_crypto_zero(transfer_key, sizeof(transfer_key));
        mega_crypto_zero(iv, sizeof(iv));
        return 0;
    }

    in_file = CreateFile(plain_path, GENERIC_READ, FILE_SHARE_READ, 0,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (in_file == INVALID_HANDLE_VALUE) {
        LocalFree((HLOCAL)buffer);
        mega_crypto_zero(transfer_key, sizeof(transfer_key));
        mega_crypto_zero(iv, sizeof(iv));
        mega_crypto_zero(fold_mac, sizeof(fold_mac));
        mega_crypto_zero(upload_crc, sizeof(upload_crc));
        return 0;
    }
    out_file = CreateFile(encrypted_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (out_file == INVALID_HANDLE_VALUE) {
        CloseHandle(in_file);
        LocalFree((HLOCAL)buffer);
        mega_crypto_zero(transfer_key, sizeof(transfer_key));
        mega_crypto_zero(iv, sizeof(iv));
        mega_crypto_zero(fold_mac, sizeof(fold_mac));
        mega_crypto_zero(upload_crc, sizeof(upload_crc));
        return 0;
    }

    ok = 1;
    remaining = *plain_size;
    position = 0;
    next_chunk_size = MEGA_UPLOAD_CHUNK_BASE;
    while (remaining > 0) {
        unsigned int chunk_size;
        unsigned char chunk_mac[16];
        DWORD written;

        chunk_size = remaining < (unsigned __int64)next_chunk_size
            ? (unsigned int)remaining
            : (unsigned int)next_chunk_size;
        if (!mega_read_file_chunk(in_file, buffer, chunk_size)
            || !mega_encrypt_upload_chunk(transfer_key, iv, buffer,
                chunk_size, position, chunk_mac))
        {
            mega_crypto_zero(chunk_mac, sizeof(chunk_mac));
            ok = 0;
            break;
        }

        for (i = 0; i < 16; ++i) {
            fold_mac[i] ^= chunk_mac[i];
        }
        if (!mega_crypto_aes128_encrypt_block(transfer_key, fold_mac)) {
            mega_crypto_zero(chunk_mac, sizeof(chunk_mac));
            ok = 0;
            break;
        }
        mega_upload_crc_update(upload_crc, buffer, chunk_size, position);

        written = 0;
        if (!WriteFile(out_file, buffer, chunk_size, &written, 0)
            || written != chunk_size)
        {
            mega_crypto_zero(chunk_mac, sizeof(chunk_mac));
            ok = 0;
            break;
        }

        mega_crypto_zero(chunk_mac, sizeof(chunk_mac));
        position += chunk_size;
        remaining -= chunk_size;
        if (next_chunk_size < MEGA_UPLOAD_CHUNK_MAX) {
            next_chunk_size += MEGA_UPLOAD_CHUNK_BASE;
            if (next_chunk_size > MEGA_UPLOAD_CHUNK_MAX) {
                next_chunk_size = MEGA_UPLOAD_CHUNK_MAX;
            }
        }
    }

    CloseHandle(out_file);
    CloseHandle(in_file);

    if (ok) {
        unsigned char meta[8];

        for (i = 0; i < 4; ++i) {
            meta[i] = (unsigned char)(fold_mac[i] ^ fold_mac[i + 4]);
            meta[i + 4] = (unsigned char)(fold_mac[i + 8] ^ fold_mac[i + 12]);
        }
        memcpy(raw_key + 16, iv, 8);
        memcpy(raw_key + 24, meta, 8);
        for (i = 0; i < 16; ++i) {
            raw_key[i] = (unsigned char)(transfer_key[i] ^ raw_key[i + 16]);
        }
        if (!mega_crypto_base64url_encode(upload_crc, sizeof(upload_crc),
            upload_crc_b64, upload_crc_b64_size))
        {
            ok = 0;
        }
        mega_crypto_zero(meta, sizeof(meta));
    }
    if (!ok) {
        DeleteFile(encrypted_path);
    }

    mega_crypto_zero(transfer_key, sizeof(transfer_key));
    mega_crypto_zero(iv, sizeof(iv));
    mega_crypto_zero(fold_mac, sizeof(fold_mac));
    mega_crypto_zero(upload_crc, sizeof(upload_crc));
    mega_crypto_zero(buffer, MEGA_UPLOAD_CHUNK_MAX + 16);
    LocalFree((HLOCAL)buffer);
    return ok;
}

static int
mega_extract_upload_token(
    const char *response_body,
    unsigned int response_body_len,
    char *token,
    unsigned int token_size
)
{
    const char *p;
    const char *end;
    unsigned int len;

    if (response_body == 0 || token == 0 || token_size == 0) {
        return 0;
    }
    token[0] = '\0';
    if (response_body_len == 36) {
        return mega_crypto_base64url_encode(
            (const unsigned char *)response_body,
            36,
            token,
            token_size);
    }
    if (mega_json_extract_string(response_body, "p", token, token_size)) {
        unsigned char decoded[40];
        int decoded_len;

        decoded_len = mega_crypto_base64url_decode(token, decoded,
            sizeof(decoded));
        if (decoded_len == 36) {
            char normalized[64];

            if (mega_crypto_base64url_encode(decoded, decoded_len,
                normalized, sizeof(normalized)))
            {
                _snprintf(token, token_size, "%s", normalized);
                token[token_size - 1] = '\0';
            }
        }
        return token[0] != '\0';
    }
    p = response_body;
    while (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t') {
        p++;
    }
    if (*p == '[') {
        p++;
        while (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t') {
            p++;
        }
    }
    if (*p == '"') {
        p++;
        end = strchr(p, '"');
    } else {
        end = p;
        while (*end != '\0' && *end != '\r' && *end != '\n'
            && *end != ' ' && *end != '\t')
        {
            end++;
        }
    }
    if (end == 0 || end <= p) {
        return 0;
    }
    len = (unsigned int)(end - p);
    if (len >= token_size) {
        len = token_size - 1;
    }
    memcpy(token, p, len);
    token[len] = '\0';
    {
        unsigned char decoded[40];
        int decoded_len;

        decoded_len = mega_crypto_base64url_decode(token, decoded,
            sizeof(decoded));
        if (decoded_len == 36) {
            char normalized[64];

            if (mega_crypto_base64url_encode(decoded, decoded_len,
                normalized, sizeof(normalized)))
            {
                _snprintf(token, token_size, "%s", normalized);
                token[token_size - 1] = '\0';
            }
        }
    }
    return token[0] != '\0';
}

static int
mega_serialize_u64(unsigned char *dst, unsigned __int64 value)
{
    unsigned char count;

    if (dst == 0) {
        return 0;
    }
    count = 0;
    while (value != 0) {
        dst[++count] = (unsigned char)(value & 0xff);
        value >>= 8;
    }
    dst[0] = count;
    return (int)count + 1;
}

static int
mega_make_upload_fingerprint(
    const WCHAR *local_path,
    char *fingerprint,
    unsigned int fingerprint_size
)
{
    HANDLE file;
    FILETIME local_ft;
    unsigned char raw[32];
    unsigned __int64 file_size;
    unsigned int used;
    unsigned __int64 ticks;
    unsigned __int64 mtime;
    DWORD high;
    DWORD low;
    int ok;

    if (fingerprint == 0 || fingerprint_size == 0) {
        return 0;
    }
    fingerprint[0] = '\0';
    if (local_path == 0 || local_path[0] == L'\0') {
        return 0;
    }

    memset(raw, 0, sizeof(raw));
    file = CreateFile(local_path, GENERIC_READ, FILE_SHARE_READ, 0,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    memset(&local_ft, 0, sizeof(local_ft));
    GetFileTime(file, 0, 0, &local_ft);
    high = 0;
    SetLastError(NO_ERROR);
    low = GetFileSize(file, &high);
    if (low == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        CloseHandle(file);
        return 0;
    }
    file_size = (((unsigned __int64)high) << 32) | (unsigned __int64)low;

    ok = 1;
    if (file_size <= 16) {
        DWORD read_bytes;

        read_bytes = 0;
        if (!mega_set_file_pointer_u64(file, 0)
            || !ReadFile(file, raw, (DWORD)file_size, &read_bytes, 0)
            || read_bytes != (DWORD)file_size)
        {
            ok = 0;
        }
    } else if (file_size <= MEGA_FINGERPRINT_MAXFULL) {
        unsigned char *buffer;
        unsigned int i;

        buffer = (unsigned char *)LocalAlloc(LPTR, MEGA_FINGERPRINT_MAXFULL);
        if (buffer == 0) {
            ok = 0;
        } else if (!mega_read_exact_at(file, 0, buffer, (unsigned int)file_size)) {
            ok = 0;
        } else {
            for (i = 0; i < 4; ++i) {
                unsigned int begin;
                unsigned int end;
                unsigned int crc;

                begin = (unsigned int)((file_size * i) / 4);
                end = (unsigned int)((file_size * (i + 1)) / 4);
                crc = mega_crc32_update(0xffffffffUL, buffer + begin,
                    end - begin) ^ 0xffffffffUL;
                mega_store_be32(raw + i * 4, crc);
            }
        }
        if (buffer != 0) {
            mega_crypto_zero(buffer, MEGA_FINGERPRINT_MAXFULL);
            LocalFree((HLOCAL)buffer);
        }
    } else {
        unsigned char block[MEGA_FINGERPRINT_SPARSE_BLOCK];
        unsigned int lane;
        unsigned int block_index;

        for (lane = 0; lane < 4 && ok; ++lane) {
            unsigned int crc;

            crc = 0xffffffffUL;
            for (block_index = 0;
                block_index < MEGA_FINGERPRINT_SPARSE_BLOCKS;
                ++block_index)
            {
                unsigned __int64 sample;
                unsigned __int64 offset;

                sample = (unsigned __int64)lane
                    * MEGA_FINGERPRINT_SPARSE_BLOCKS + block_index;
                offset = ((file_size - MEGA_FINGERPRINT_SPARSE_BLOCK)
                    * sample) / MEGA_FINGERPRINT_SPARSE_DENOM;
                if (!mega_read_exact_at(file, offset, block,
                    MEGA_FINGERPRINT_SPARSE_BLOCK))
                {
                    ok = 0;
                    break;
                }
                crc = mega_crc32_update(crc, block,
                    MEGA_FINGERPRINT_SPARSE_BLOCK);
            }
            if (ok) {
                crc ^= 0xffffffffUL;
                mega_store_be32(raw + lane * 4, crc);
            }
        }
        mega_crypto_zero(block, sizeof(block));
    }

    CloseHandle(file);
    if (!ok) {
        mega_crypto_zero(raw, sizeof(raw));
        return 0;
    }

    ticks = ((unsigned __int64)local_ft.dwHighDateTime << 32)
        | (unsigned __int64)local_ft.dwLowDateTime;
    if (ticks > 116444736000000000Ui64) {
        mtime = (ticks - 116444736000000000Ui64) / 10000000Ui64;
    } else {
        mtime = 0;
    }
    used = 16 + (unsigned int)mega_serialize_u64(raw + 16, mtime);
    return mega_crypto_base64url_encode(raw, (int)used,
        fingerprint, fingerprint_size);
}

int
mega_api_upload_file_update(
    const char *existing_handle,
    const char *parent_handle,
    const char *name,
    const WCHAR *local_path,
    const WCHAR *encrypted_path,
    char *new_handle,
    unsigned int new_handle_size,
    mega_api_result *result
)
{
    unsigned char raw_key[32];
    unsigned __int64 plain_size;
    char command[4096];
    char response_body[4096];
    char upload_url[1024];
    char upload_url_sized[1100];
    char upload_token[128];
    char attr_b64[512];
    char key_b64[128];
    char fingerprint[96];
    char upload_crc_b64[32];
    char escaped_token[160];
    unsigned char attr_key[16];
    unsigned int upload_body_len;
    int ok;

    if (new_handle != 0 && new_handle_size > 0) {
        new_handle[0] = '\0';
    }
    if (parent_handle == 0 || parent_handle[0] == '\0'
        || name == 0 || name[0] == '\0'
        || local_path == 0 || encrypted_path == 0)
    {
        mega_api_set_error(result, "invalid upload arguments");
        return 0;
    }
    if (!g_mega_session.master_key_valid) {
        mega_api_set_error(result, "missing MEGA master key");
        return 0;
    }

    memset(raw_key, 0, sizeof(raw_key));
    if (!mega_encrypt_upload_file(local_path, encrypted_path, raw_key,
        sizeof(raw_key), &plain_size, upload_crc_b64,
        sizeof(upload_crc_b64)))
    {
        mega_api_set_error(result, "could not encrypt upload file");
        return 0;
    }

    fingerprint[0] = '\0';
    mega_make_upload_fingerprint(local_path, fingerprint, sizeof(fingerprint));
    mega_make_node_attr_key(0, raw_key, attr_key);
    if (!mega_encrypt_upload_attrs(name, fingerprint, attr_key,
        attr_b64, sizeof(attr_b64)))
    {
        DeleteFile(encrypted_path);
        mega_crypto_zero(attr_key, sizeof(attr_key));
        mega_crypto_zero(raw_key, sizeof(raw_key));
        mega_api_set_error(result, "could not encrypt upload attributes");
        return 0;
    }
    mega_crypto_zero(attr_key, sizeof(attr_key));

    if (!mega_encrypt_node_key(raw_key, sizeof(raw_key), key_b64, sizeof(key_b64)))
    {
        DeleteFile(encrypted_path);
        mega_crypto_zero(raw_key, sizeof(raw_key));
        mega_api_set_error(result, "could not encode upload key");
        return 0;
    }

    _snprintf(command, sizeof(command),
        "[{\"a\":\"u\",\"ssl\":2,\"v\":3,\"s\":%lu}]",
        (unsigned long)plain_size);
    command[sizeof(command) - 1] = '\0';
    response_body[0] = '\0';
    ok = mega_api_session_command(command, response_body,
        sizeof(response_body), result);
    if (!ok || !mega_json_extract_string(response_body, "p",
        upload_url, sizeof(upload_url)))
    {
        DeleteFile(encrypted_path);
        mega_crypto_zero(raw_key, sizeof(raw_key));
        if (ok) {
            mega_api_set_error(result, "MEGA upload URL not found");
        }
        return 0;
    }

    _snprintf(upload_url_sized, sizeof(upload_url_sized), "%s/0?d=%s",
        upload_url, upload_crc_b64);
    upload_url_sized[sizeof(upload_url_sized) - 1] = '\0';

    response_body[0] = '\0';
    if (!mega_http_upload_file_to_url(upload_url_sized, encrypted_path,
        response_body, sizeof(response_body), result != 0 ? &result->http : 0))
    {
        DeleteFile(encrypted_path);
        mega_crypto_zero(raw_key, sizeof(raw_key));
        mega_api_set_error(result, result != 0 && result->http.error[0] != '\0'
            ? result->http.error
            : "encrypted upload failed");
        return 0;
    }
    DeleteFile(encrypted_path);

    upload_body_len = result != 0 ? (unsigned int)result->http.body_bytes : 0;
    if (!mega_extract_upload_token(response_body, upload_body_len,
        upload_token, sizeof(upload_token))
        || !mega_json_escape_string(upload_token, escaped_token,
            sizeof(escaped_token)))
    {
        mega_crypto_zero(raw_key, sizeof(raw_key));
        mega_api_set_error(result, "MEGA upload token not found");
        return 0;
    }

    if (existing_handle != 0 && existing_handle[0] != '\0') {
        _snprintf(command, sizeof(command),
            "[{\"a\":\"p\",\"v\":4,\"t\":\"%s\",\"sm\":1,\"n\":[{\"h\":\"%s\",\"t\":0,\"a\":\"%s\",\"k\":\"%s\",\"ov\":\"%s\"}]}]",
            parent_handle, escaped_token, attr_b64, key_b64, existing_handle);
    } else {
        _snprintf(command, sizeof(command),
            "[{\"a\":\"p\",\"v\":4,\"t\":\"%s\",\"sm\":1,\"n\":[{\"h\":\"%s\",\"t\":0,\"a\":\"%s\",\"k\":\"%s\"}]}]",
            parent_handle, escaped_token, attr_b64, key_b64);
    }
    command[sizeof(command) - 1] = '\0';
    response_body[0] = '\0';
    if (!mega_api_session_command(command, response_body,
        sizeof(response_body), result))
    {
        mega_crypto_zero(raw_key, sizeof(raw_key));
        return 0;
    }
    ok = mega_api_check_command_response(response_body, result);
    if (!ok) {
        if (result != 0) {
            char detail[160];

            _snprintf(detail, sizeof(detail),
                "%s; upload diag token=%u body=%u attr=%u key=%u parent=%u crc=%u ov=%u",
                result->error,
                (unsigned int)strlen(upload_token),
                upload_body_len,
                (unsigned int)strlen(attr_b64),
                (unsigned int)strlen(key_b64),
                parent_handle != 0 ? (unsigned int)strlen(parent_handle) : 0U,
                (unsigned int)strlen(upload_crc_b64),
                existing_handle != 0 && existing_handle[0] != '\0' ? 1U : 0U);
            detail[sizeof(detail) - 1] = '\0';
            mega_api_set_error(result, detail);
        }
        mega_crypto_zero(raw_key, sizeof(raw_key));
        return 0;
    }
    if (new_handle != 0 && new_handle_size > 0) {
        mega_json_extract_string(response_body, "h", new_handle,
            new_handle_size);
        if (new_handle[0] == '\0') {
            if (existing_handle != 0 && existing_handle[0] != '\0') {
                _snprintf(new_handle, new_handle_size, "%s", existing_handle);
                new_handle[new_handle_size - 1] = '\0';
            }
        }
    }

    mega_crypto_zero(raw_key, sizeof(raw_key));
    return 1;
}

int
mega_api_create_folder(
    const char *parent_handle,
    const char *name,
    char *new_handle,
    unsigned int new_handle_size,
    mega_api_result *result
)
{
    unsigned char raw_key[16];
    unsigned char attr_key[16];
    unsigned char handle_seed[6];
    char temp_handle[16];
    char attr_b64[512];
    char key_b64[128];
    char command[2048];
    char response_body[4096];
    int ok;

    if (new_handle != 0 && new_handle_size > 0) {
        new_handle[0] = '\0';
    }
    if (parent_handle == 0 || parent_handle[0] == '\0'
        || name == 0 || name[0] == '\0')
    {
        mega_api_set_error(result, "invalid create folder arguments");
        return 0;
    }
    if (!mega_crypto_random_bytes(raw_key, sizeof(raw_key))
        || !mega_crypto_random_bytes(handle_seed, sizeof(handle_seed)))
    {
        mega_api_set_error(result, "could not create folder randomness");
        return 0;
    }
    if (!mega_crypto_base64url_encode(handle_seed, sizeof(handle_seed),
        temp_handle, sizeof(temp_handle)))
    {
        mega_crypto_zero(raw_key, sizeof(raw_key));
        mega_crypto_zero(handle_seed, sizeof(handle_seed));
        mega_api_set_error(result, "could not encode folder handle");
        return 0;
    }

    mega_make_node_attr_key(1, raw_key, attr_key);
    if (!mega_encrypt_attr_name(name, attr_key, attr_b64, sizeof(attr_b64))
        || !mega_encrypt_node_key(raw_key, sizeof(raw_key), key_b64, sizeof(key_b64)))
    {
        mega_crypto_zero(raw_key, sizeof(raw_key));
        mega_crypto_zero(attr_key, sizeof(attr_key));
        mega_crypto_zero(handle_seed, sizeof(handle_seed));
        mega_api_set_error(result, "could not encrypt folder metadata");
        return 0;
    }

    _snprintf(command, sizeof(command),
        "[{\"a\":\"p\",\"v\":4,\"t\":\"%s\",\"sm\":1,\"n\":[{\"h\":\"%s\",\"t\":1,\"a\":\"%s\",\"k\":\"%s\"}]}]",
        parent_handle, temp_handle, attr_b64, key_b64);
    command[sizeof(command) - 1] = '\0';
    response_body[0] = '\0';
    ok = mega_api_session_command(command, response_body,
        sizeof(response_body), result);
    if (ok) {
        ok = mega_api_check_command_response(response_body, result);
    }
    if (ok && !strstr(response_body, "\"h\"")) {
        mega_api_set_error(result, "create folder returned no node handle");
        ok = 0;
    }
    if (ok && new_handle != 0 && new_handle_size > 0) {
        mega_json_extract_string(response_body, "h", new_handle, new_handle_size);
    }

    mega_crypto_zero(raw_key, sizeof(raw_key));
    mega_crypto_zero(attr_key, sizeof(attr_key));
    mega_crypto_zero(handle_seed, sizeof(handle_seed));
    return ok;
}

int
mega_api_rename_node(
    const char *node_handle,
    const char *new_name,
    mega_api_result *result
)
{
    mega_node_entry *node;
    unsigned char attr_key[16];
    char attr_b64[512];
    char command[1024];
    char response_body[2048];
    int node_index;
    int ok;

    if (node_handle == 0 || node_handle[0] == '\0'
        || new_name == 0 || new_name[0] == '\0')
    {
        mega_api_set_error(result, "invalid rename arguments");
        return 0;
    }
    node_index = mega_api_find_node_by_handle(node_handle);
    if (node_index < 0 || node_index >= g_mega_node_count) {
        mega_api_set_error(result, "rename failed: node not found");
        return 0;
    }
    node = &g_mega_nodes[node_index];
    if (node->type == 0 && !node->file_key_valid) {
        mega_api_set_error(result, "rename failed: missing file key");
        return 0;
    }
    if (node->type != 0 && node->name[0] == '\0') {
        mega_api_set_error(result, "rename failed: missing folder key");
        return 0;
    }

    mega_make_node_attr_key(node->type, node->file_key, attr_key);
    if (!mega_encrypt_attr_name(new_name, attr_key, attr_b64, sizeof(attr_b64))) {
        mega_crypto_zero(attr_key, sizeof(attr_key));
        mega_api_set_error(result, "rename failed: could not encrypt name");
        return 0;
    }

    _snprintf(command, sizeof(command),
        "[{\"a\":\"a\",\"n\":\"%s\",\"at\":\"%s\"}]",
        node_handle, attr_b64);
    command[sizeof(command) - 1] = '\0';
    response_body[0] = '\0';
    ok = mega_api_session_command(command, response_body,
        sizeof(response_body), result);
    if (ok) {
        ok = mega_api_check_command_response(response_body, result);
    }
    mega_crypto_zero(attr_key, sizeof(attr_key));
    return ok;
}

int
mega_api_delete_node(
    const char *node_handle,
    mega_api_result *result
)
{
    char command[128];
    char response_body[1024];
    int ok;

    if (node_handle == 0 || node_handle[0] == '\0') {
        mega_api_set_error(result, "invalid delete arguments");
        return 0;
    }
    _snprintf(command, sizeof(command),
        "[{\"a\":\"d\",\"n\":\"%s\"}]",
        node_handle);
    command[sizeof(command) - 1] = '\0';
    response_body[0] = '\0';
    ok = mega_api_session_command(command, response_body,
        sizeof(response_body), result);
    if (ok) {
        ok = mega_api_check_command_response(response_body, result);
    }
    return ok;
}

int
mega_api_get_download_url(
    const char *node_handle,
    char *url,
    unsigned int url_size,
    mega_api_result *result
)
{
    char command[128];
    char response_body[4096];
    int ok;

    if (url == 0 || url_size == 0) {
        mega_api_set_error(result, "invalid download URL buffer");
        return 0;
    }
    url[0] = '\0';

    if (node_handle == 0 || node_handle[0] == '\0') {
        mega_api_set_error(result, "invalid file handle");
        return 0;
    }

    _snprintf(command, sizeof(command),
        "[{\"a\":\"g\",\"g\":1,\"ssl\":2,\"n\":\"%s\"}]",
        node_handle);
    command[sizeof(command) - 1] = '\0';

    response_body[0] = '\0';
    ok = mega_api_session_command(command, response_body,
        sizeof(response_body), result);
    if (!ok) {
        return 0;
    }

    if (!mega_json_extract_string(response_body, "g", url, url_size)) {
        mega_api_set_error(result, "MEGA download URL not found");
        return 0;
    }

    return 1;
}
