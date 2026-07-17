#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "mega_http.h"
#include "mega_crypto.h"

typedef struct wm_https_result {
    int ok;
    int tls_error;
    int wsa_error;
    int http_bytes;
} wm_https_result;

typedef struct wm_tls_connection wm_tls_connection;

typedef int (*wm_tls_open_fn)(
    const char *host,
    unsigned short port,
    const char *sni_host,
    wm_tls_connection **out_conn,
    wm_https_result *result
);

typedef int (*wm_tls_write_fn)(
    wm_tls_connection *conn,
    const void *data,
    unsigned int data_len,
    unsigned int *bytes_written,
    wm_https_result *result
);

typedef int (*wm_tls_read_fn)(
    wm_tls_connection *conn,
    void *buffer,
    unsigned int buffer_size,
    unsigned int *bytes_read,
    wm_https_result *result
);

typedef void (*wm_tls_close_fn)(wm_tls_connection *conn);

typedef struct mega_tls_api {
    HMODULE dll;
    wm_tls_open_fn open;
    wm_tls_write_fn write;
    wm_tls_read_fn read;
    wm_tls_close_fn close;
} mega_tls_api;

static const char *mega_find_body_start(const char *response);
static int mega_parse_status_code(const char *response);
static void mega_copy_status_line(const char *response, char *out, unsigned int out_size);
static void mega_copy_headers(const char *response, char *out, unsigned int out_size);

#define MEGA_HTTP_INITIAL_HEADER_LIMIT 8192U

static mega_http_progress_fn g_progress_callback;
static void *g_progress_user_data;

void
mega_http_set_progress_callback(
    mega_http_progress_fn callback,
    void *user_data
)
{
    g_progress_callback = callback;
    g_progress_user_data = user_data;
}

void
mega_http_progress_message(const char *message)
{
    if (g_progress_callback != 0 && message != 0) {
        g_progress_callback(message, g_progress_user_data);
    }
}

static void
mega_http_progress(const char *message)
{
    mega_http_progress_message(message);
}

static void
mega_result_clear(mega_http_result *result)
{
    if (result != 0) {
        memset(result, 0, sizeof(*result));
    }
}

static void
mega_result_error(mega_http_result *result, const char *message)
{
    if (result != 0 && message != 0) {
        _snprintf(result->error, sizeof(result->error), "%s", message);
        result->error[sizeof(result->error) - 1] = '\0';
    }
}

static int
mega_load_tls(mega_tls_api *api, mega_http_result *result)
{
    memset(api, 0, sizeof(*api));

    api->dll = LoadLibrary(TEXT("wm_https.dll"));
    if (api->dll == 0) {
        mega_result_error(result, "wm_https.dll not found");
        return 0;
    }

    api->open = (wm_tls_open_fn)GetProcAddressA(api->dll, "wm_tls_open");
    api->write = (wm_tls_write_fn)GetProcAddressA(api->dll, "wm_tls_write");
    api->read = (wm_tls_read_fn)GetProcAddressA(api->dll, "wm_tls_read");
    api->close = (wm_tls_close_fn)GetProcAddressA(api->dll, "wm_tls_close");

    if (api->open == 0 || api->write == 0 || api->read == 0 || api->close == 0) {
        FreeLibrary(api->dll);
        memset(api, 0, sizeof(*api));
        mega_result_error(result, "wm_https.dll is missing streaming exports");
        return 0;
    }

    return 1;
}

static void
mega_unload_tls(mega_tls_api *api)
{
    if (api != 0 && api->dll != 0) {
        FreeLibrary(api->dll);
        memset(api, 0, sizeof(*api));
    }
}

static int
mega_write_all(
    mega_tls_api *api,
    wm_tls_connection *conn,
    const void *data,
    unsigned int data_len,
    mega_http_result *result
)
{
    unsigned int written;
    wm_https_result tls_result;

    if (!api->write(conn, data, data_len, &written, &tls_result)) {
        if (result != 0) {
            result->tls_error = tls_result.tls_error;
            result->wsa_error = tls_result.wsa_error;
        }
        mega_result_error(result, "TLS write failed");
        return 0;
    }

    if (written != data_len) {
        mega_result_error(result, "short TLS write");
        return 0;
    }

    return 1;
}

static int
mega_parse_status_code(const char *response)
{
    const char *space;

    if (response == 0) {
        return 0;
    }

    space = strchr(response, ' ');
    if (space == 0) {
        return 0;
    }

    return atoi(space + 1);
}

static void
mega_copy_status_line(const char *response, char *out, unsigned int out_size)
{
    const char *end;
    unsigned int len;

    if (out == 0 || out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (response == 0) {
        return;
    }

    end = strstr(response, "\r\n");
    if (end == 0) {
        end = strchr(response, '\n');
    }
    if (end == 0) {
        end = response + strlen(response);
    }

    len = (unsigned int)(end - response);
    if (len >= out_size) {
        len = out_size - 1;
    }

    memcpy(out, response, len);
    out[len] = '\0';
}

static void
mega_copy_headers(const char *response, char *out, unsigned int out_size)
{
    const char *body;
    unsigned int len;

    if (out == 0 || out_size == 0) {
        return;
    }

    out[0] = '\0';
    body = mega_find_body_start(response);
    if (response == 0 || body == 0) {
        return;
    }

    len = (unsigned int)(body - response);
    if (len >= out_size) {
        len = out_size - 1;
    }

    memcpy(out, response, len);
    out[len] = '\0';
}

static const char *
mega_find_body_start(const char *response)
{
    const char *body;

    if (response == 0) {
        return 0;
    }

    body = strstr(response, "\r\n\r\n");
    if (body != 0) {
        return body + 4;
    }

    body = strstr(response, "\n\n");
    if (body != 0) {
        return body + 2;
    }

    return 0;
}

static int
mega_header_has_name(const char *line, const char *name)
{
    while (*line != '\0' && *name != '\0') {
        char lc;
        char nc;

        lc = *line;
        nc = *name;
        if (lc >= 'A' && lc <= 'Z') {
            lc = (char)(lc - 'A' + 'a');
        }
        if (nc >= 'A' && nc <= 'Z') {
            nc = (char)(nc - 'A' + 'a');
        }
        if (lc != nc) {
            return 0;
        }
        line++;
        name++;
    }

    return *name == '\0' && *line == ':';
}

static int
mega_parse_content_length(const char *response, int *out_length)
{
    const char *body;
    const char *line;
    const char *next;

    if (out_length != 0) {
        *out_length = -1;
    }

    body = mega_find_body_start(response);
    if (response == 0 || body == 0 || out_length == 0) {
        return 0;
    }

    line = response;
    while (line < body) {
        next = strstr(line, "\r\n");
        if (next == 0 || next > body) {
            break;
        }

        if (mega_header_has_name(line, "Content-Length")) {
            const char *value;

            value = strchr(line, ':');
            if (value != 0 && value < next) {
                value++;
                while (*value == ' ' || *value == '\t') {
                    value++;
                }
                *out_length = atoi(value);
                return 1;
            }
        }

        line = next + 2;
    }

    return 0;
}

static int
mega_parse_https_url(
    const char *url,
    char *host,
    unsigned int host_size,
    char *path,
    unsigned int path_size
)
{
    const char *p;
    const char *slash;
    unsigned int host_len;

    if (url == 0 || host == 0 || path == 0
        || host_size == 0 || path_size == 0)
    {
        return 0;
    }

    if (strncmp(url, "https://", 8) != 0) {
        return 0;
    }

    p = url + 8;
    slash = strchr(p, '/');
    if (slash == 0) {
        return 0;
    }

    host_len = (unsigned int)(slash - p);
    if (host_len == 0 || host_len >= host_size) {
        return 0;
    }
    memcpy(host, p, host_len);
    host[host_len] = '\0';

    if (strlen(slash) >= path_size) {
        return 0;
    }
    strcpy(path, slash);
    return 1;
}

int
mega_http_download_url_to_file(
    const char *url,
    const WCHAR *file_path,
    mega_http_result *result
)
{
    char host[128];
    char path[1024];
    char header[1536];
    char response_header[4096];
    unsigned char buffer[2048];
    mega_tls_api api;
    wm_tls_connection *conn;
    wm_https_result tls_result;
    HANDLE file;
    unsigned int header_used;
    int content_length;
    int header_done;
    int ok;

    mega_result_clear(result);
    if (url == 0 || file_path == 0) {
        mega_result_error(result, "invalid download arguments");
        return 0;
    }
    if (!mega_parse_https_url(url, host, sizeof(host), path, sizeof(path))) {
        mega_result_error(result, "could not parse download URL");
        return 0;
    }

    file = CreateFile(file_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        mega_result_error(result, "could not create download file");
        return 0;
    }

    mega_http_progress("Loading TLS DLL...");
    if (!mega_load_tls(&api, result)) {
        CloseHandle(file);
        return 0;
    }

    conn = 0;
    mega_http_progress("Opening TLS connection...");
    if (!api.open(host, 443, host, &conn, &tls_result)) {
        if (result != 0) {
            result->tls_error = tls_result.tls_error;
            result->wsa_error = tls_result.wsa_error;
        }
        mega_unload_tls(&api);
        CloseHandle(file);
        mega_result_error(result, "TLS open failed");
        return 0;
    }

    _snprintf(header, sizeof(header),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: MegaCE/0.1 (Windows CE)\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);
    header[sizeof(header) - 1] = '\0';

    mega_http_progress("Sending HTTP request...");
    ok = mega_write_all(&api, conn, header, (unsigned int)strlen(header), result);
    header_used = 0;
    content_length = -1;
    header_done = 0;
    response_header[0] = '\0';

    mega_http_progress("Reading HTTP response...");
    while (ok) {
        unsigned int got;

        got = 0;
        if (!api.read(conn, buffer, sizeof(buffer), &got, &tls_result)) {
            if (result != 0) {
                result->tls_error = tls_result.tls_error;
                result->wsa_error = tls_result.wsa_error;
            }
            mega_result_error(result, "TLS read failed");
            ok = 0;
            break;
        }
        if (got == 0) {
            break;
        }

        if (!header_done) {
            unsigned int copy_len;
            const char *body;

            copy_len = got;
            if (header_used + copy_len >= sizeof(response_header)) {
                copy_len = sizeof(response_header) - header_used - 1;
            }
            memcpy(response_header + header_used, buffer, copy_len);
            header_used += copy_len;
            response_header[header_used] = '\0';

            body = mega_find_body_start(response_header);
            if (body != 0) {
                unsigned int body_offset;
                unsigned int body_len;
                DWORD written;

                header_done = 1;
                if (result != 0) {
                    result->status_code = mega_parse_status_code(response_header);
                    mega_copy_status_line(response_header, result->status_line,
                        sizeof(result->status_line));
                    mega_copy_headers(response_header, result->headers,
                        sizeof(result->headers));
                    mega_parse_content_length(response_header, &content_length);
                    result->ok = result->status_code >= 200
                        && result->status_code < 300;
                }
                if (result != 0 && !result->ok) {
                    mega_result_error(result, "HTTP request returned non-2xx status");
                    ok = 0;
                    break;
                }

                body_offset = (unsigned int)(body - response_header);
                if (body_offset < header_used) {
                    body_len = header_used - body_offset;
                    written = 0;
                    if (!WriteFile(file, response_header + body_offset,
                        body_len, &written, 0)
                        || written != body_len)
                    {
                        mega_result_error(result, "download file write failed");
                        ok = 0;
                        break;
                    }
                    if (result != 0) {
                        result->body_bytes += (int)body_len;
                    }
                    if (content_length >= 0
                        && result != 0
                        && result->body_bytes >= content_length)
                    {
                        break;
                    }
                }
            } else if (header_used >= sizeof(response_header) - 1) {
                mega_result_error(result, "download response header too large");
                ok = 0;
                break;
            }
        } else {
            DWORD written;

            written = 0;
            if (!WriteFile(file, buffer, got, &written, 0) || written != got) {
                mega_result_error(result, "download file write failed");
                ok = 0;
                break;
            }
            if (result != 0) {
                char progress[80];

                result->body_bytes += (int)got;
                _snprintf(progress, sizeof(progress),
                    "Downloaded %d%s%d bytes...",
                    result->body_bytes,
                    content_length >= 0 ? "/" : " ",
                    content_length >= 0 ? content_length : 0);
                progress[sizeof(progress) - 1] = '\0';
                mega_http_progress(progress);
                if (content_length >= 0 && result->body_bytes >= content_length) {
                    break;
                }
            }
        }
    }

    mega_http_progress("Closing TLS connection...");
    api.close(conn);
    mega_unload_tls(&api);
    CloseHandle(file);

    if (result != 0) {
        result->ok = ok && result->status_code >= 200 && result->status_code < 300;
    }
    return result != 0 ? result->ok : ok;
}

int
mega_http_upload_file_to_url(
    const char *url,
    const WCHAR *file_path,
    char *response_body,
    unsigned int response_body_size,
    mega_http_result *result
)
{
    char host[128];
    char path[1024];
    char header[1536];
    char initial_response[MEGA_HTTP_INITIAL_HEADER_LIMIT];
    unsigned char buffer[2048];
    mega_tls_api api;
    wm_tls_connection *conn;
    wm_https_result tls_result;
    HANDLE file;
    DWORD size_high;
    DWORD size_low;
    unsigned __int64 total_size;
    unsigned __int64 sent_size;
    unsigned int used;
    unsigned int body_used;
    unsigned int total_received;
    int headers_done;
    int content_length;
    int ok;

    mega_result_clear(result);
    if (response_body != 0 && response_body_size > 0) {
        response_body[0] = '\0';
    }
    if (url == 0 || file_path == 0 || response_body == 0
        || response_body_size < 2)
    {
        mega_result_error(result, "invalid upload arguments");
        return 0;
    }
    if (!mega_parse_https_url(url, host, sizeof(host), path, sizeof(path))) {
        mega_result_error(result, "could not parse upload URL");
        return 0;
    }

    file = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        mega_result_error(result, "could not open upload file");
        return 0;
    }

    size_high = 0;
    size_low = GetFileSize(file, &size_high);
    total_size = (((unsigned __int64)size_high) << 32)
        | (unsigned __int64)size_low;

    mega_http_progress("Loading TLS DLL...");
    if (!mega_load_tls(&api, result)) {
        CloseHandle(file);
        return 0;
    }

    conn = 0;
    mega_http_progress("Opening TLS connection...");
    if (!api.open(host, 443, host, &conn, &tls_result)) {
        if (result != 0) {
            result->tls_error = tls_result.tls_error;
            result->wsa_error = tls_result.wsa_error;
        }
        mega_unload_tls(&api);
        CloseHandle(file);
        mega_result_error(result, "TLS open failed");
        return 0;
    }

    _snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: MegaCE/0.1 (Windows CE)\r\n"
        "Accept: */*\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, (unsigned long)total_size);
    header[sizeof(header) - 1] = '\0';

    mega_http_progress("Sending upload request...");
    ok = mega_write_all(&api, conn, header, (unsigned int)strlen(header), result);
    sent_size = 0;
    while (ok) {
        DWORD read_bytes;

        read_bytes = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &read_bytes, 0)) {
            mega_result_error(result, "upload file read failed");
            ok = 0;
            break;
        }
        if (read_bytes == 0) {
            break;
        }
        if (!mega_write_all(&api, conn, buffer, read_bytes, result)) {
            ok = 0;
            break;
        }
        sent_size += read_bytes;
        if ((sent_size % 65536) == 0 || sent_size == total_size) {
            char progress[80];

            _snprintf(progress, sizeof(progress), "Uploaded %lu/%lu bytes...",
                (unsigned long)sent_size, (unsigned long)total_size);
            progress[sizeof(progress) - 1] = '\0';
            mega_http_progress(progress);
        }
    }

    mega_http_progress("Reading HTTP response...");
    initial_response[0] = '\0';
    used = 0;
    body_used = 0;
    total_received = 0;
    headers_done = 0;
    content_length = -1;
    while (ok) {
        unsigned int got;
        char *read_target;
        unsigned int read_space;

        if (headers_done) {
            if (body_used >= response_body_size - 1) {
                mega_http_progress("HTTP response reached local buffer limit.");
                break;
            }
            read_target = response_body + body_used;
            read_space = response_body_size - body_used - 1;
        } else {
            if (used >= sizeof(initial_response) - 1) {
                mega_result_error(result, "HTTP response headers too large");
                ok = 0;
                break;
            }
            read_target = initial_response + used;
            read_space = sizeof(initial_response) - used - 1;
        }

        got = 0;
        if (!api.read(conn, read_target, read_space, &got, &tls_result)) {
            if (result != 0) {
                result->tls_error = tls_result.tls_error;
                result->wsa_error = tls_result.wsa_error;
            }
            mega_result_error(result, "TLS read failed");
            ok = 0;
            break;
        }
        if (got == 0) {
            break;
        }
        total_received += got;

        if (headers_done) {
            body_used += got;
            response_body[body_used] = '\0';
        } else {
            const char *body_start;
            unsigned int header_body_bytes;

            used += got;
            initial_response[used] = '\0';
            body_start = mega_find_body_start(initial_response);
            if (body_start != 0) {
                header_body_bytes = used
                    - (unsigned int)(body_start - initial_response);
                if (header_body_bytes >= response_body_size) {
                    header_body_bytes = response_body_size - 1;
                }
                if (result != 0) {
                    result->status_code = mega_parse_status_code(initial_response);
                    mega_copy_status_line(initial_response, result->status_line,
                        sizeof(result->status_line));
                    mega_copy_headers(initial_response, result->headers,
                        sizeof(result->headers));
                    mega_parse_content_length(initial_response, &content_length);
                }
                memmove(response_body, body_start, header_body_bytes);
                body_used = header_body_bytes;
                response_body[body_used] = '\0';
                headers_done = 1;
            }
        }

        if (headers_done && content_length >= 0
            && body_used >= (unsigned int)content_length)
        {
            break;
        }
    }

    mega_http_progress("Closing TLS connection...");
    api.close(conn);
    mega_unload_tls(&api);
    CloseHandle(file);
    mega_crypto_zero(buffer, sizeof(buffer));

    if (result != 0) {
        result->bytes_received = (int)total_received;
        result->body_bytes = (int)body_used;
        if (!headers_done) {
            result->status_code = mega_parse_status_code(initial_response);
            mega_copy_status_line(initial_response, result->status_line,
                sizeof(result->status_line));
            mega_copy_headers(initial_response, result->headers,
                sizeof(result->headers));
        }
        result->ok = ok && result->status_code >= 200 && result->status_code < 300;
        if (ok && !result->ok) {
            mega_result_error(result, "HTTP request returned non-2xx status");
        }
    }

    return result != 0 ? result->ok : ok;
}

int
mega_http_post(
    const char *host,
    unsigned short port,
    const char *path,
    const void *body,
    unsigned int body_len,
    char *response_body,
    unsigned int response_body_size,
    mega_http_result *result
)
{
    return mega_http_post_ex(host, port, path, 0, body, body_len,
        response_body, response_body_size, result);
}

int
mega_http_post_ex(
    const char *host,
    unsigned short port,
    const char *path,
    const char *extra_headers,
    const void *body,
    unsigned int body_len,
    char *response_body,
    unsigned int response_body_size,
    mega_http_result *result
)
{
    char initial_response[MEGA_HTTP_INITIAL_HEADER_LIMIT];
    mega_tls_api api;
    wm_tls_connection *conn;
    wm_https_result tls_result;
    char header[512];
    unsigned int used;
    unsigned int body_used;
    unsigned int total_received;
    int headers_done;
    int content_length;
    int ok;

    mega_result_clear(result);
    if (response_body != 0 && response_body_size > 0) {
        response_body[0] = '\0';
    }

    if (host == 0 || path == 0 || response_body == 0 || response_body_size < 2) {
        mega_result_error(result, "invalid HTTP request arguments");
        return 0;
    }

    initial_response[0] = '\0';

    mega_http_progress("Loading TLS DLL...");
    if (!mega_load_tls(&api, result)) {
        return 0;
    }

    conn = 0;
    mega_http_progress("Opening TLS connection...");
    if (!api.open(host, port, host, &conn, &tls_result)) {
        if (result != 0) {
            result->tls_error = tls_result.tls_error;
            result->wsa_error = tls_result.wsa_error;
        }
        mega_unload_tls(&api);
        mega_result_error(result, "TLS open failed");
        return 0;
    }

    _snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: MegaCE/0.1 (Windows CE)\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n",
        path, host, body_len);
    header[sizeof(header) - 1] = '\0';

    mega_http_progress("Sending HTTP request...");
    ok = mega_write_all(&api, conn, header, (unsigned int)strlen(header), result);
    if (ok && extra_headers != 0 && extra_headers[0] != '\0') {
        ok = mega_write_all(&api, conn, extra_headers,
            (unsigned int)strlen(extra_headers), result);
    }
    if (ok) {
        ok = mega_write_all(&api, conn, "\r\n", 2, result);
    }
    if (ok && body_len > 0) {
        ok = mega_write_all(&api, conn, body, body_len, result);
    }

    mega_http_progress("Reading HTTP response...");
    used = 0;
    body_used = 0;
    total_received = 0;
    headers_done = 0;
    content_length = -1;
    while (ok) {
        unsigned int got;
        char *read_target;
        unsigned int read_space;

        if (headers_done) {
            if (body_used >= response_body_size - 1) {
                mega_http_progress("HTTP response reached local buffer limit.");
                break;
            }
            read_target = response_body + body_used;
            read_space = response_body_size - body_used - 1;
        } else {
            if (used >= sizeof(initial_response) - 1) {
                mega_result_error(result, "HTTP response headers too large");
                ok = 0;
                break;
            }
            read_target = initial_response + used;
            read_space = sizeof(initial_response) - used - 1;
        }

        got = 0;
        if (!api.read(conn, read_target, read_space, &got, &tls_result))
        {
            if (result != 0) {
                result->tls_error = tls_result.tls_error;
                result->wsa_error = tls_result.wsa_error;
            }
            mega_result_error(result, "TLS read failed");
            ok = 0;
            break;
        }

        if (got == 0) {
            break;
        }
        total_received += got;

        if (headers_done) {
            body_used += got;
            response_body[body_used] = '\0';
        } else {
            const char *body_start;
            unsigned int header_body_bytes;

            used += got;
            initial_response[used] = '\0';
            body_start = mega_find_body_start(initial_response);
            if (body_start != 0) {
                header_body_bytes = used - (unsigned int)(body_start - initial_response);
                if (header_body_bytes >= response_body_size) {
                    header_body_bytes = response_body_size - 1;
                    mega_http_progress("HTTP response reached local buffer limit.");
                }

                if (result != 0) {
                    result->status_code = mega_parse_status_code(initial_response);
                    mega_copy_status_line(initial_response, result->status_line,
                        sizeof(result->status_line));
                    mega_copy_headers(initial_response, result->headers,
                        sizeof(result->headers));
                    mega_parse_content_length(initial_response, &content_length);
                }

                memmove(response_body, body_start, header_body_bytes);
                body_used = header_body_bytes;
                response_body[body_used] = '\0';
                headers_done = 1;
            }
        }

        if ((headers_done && (body_used % 1024) == 0)
            || (!headers_done && (used % 1024) == 0))
        {
            char progress[64];

            _snprintf(progress, sizeof(progress), "Received %u bytes...", used);
            if (headers_done) {
                _snprintf(progress, sizeof(progress), "Received %u body bytes...",
                    body_used);
            }
            progress[sizeof(progress) - 1] = '\0';
            mega_http_progress(progress);
        }

        if (headers_done && content_length >= 0
            && body_used >= (unsigned int)content_length)
        {
            break;
        }
    }

    mega_http_progress("Closing TLS connection...");
    api.close(conn);
    mega_unload_tls(&api);

    if (result != 0) {
        result->bytes_received = (int)total_received;
        if (!headers_done) {
            result->status_code = mega_parse_status_code(initial_response);
            mega_copy_status_line(initial_response, result->status_line,
                sizeof(result->status_line));
            mega_copy_headers(initial_response, result->headers,
                sizeof(result->headers));
            if (used > 0) {
                unsigned int copy_bytes;

                copy_bytes = used;
                if (copy_bytes >= response_body_size) {
                    copy_bytes = response_body_size - 1;
                }
                memcpy(response_body, initial_response, copy_bytes);
                response_body[copy_bytes] = '\0';
                body_used = copy_bytes;
            }
        }
        result->ok = ok && result->status_code >= 200 && result->status_code < 300;
        result->body_bytes = (int)body_used;
        if (ok && !result->ok) {
            mega_result_error(result, "HTTP request returned non-2xx status");
        }
    }

    return result != 0 ? result->ok : ok;
}

int
mega_http_post_file_ex(
    const char *host,
    unsigned short port,
    const char *path,
    const char *extra_headers,
    const void *body,
    unsigned int body_len,
    const WCHAR *response_file_path,
    mega_http_result *result
)
{
    char initial_response[MEGA_HTTP_INITIAL_HEADER_LIMIT];
    char read_buffer[4096];
    mega_tls_api api;
    wm_tls_connection *conn;
    wm_https_result tls_result;
    HANDLE file;
    char header[512];
    unsigned int used;
    unsigned int body_used;
    unsigned int total_received;
    int headers_done;
    int content_length;
    int ok;

    mega_result_clear(result);
    if (host == 0 || path == 0 || response_file_path == 0) {
        mega_result_error(result, "invalid HTTP file request arguments");
        return 0;
    }

    file = CreateFile(response_file_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        mega_result_error(result, "Could not create HTTP response file");
        return 0;
    }

    initial_response[0] = '\0';

    mega_http_progress("Loading TLS DLL...");
    if (!mega_load_tls(&api, result)) {
        CloseHandle(file);
        return 0;
    }

    conn = 0;
    mega_http_progress("Opening TLS connection...");
    if (!api.open(host, port, host, &conn, &tls_result)) {
        if (result != 0) {
            result->tls_error = tls_result.tls_error;
            result->wsa_error = tls_result.wsa_error;
        }
        mega_unload_tls(&api);
        CloseHandle(file);
        mega_result_error(result, "TLS open failed");
        return 0;
    }

    _snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: MegaCE/0.1 (Windows CE)\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n",
        path, host, body_len);
    header[sizeof(header) - 1] = '\0';

    mega_http_progress("Sending HTTP request...");
    ok = mega_write_all(&api, conn, header, (unsigned int)strlen(header), result);
    if (ok && extra_headers != 0 && extra_headers[0] != '\0') {
        ok = mega_write_all(&api, conn, extra_headers,
            (unsigned int)strlen(extra_headers), result);
    }
    if (ok) {
        ok = mega_write_all(&api, conn, "\r\n", 2, result);
    }
    if (ok && body_len > 0) {
        ok = mega_write_all(&api, conn, body, body_len, result);
    }

    mega_http_progress("Reading HTTP response...");
    used = 0;
    body_used = 0;
    total_received = 0;
    headers_done = 0;
    content_length = -1;
    while (ok) {
        unsigned int got;
        char *read_target;
        unsigned int read_space;

        if (headers_done) {
            read_target = read_buffer;
            read_space = sizeof(read_buffer);
        } else {
            if (used >= sizeof(initial_response) - 1) {
                mega_result_error(result, "HTTP response headers too large");
                ok = 0;
                break;
            }
            read_target = initial_response + used;
            read_space = sizeof(initial_response) - used - 1;
        }

        got = 0;
        if (!api.read(conn, read_target, read_space, &got, &tls_result)) {
            if (result != 0) {
                result->tls_error = tls_result.tls_error;
                result->wsa_error = tls_result.wsa_error;
            }
            mega_result_error(result, "TLS read failed");
            ok = 0;
            break;
        }
        if (got == 0) {
            break;
        }
        total_received += got;

        if (headers_done) {
            DWORD written;

            written = 0;
            if (!WriteFile(file, read_buffer, got, &written, 0)
                || written != got)
            {
                mega_result_error(result, "Could not write HTTP response file");
                ok = 0;
                break;
            }
            body_used += got;
        } else {
            const char *body_start;
            unsigned int header_body_bytes;

            used += got;
            initial_response[used] = '\0';
            body_start = mega_find_body_start(initial_response);
            if (body_start != 0) {
                if (result != 0) {
                    result->status_code = mega_parse_status_code(initial_response);
                    mega_copy_status_line(initial_response, result->status_line,
                        sizeof(result->status_line));
                    mega_copy_headers(initial_response, result->headers,
                        sizeof(result->headers));
                    mega_parse_content_length(initial_response, &content_length);
                }

                header_body_bytes = used - (unsigned int)(body_start - initial_response);
                if (header_body_bytes > 0) {
                    DWORD written;

                    written = 0;
                    if (!WriteFile(file, body_start, header_body_bytes,
                        &written, 0) || written != header_body_bytes)
                    {
                        mega_result_error(result, "Could not write HTTP response file");
                        ok = 0;
                        break;
                    }
                    body_used += header_body_bytes;
                }
                headers_done = 1;
            }
        }

        if (body_used != 0 && (body_used % 65536) == 0) {
            char progress[80];

            _snprintf(progress, sizeof(progress), "Received %u body bytes...",
                body_used);
            progress[sizeof(progress) - 1] = '\0';
            mega_http_progress(progress);
        }

        if (headers_done && content_length >= 0
            && body_used >= (unsigned int)content_length)
        {
            break;
        }
    }

    mega_http_progress("Closing TLS connection...");
    api.close(conn);
    mega_unload_tls(&api);
    CloseHandle(file);

    if (result != 0) {
        result->bytes_received = (int)total_received;
        result->body_bytes = (int)body_used;
        if (!headers_done) {
            result->status_code = mega_parse_status_code(initial_response);
            mega_copy_status_line(initial_response, result->status_line,
                sizeof(result->status_line));
            mega_copy_headers(initial_response, result->headers,
                sizeof(result->headers));
        }
        result->ok = ok && result->status_code >= 200 && result->status_code < 300;
        if (ok && !result->ok) {
            mega_result_error(result, "HTTP request returned non-2xx status");
        }
    }

    return result != 0 ? result->ok : ok;
}
