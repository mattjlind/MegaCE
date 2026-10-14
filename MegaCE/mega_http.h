#ifndef MEGA_HTTP_H
#define MEGA_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mega_http_result {
    int ok;
    int status_code;
    int tls_error;
    int wsa_error;
    unsigned __int64 bytes_received;
    unsigned __int64 body_bytes;
    char status_line[80];
    char headers[512];
    char error[128];
} mega_http_result;

typedef void (*mega_http_progress_fn)(const char *message, void *user_data);
typedef void (*mega_http_transfer_progress_fn)(
    unsigned __int64 bytes_done,
    unsigned __int64 bytes_total,
    void *user_data
);
typedef int (*mega_http_cancel_fn)(void *user_data);
typedef int (*mega_http_data_transform_fn)(
    unsigned char *data,
    unsigned int data_len,
    void *user_data
);

void mega_http_set_progress_callback(
    mega_http_progress_fn callback,
    void *user_data
);

void mega_http_progress_message(const char *message);

void mega_http_set_transfer_progress_callback(
    mega_http_transfer_progress_fn callback,
    void *user_data
);

void mega_http_set_cancel_callback(
    mega_http_cancel_fn callback,
    void *user_data
);

int mega_http_cancel_requested(void);

void mega_http_close_idle_connections(void);

HMODULE mega_http_load_bear_tls_dll(void);

int mega_http_post(
    const char *host,
    unsigned short port,
    const char *path,
    const void *body,
    unsigned int body_len,
    char *response_body,
    unsigned int response_body_size,
    mega_http_result *result
);

int mega_http_post_ex(
    const char *host,
    unsigned short port,
    const char *path,
    const char *extra_headers,
    const void *body,
    unsigned int body_len,
    char *response_body,
    unsigned int response_body_size,
    mega_http_result *result
);

int mega_http_post_file_ex(
    const char *host,
    unsigned short port,
    const char *path,
    const char *extra_headers,
    const void *body,
    unsigned int body_len,
    const WCHAR *response_file_path,
    mega_http_result *result
);

int mega_http_download_url_to_file(
    const char *url,
    const WCHAR *file_path,
    mega_http_result *result
);

int mega_http_download_url_to_file_ex(
    const char *url,
    const WCHAR *file_path,
    mega_http_data_transform_fn transform,
    void *transform_user_data,
    mega_http_result *result
);

int mega_http_upload_file_to_url(
    const char *url,
    const WCHAR *file_path,
    char *response_body,
    unsigned int response_body_size,
    mega_http_result *result
);

int mega_http_upload_file_to_url_ex(
    const char *url,
    const WCHAR *file_path,
    mega_http_data_transform_fn transform,
    void *transform_user_data,
    char *response_body,
    unsigned int response_body_size,
    mega_http_result *result
);

#ifdef __cplusplus
}
#endif

#endif
