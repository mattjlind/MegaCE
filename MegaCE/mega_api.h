#ifndef MEGA_API_H
#define MEGA_API_H

#include <windows.h>
#include "mega_http.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mega_api_result {
    int ok;
    int request_id;
    int account_version;
    int login_success;
    int sensitive_response;
    mega_http_result http;
    char diagnostic[128];
    char error[128];
} mega_api_result;

typedef struct mega_fetch_nodes_summary {
    int node_count;
    int folder_count;
    int file_count;
    int root_count;
    int incoming_count;
    int rubbish_count;
    int users_count;
    int parsed_nodes;
    int decrypted_names;
    int undecrypted_files;
    int undecrypted_folders;
    int undecrypted_specials;
    int truncated;
    char first_names[256];
} mega_fetch_nodes_summary;

typedef struct mega_node_info {
    char handle[16];
    char parent[16];
    int type;
    unsigned __int64 size;
    unsigned int mtime;
    char name[96];
    int file_key_valid;
    unsigned char file_key[32];
} mega_node_info;

int mega_api_has_login_key(void);

void mega_api_clear_login_key(void);

int mega_api_has_session(void);

void mega_api_clear_session(void);

int mega_api_get_session_status(char *status, unsigned int status_size);

int mega_api_save_session_file(const WCHAR *path);

int mega_api_load_session_file(const WCHAR *path);

int mega_api_command(
    const char *json_commands,
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
);

int mega_api_probe(
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
);

int mega_api_get_user_salt(
    const char *email,
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
);

int mega_api_login_v1(
    const char *email,
    const char *password,
    char *response_body,
    unsigned int response_body_size,
    mega_api_result *result
);

int mega_api_fetch_nodes(
    char *response_body,
    unsigned int response_body_size,
    mega_fetch_nodes_summary *summary,
    mega_api_result *result
);

int mega_api_fetch_nodes_file(
    const WCHAR *response_file_path,
    mega_fetch_nodes_summary *summary,
    mega_api_result *result
);

int mega_api_get_node_count(void);

int mega_api_get_node(int index, mega_node_info *node);

int mega_api_find_root_node(void);

int mega_api_find_node_by_handle(const char *handle);

int mega_api_get_child_node(const char *parent, int child_offset, mega_node_info *node);

int mega_api_add_local_folder_node(
    const char *handle,
    const char *parent,
    const char *name
);

int mega_api_rename_local_node(const char *handle, const char *new_name);

int mega_api_remove_local_node(const char *handle);

int mega_api_get_download_url(
    const char *node_handle,
    char *url,
    unsigned int url_size,
    mega_api_result *result
);

int mega_api_upload_file_update(
    const char *existing_handle,
    const char *parent_handle,
    const char *name,
    const WCHAR *local_path,
    const WCHAR *encrypted_path,
    char *new_handle,
    unsigned int new_handle_size,
    mega_api_result *result
);

int mega_api_create_folder(
    const char *parent_handle,
    const char *name,
    char *new_handle,
    unsigned int new_handle_size,
    mega_api_result *result
);

int mega_api_rename_node(
    const char *node_handle,
    const char *new_name,
    mega_api_result *result
);

int mega_api_delete_node(
    const char *node_handle,
    mega_api_result *result
);

#ifdef __cplusplus
}
#endif

#endif
