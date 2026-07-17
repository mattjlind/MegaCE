#include <windows.h>
#include <commctrl.h>
#include <aygshell.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resource.h"
#include "mega_api.h"
#include "mega_crypto.h"

#pragma comment(lib, "aygshell.lib")

#define MEGACE_CLASS_NAME TEXT("MegaCEWindow")
#define MEGACE_TITLE      TEXT("MegaCE")
#define WM_MEGACE_LOG     (WM_APP + 1)
#define WM_MEGACE_DONE    (WM_APP + 2)
#define WM_MEGACE_DOWNLOAD_DONE (WM_APP + 3)
#define WM_MEGACE_SYNC_DONE (WM_APP + 4)
#define WM_MEGACE_SERVER_OP_DONE (WM_APP + 5)
#define WM_MEGACE_SYNC_STATUS (WM_APP + 6)
#define WM_MEGACE_CONFLICT_DONE (WM_APP + 7)

#define MEGACE_VIEW_FILES 1
#define MEGACE_VIEW_LOGIN 2
#define MEGACE_VIEW_LOGS  3
#define MEGACE_VIEW_SETTINGS 4
#define MEGACE_VIEW_CREATE_FOLDER 5
#define MEGACE_VIEW_RENAME 6
#define MEGACE_VIEW_SYNC 7
#define MEGACE_RESPONSE_SMALL_SIZE 65536U
#define MEGACE_FILE_ICON_FILE   0
#define MEGACE_FILE_ICON_FOLDER 1
#define MEGACE_FILE_ICON_UP     2
#define MEGACE_FILE_ICON_FOLDER_SYNC 3
#define MEGACE_BASE_DPI 96
#define MEGACE_LIST_ICON_BASE_SIZE 24
#define MEGACE_TEXT_POINT_DEFAULT 10
#define MEGACE_TEXT_POINT_MIN 8
#define MEGACE_TEXT_POINT_MAX 22
#define MEGACE_COLUMN_SAVE_TIMER 3001
#define MEGACE_COLUMN_SAVE_DELAY_MS 5000
#define MEGACE_SPINNER_TIMER 3002
#define MEGACE_SPINNER_DELAY_MS 250
#define MEGACE_MAX_SYNC_HANDLES 64
#define MEGACE_DOWNLOAD_MODE_MANUAL 0
#define MEGACE_DOWNLOAD_MODE_SYNC 1
#define MEGACE_MAX_SYNC_CONFLICTS 16
#define MEGACE_SYNC_STATE_MAGIC "MCESST1"
#define MEGACE_SYNC_STATE_VERSION 1
#define MEGACE_SERVER_OP_CREATE_FOLDER 1
#define MEGACE_SERVER_OP_RENAME 2
#define MEGACE_SERVER_OP_DELETE 3
#define MEGACE_INPUT_CLASS_NAME TEXT("MegaCEInputWindow")
#ifndef ILC_COLOR32
#define ILC_COLOR32 0x00000020
#endif
static HWND g_log;
static HWND g_files;
static HWND g_main_window;
static HWND g_menu_bar;
static HIMAGELIST g_file_images;
static WNDPROC g_files_old_proc;
static HWND g_email;
static HWND g_password;
static HWND g_sync_label;
static HWND g_sync_dir;
static HWND g_text_size_label;
static HWND g_text_size_edit;
static HWND g_sync_status_label;
static HWND g_sync_progress;
static HWND g_create_folder_label;
static HWND g_create_folder_name;
static HWND g_rename_label;
static HWND g_rename_name;
static HWND g_spinner;
static HFONT g_app_font;
static LONG g_probe_running;
static int g_probe_mode;
static char g_probe_email[256];
static char g_probe_password[256];
static int g_download_node_index;
static int g_view_mode = MEGACE_VIEW_FILES;
static char g_current_parent[16];
static char g_parent_stack[32][16];
static int g_parent_depth;
static int *g_file_item_nodes;
static int g_file_item_capacity;
static int g_file_column_widths[3] = { 150, 110, 70 };
static int g_file_sort_column;
static int g_file_sort_reverse;
static int g_spinner_frame;
static int g_spinner_active;
static int g_rename_node_index = -1;
static int g_dpi_x = MEGACE_BASE_DPI;
static int g_dpi_y = MEGACE_BASE_DPI;
static int g_list_icon_size = MEGACE_LIST_ICON_BASE_SIZE;
static int g_text_point_size = MEGACE_TEXT_POINT_DEFAULT;
static WCHAR g_sync_directory[MAX_PATH];
static char g_sync_handles[MEGACE_MAX_SYNC_HANDLES][16];
static int g_sync_handle_count;
static int g_context_node_index = -1;
static int g_download_root_index = -1;
static char g_download_root_handle[16];
static int g_download_mode;
static int g_server_op_type;
static int g_server_op_node_index;
static char g_server_op_parent[16];
static char g_server_op_name[128];

typedef struct sync_conflict_entry {
    mega_node_info node;
    WCHAR path[MAX_PATH];
    WCHAR name[128];
    int choice;
} sync_conflict_entry;

typedef struct sync_state_header {
    char magic[8];
    unsigned int version;
    unsigned int count;
} sync_state_header;

typedef struct sync_state_record {
    char handle[16];
    unsigned __int64 remote_size;
    unsigned int remote_mtime;
    unsigned __int64 local_size;
    unsigned int local_mtime;
    int type;
    WCHAR local_path[MAX_PATH];
} sync_state_record;

typedef struct sync_state_record_v1 {
    char handle[16];
    unsigned __int64 remote_size;
    unsigned int remote_mtime;
    unsigned __int64 local_size;
    unsigned int local_mtime;
    int type;
} sync_state_record_v1;

typedef struct file_sort_entry {
    int node_index;
    mega_node_info node;
    WCHAR label[160];
} file_sort_entry;

static sync_state_record *g_sync_state_records;
static int g_sync_state_count;
static int g_sync_state_capacity;
static sync_conflict_entry g_sync_conflicts[MEGACE_MAX_SYNC_CONFLICTS];
static int g_sync_conflict_count;

static void save_session_to_file(void);
static void layout_children(HWND hwnd);
static void populate_file_list(void);
static int build_app_file_path(const WCHAR *file_name, WCHAR *path, unsigned int path_size);
static void http_progress_callback(const char *message, void *user_data);
static void show_file_context_menu(HWND hwnd);
static void start_server_operation(HWND hwnd, int op_type, int node_index);
static void set_current_parent_from_root(void);
static void show_rename_page(HWND hwnd, int node_index);
static void setup_file_icons(void);
static void recalculate_icon_size(void);
static void post_sync_status(const WCHAR *text, int progress);
static int get_local_file_state(
    const WCHAR *path,
    unsigned __int64 *size,
    unsigned int *mtime
);
static int sync_state_upsert_file(
    const mega_node_info *node,
    const WCHAR *plain_path
);
static int sync_state_upsert_folder(
    const mega_node_info *node,
    const WCHAR *plain_path
);
static int sync_state_upsert_pending_local(const WCHAR *plain_path);
static unsigned int filetime_to_unix_time(const FILETIME *ft);

static int
scale_x(int value)
{
    return (value * g_dpi_x + MEGACE_BASE_DPI / 2) / MEGACE_BASE_DPI;
}

static int
scale_y(int value)
{
    return (value * g_dpi_y + MEGACE_BASE_DPI / 2) / MEGACE_BASE_DPI;
}

static void
init_ui_metrics(HWND hwnd)
{
    HDC dc;

    dc = GetDC(hwnd);
    if (dc != 0) {
        int dpi_x;
        int dpi_y;

        dpi_x = GetDeviceCaps(dc, LOGPIXELSX);
        dpi_y = GetDeviceCaps(dc, LOGPIXELSY);
        ReleaseDC(hwnd, dc);
        if (dpi_x >= 72 && dpi_x <= 384) {
            g_dpi_x = dpi_x;
        }
        if (dpi_y >= 72 && dpi_y <= 384) {
            g_dpi_y = dpi_y;
        }
    }
    recalculate_icon_size();
}

static int
clamp_text_point_size(int point_size)
{
    if (point_size < MEGACE_TEXT_POINT_MIN) {
        return MEGACE_TEXT_POINT_MIN;
    }
    if (point_size > MEGACE_TEXT_POINT_MAX) {
        return MEGACE_TEXT_POINT_MAX;
    }
    return point_size;
}

static int
text_pixel_height(void)
{
    int height;

    height = (g_text_point_size * g_dpi_y + 36) / 72;
    if (height < scale_y(14)) {
        height = scale_y(14);
    }
    return height;
}

static void
recalculate_icon_size(void)
{
    int size;

    size = text_pixel_height() + scale_y(8);
    if (size < scale_y(MEGACE_LIST_ICON_BASE_SIZE)) {
        size = scale_y(MEGACE_LIST_ICON_BASE_SIZE);
    }
    if (size > scale_y(48)) {
        size = scale_y(48);
    }
    g_list_icon_size = size;
}

static void
create_app_font(void)
{
    LOGFONT lf;

    if (g_app_font != 0) {
        DeleteObject(g_app_font);
        g_app_font = 0;
    }

    memset(&lf, 0, sizeof(lf));
    lf.lfHeight = -((g_text_point_size * g_dpi_y + 36) / 72);
    lf.lfWeight = FW_NORMAL;
    lf.lfCharSet = DEFAULT_CHARSET;
    lstrcpy(lf.lfFaceName, TEXT("Tahoma"));
    g_app_font = CreateFontIndirect(&lf);
}

static void
set_child_font(HWND hwnd)
{
    if (hwnd != 0 && g_app_font != 0) {
        SendMessage(hwnd, WM_SETFONT, (WPARAM)g_app_font, TRUE);
    }
}

static void
apply_app_font(HWND hwnd)
{
    set_child_font(g_files);
    set_child_font(g_log);
    set_child_font(g_email);
    set_child_font(g_password);
    set_child_font(g_sync_label);
    set_child_font(g_sync_dir);
    set_child_font(g_text_size_label);
    set_child_font(g_text_size_edit);
    set_child_font(g_sync_status_label);
    set_child_font(g_create_folder_label);
    set_child_font(g_create_folder_name);
    set_child_font(g_rename_label);
    set_child_font(g_rename_name);
    set_child_font(g_spinner);
    set_child_font(GetDlgItem(hwnd, IDC_MEGACE_LOGIN));
    set_child_font(GetDlgItem(hwnd, IDC_MEGACE_SAVESETTINGS));
    set_child_font(GetDlgItem(hwnd, IDC_MEGACE_CREATEFOLDERGO));
    set_child_font(GetDlgItem(hwnd, IDC_MEGACE_RENAMEGO));
}

static void
post_sync_status(const WCHAR *text, int progress)
{
    WCHAR *copy;
    size_t len;

    if (g_main_window == 0 || text == 0) {
        return;
    }
    if (progress < 0) {
        progress = 0;
    }
    if (progress > 100) {
        progress = 100;
    }
    len = wcslen(text) + 1;
    copy = (WCHAR *)LocalAlloc(LPTR, len * sizeof(WCHAR));
    if (copy == 0) {
        return;
    }
    memcpy(copy, text, len * sizeof(WCHAR));
    PostMessage(g_main_window, WM_MEGACE_SYNC_STATUS,
        (WPARAM)progress, (LPARAM)copy);
}

static void
reset_sync_page(const WCHAR *text)
{
    if (g_sync_status_label != 0) {
        SetWindowText(g_sync_status_label,
            text != 0 ? text : TEXT("Ready to sync"));
    }
    if (g_sync_progress != 0) {
        SendMessage(g_sync_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(g_sync_progress, PBM_SETPOS, 0, 0);
    }
}

static void
update_text_size_controls(void)
{
    WCHAR text[16];

    if (g_text_size_edit == 0) {
        return;
    }
    _snwprintf(text, sizeof(text) / sizeof(text[0]), L"%d",
        g_text_point_size);
    text[(sizeof(text) / sizeof(text[0])) - 1] = L'\0';
    SetWindowText(g_text_size_edit, text);
}

static void
rebuild_file_icons(void)
{
    if (g_files != 0) {
        ListView_SetImageList(g_files, 0, LVSIL_SMALL);
    }
    if (g_file_images != 0) {
        ImageList_Destroy(g_file_images);
        g_file_images = 0;
    }
    setup_file_icons();
}

static void
apply_text_size(HWND hwnd)
{
    g_text_point_size = clamp_text_point_size(g_text_point_size);
    recalculate_icon_size();
    create_app_font();
    apply_app_font(hwnd);
    rebuild_file_icons();
    layout_children(hwnd);
    populate_file_list();
}

static void
schedule_file_column_width_save(HWND hwnd)
{
    if (hwnd == 0) {
        return;
    }
    KillTimer(hwnd, MEGACE_COLUMN_SAVE_TIMER);
    SetTimer(hwnd, MEGACE_COLUMN_SAVE_TIMER,
        MEGACE_COLUMN_SAVE_DELAY_MS, 0);
}

static void
start_spinner(HWND hwnd)
{
    if (hwnd == 0 || g_spinner == 0) {
        return;
    }
    g_spinner_active = 1;
    g_spinner_frame = 0;
    SetWindowText(g_spinner, TEXT("Working |"));
    SetWindowPos(g_spinner, HWND_TOP, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    ShowWindow(g_spinner, g_view_mode == MEGACE_VIEW_FILES ? SW_SHOW : SW_HIDE);
    KillTimer(hwnd, MEGACE_SPINNER_TIMER);
    SetTimer(hwnd, MEGACE_SPINNER_TIMER, MEGACE_SPINNER_DELAY_MS, 0);
}

static void
stop_spinner(HWND hwnd)
{
    if (hwnd != 0) {
        KillTimer(hwnd, MEGACE_SPINNER_TIMER);
    }
    g_spinner_active = 0;
    if (g_spinner != 0) {
        ShowWindow(g_spinner, SW_HIDE);
    }
}

static void
advance_spinner(void)
{
    static const WCHAR frames[] = L"|/-\\";
    WCHAR text[16];

    if (g_spinner == 0) {
        return;
    }
    _snwprintf(text, sizeof(text) / sizeof(text[0]), L"Working %c",
        frames[g_spinner_frame & 3]);
    text[(sizeof(text) / sizeof(text[0])) - 1] = L'\0';
    g_spinner_frame++;
    SetWindowText(g_spinner, text);
}

static void
reset_file_item_nodes(void)
{
    if (g_file_item_nodes != 0 && g_file_item_capacity > 0) {
        memset(g_file_item_nodes, 0xff,
            sizeof(int) * (unsigned int)g_file_item_capacity);
    }
}

static void
free_file_item_nodes(void)
{
    if (g_file_item_nodes != 0) {
        LocalFree((HLOCAL)g_file_item_nodes);
    }
    g_file_item_nodes = 0;
    g_file_item_capacity = 0;
}

static int
ensure_file_item_capacity(int required)
{
    int *grown;
    int new_capacity;

    if (required <= g_file_item_capacity) {
        return 1;
    }

    new_capacity = g_file_item_capacity == 0 ? 256 : g_file_item_capacity;
    while (new_capacity < required) {
        if (new_capacity > 0x3fffffff) {
            return 0;
        }
        new_capacity *= 2;
    }

    grown = (int *)LocalAlloc(LPTR, sizeof(int) * (unsigned int)new_capacity);
    if (grown == 0) {
        return 0;
    }
    memset(grown, 0xff, sizeof(int) * (unsigned int)new_capacity);
    if (g_file_item_nodes != 0) {
        memcpy(grown, g_file_item_nodes,
            sizeof(int) * (unsigned int)g_file_item_capacity);
        LocalFree((HLOCAL)g_file_item_nodes);
    }

    g_file_item_nodes = grown;
    g_file_item_capacity = new_capacity;
    return 1;
}

static void
append_log_text(const WCHAR *text)
{
    int len;
    int end;

    if (g_log == 0 || text == 0) {
        return;
    }

    len = GetWindowTextLength(g_log);
    end = len;
    SendMessage(g_log, EM_SETSEL, (WPARAM)end, (LPARAM)end);
    SendMessage(g_log, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessage(g_log, EM_REPLACESEL, FALSE, (LPARAM)TEXT("\r\n"));
}

static void
set_view_mode(HWND hwnd, int view_mode)
{
    g_view_mode = view_mode;

    if (g_files != 0) {
        ShowWindow(g_files, view_mode == MEGACE_VIEW_FILES ? SW_SHOW : SW_HIDE);
    }
    if (g_email != 0) {
        ShowWindow(g_email, view_mode == MEGACE_VIEW_LOGIN ? SW_SHOW : SW_HIDE);
    }
    if (g_password != 0) {
        ShowWindow(g_password, view_mode == MEGACE_VIEW_LOGIN ? SW_SHOW : SW_HIDE);
    }
    if (g_sync_dir != 0) {
        ShowWindow(g_sync_dir,
            view_mode == MEGACE_VIEW_SETTINGS ? SW_SHOW : SW_HIDE);
    }
    if (g_sync_label != 0) {
        ShowWindow(g_sync_label,
            view_mode == MEGACE_VIEW_SETTINGS ? SW_SHOW : SW_HIDE);
    }
    if (g_text_size_label != 0) {
        ShowWindow(g_text_size_label,
            view_mode == MEGACE_VIEW_SETTINGS ? SW_SHOW : SW_HIDE);
    }
    if (g_text_size_edit != 0) {
        ShowWindow(g_text_size_edit,
            view_mode == MEGACE_VIEW_SETTINGS ? SW_SHOW : SW_HIDE);
    }
    if (g_sync_status_label != 0) {
        ShowWindow(g_sync_status_label,
            view_mode == MEGACE_VIEW_SYNC ? SW_SHOW : SW_HIDE);
    }
    if (g_sync_progress != 0) {
        ShowWindow(g_sync_progress,
            view_mode == MEGACE_VIEW_SYNC ? SW_SHOW : SW_HIDE);
    }
    if (g_create_folder_label != 0) {
        ShowWindow(g_create_folder_label,
            view_mode == MEGACE_VIEW_CREATE_FOLDER ? SW_SHOW : SW_HIDE);
    }
    if (g_create_folder_name != 0) {
        ShowWindow(g_create_folder_name,
            view_mode == MEGACE_VIEW_CREATE_FOLDER ? SW_SHOW : SW_HIDE);
    }
    if (g_rename_label != 0) {
        ShowWindow(g_rename_label,
            view_mode == MEGACE_VIEW_RENAME ? SW_SHOW : SW_HIDE);
    }
    if (g_rename_name != 0) {
        ShowWindow(g_rename_name,
            view_mode == MEGACE_VIEW_RENAME ? SW_SHOW : SW_HIDE);
    }
    if (GetDlgItem(hwnd, IDC_MEGACE_CREATEFOLDERGO) != 0) {
        ShowWindow(GetDlgItem(hwnd, IDC_MEGACE_CREATEFOLDERGO),
            view_mode == MEGACE_VIEW_CREATE_FOLDER ? SW_SHOW : SW_HIDE);
    }
    if (GetDlgItem(hwnd, IDC_MEGACE_RENAMEGO) != 0) {
        ShowWindow(GetDlgItem(hwnd, IDC_MEGACE_RENAMEGO),
            view_mode == MEGACE_VIEW_RENAME ? SW_SHOW : SW_HIDE);
    }
    if (GetDlgItem(hwnd, IDC_MEGACE_SAVESETTINGS) != 0) {
        ShowWindow(GetDlgItem(hwnd, IDC_MEGACE_SAVESETTINGS),
            view_mode == MEGACE_VIEW_SETTINGS ? SW_SHOW : SW_HIDE);
    }
    if (GetDlgItem(hwnd, IDC_MEGACE_LOGIN) != 0) {
        ShowWindow(GetDlgItem(hwnd, IDC_MEGACE_LOGIN),
            view_mode == MEGACE_VIEW_LOGIN ? SW_SHOW : SW_HIDE);
    }
    if (g_log != 0) {
        ShowWindow(g_log, view_mode == MEGACE_VIEW_LOGS ? SW_SHOW : SW_HIDE);
    }
    if (g_spinner != 0) {
        ShowWindow(g_spinner,
            g_spinner_active && view_mode == MEGACE_VIEW_FILES
                ? SW_SHOW
                : SW_HIDE);
    }

    layout_children(hwnd);
}

static void
append_log_ascii(const char *text)
{
    WCHAR wide[1024];

    if (text == 0) {
        return;
    }

    MultiByteToWideChar(CP_ACP, 0, text, -1, wide,
        sizeof(wide) / sizeof(wide[0]));
    wide[(sizeof(wide) / sizeof(wide[0])) - 1] = L'\0';
    append_log_text(wide);
}

static void
post_log_text(const WCHAR *text)
{
    WCHAR *copy;
    size_t len;

    if (g_main_window == 0 || text == 0) {
        return;
    }

    len = wcslen(text) + 1;
    copy = (WCHAR *)LocalAlloc(LPTR, len * sizeof(WCHAR));
    if (copy == 0) {
        return;
    }

    memcpy(copy, text, len * sizeof(WCHAR));
    PostMessage(g_main_window, WM_MEGACE_LOG, 0, (LPARAM)copy);
}

static void
post_log_ascii(const char *text)
{
    WCHAR wide[1024];

    if (text == 0) {
        return;
    }

    MultiByteToWideChar(CP_ACP, 0, text, -1, wide,
        sizeof(wide) / sizeof(wide[0]));
    wide[(sizeof(wide) / sizeof(wide[0])) - 1] = L'\0';
    post_log_text(wide);
}

static void
load_file_column_widths(void)
{
    WCHAR path[MAX_PATH];
    HANDLE file;
    DWORD read_bytes;
    int widths[3];

    if (!build_app_file_path(L"columns.dat", path,
        sizeof(path) / sizeof(path[0])))
    {
        return;
    }

    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    read_bytes = 0;
    memset(widths, 0, sizeof(widths));
    if (ReadFile(file, widths, sizeof(widths), &read_bytes, 0)
        && read_bytes == sizeof(widths)
        && widths[0] >= scale_x(60)
        && widths[1] >= scale_x(50)
        && widths[2] >= scale_x(40)
        && widths[0] <= 1000 && widths[1] <= 1000 && widths[2] <= 1000)
    {
        memcpy(g_file_column_widths, widths, sizeof(g_file_column_widths));
    }
    CloseHandle(file);
}

static void
save_file_column_widths(void)
{
    WCHAR path[MAX_PATH];
    HANDLE file;
    DWORD written;
    int i;

    if (g_files == 0) {
        return;
    }

    for (i = 0; i < 3; ++i) {
        int width;

        width = ListView_GetColumnWidth(g_files, i);
        if (width > 0) {
            g_file_column_widths[i] = width;
        }
    }

    if (!build_app_file_path(L"columns.dat", path,
        sizeof(path) / sizeof(path[0])))
    {
        return;
    }

    file = CreateFile(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    written = 0;
    WriteFile(file, g_file_column_widths,
        sizeof(g_file_column_widths), &written, 0);
    CloseHandle(file);
}

static void
set_default_sync_directory(void)
{
    if (!build_app_file_path(L"Sync", g_sync_directory,
        sizeof(g_sync_directory) / sizeof(g_sync_directory[0])))
    {
        _snwprintf(g_sync_directory,
            sizeof(g_sync_directory) / sizeof(g_sync_directory[0]),
            L"\\My Documents\\MegaCE Sync");
        g_sync_directory[
            (sizeof(g_sync_directory) / sizeof(g_sync_directory[0])) - 1] = L'\0';
    }
}

static void
load_settings(void)
{
    WCHAR path[MAX_PATH];
    HANDLE file;
    DWORD read_bytes;
    struct settings_file {
        char magic[8];
        WCHAR sync_directory[MAX_PATH];
        int sync_handle_count;
        char sync_handles[MEGACE_MAX_SYNC_HANDLES][16];
        int text_point_size;
    } settings;

    set_default_sync_directory();
    g_text_point_size = MEGACE_TEXT_POINT_DEFAULT;
    memset(g_sync_handles, 0, sizeof(g_sync_handles));
    g_sync_handle_count = 0;
    if (!build_app_file_path(L"settings.dat", path,
        sizeof(path) / sizeof(path[0])))
    {
        return;
    }

    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    read_bytes = 0;
    memset(&settings, 0, sizeof(settings));
    if (ReadFile(file, &settings, sizeof(settings), &read_bytes, 0)
        && read_bytes >= sizeof(WCHAR))
    {
        DWORD settings_v1_size;

        settings_v1_size = (DWORD)((char *)settings.sync_handles
            - (char *)&settings + sizeof(settings.sync_handles));
        if (read_bytes >= settings_v1_size
            && memcmp(settings.magic, "MCESCFG", 7) == 0)
        {
            memcpy(g_sync_directory, settings.sync_directory,
                sizeof(g_sync_directory));
            g_sync_directory[
                (sizeof(g_sync_directory) / sizeof(g_sync_directory[0])) - 1] = L'\0';
            if (settings.sync_handle_count > 0
                && settings.sync_handle_count <= MEGACE_MAX_SYNC_HANDLES)
            {
                g_sync_handle_count = settings.sync_handle_count;
                memcpy(g_sync_handles, settings.sync_handles,
                    sizeof(g_sync_handles));
            }
            if (read_bytes >=
                (DWORD)((char *)&settings.text_point_size - (char *)&settings
                    + sizeof(settings.text_point_size)))
            {
                g_text_point_size =
                    clamp_text_point_size(settings.text_point_size);
            }
        } else {
            memcpy(g_sync_directory, &settings, sizeof(g_sync_directory));
            g_sync_directory[
                (sizeof(g_sync_directory) / sizeof(g_sync_directory[0])) - 1] = L'\0';
        }
    } else {
        set_default_sync_directory();
    }
    CloseHandle(file);
}

static void
save_settings(void)
{
    WCHAR path[MAX_PATH];
    HANDLE file;
    DWORD written;
    struct settings_file {
        char magic[8];
        WCHAR sync_directory[MAX_PATH];
        int sync_handle_count;
        char sync_handles[MEGACE_MAX_SYNC_HANDLES][16];
        int text_point_size;
    } settings;
    WCHAR text_size[16];
    int parsed_size;

    if (g_sync_dir != 0) {
        GetWindowText(g_sync_dir, g_sync_directory,
            sizeof(g_sync_directory) / sizeof(g_sync_directory[0]));
        g_sync_directory[
            (sizeof(g_sync_directory) / sizeof(g_sync_directory[0])) - 1] = L'\0';
    }
    if (g_sync_directory[0] == L'\0') {
        set_default_sync_directory();
    }
    if (g_text_size_edit != 0) {
        GetWindowText(g_text_size_edit, text_size,
            sizeof(text_size) / sizeof(text_size[0]));
        text_size[(sizeof(text_size) / sizeof(text_size[0])) - 1] = L'\0';
        parsed_size = _wtoi(text_size);
        if (parsed_size > 0) {
            g_text_point_size = clamp_text_point_size(parsed_size);
        }
        update_text_size_controls();
        apply_text_size(g_main_window);
    }

    if (!build_app_file_path(L"settings.dat", path,
        sizeof(path) / sizeof(path[0])))
    {
        append_log_text(TEXT("Could not build settings.dat path."));
        return;
    }

    file = CreateFile(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        append_log_text(TEXT("Could not save settings.dat."));
        return;
    }

    written = 0;
    memset(&settings, 0, sizeof(settings));
    memcpy(settings.magic, "MCESCFG", 7);
    memcpy(settings.sync_directory, g_sync_directory,
        sizeof(settings.sync_directory));
    settings.sync_handle_count = g_sync_handle_count;
    memcpy(settings.sync_handles, g_sync_handles, sizeof(settings.sync_handles));
    settings.text_point_size = g_text_point_size;
    WriteFile(file, &settings, sizeof(settings), &written, 0);
    CloseHandle(file);
    append_log_text(TEXT("Settings saved."));
}

static void
setup_file_columns(void)
{
    LVCOLUMN col;

    if (g_files == 0) {
        return;
    }

    memset(&col, 0, sizeof(col));
    g_file_column_widths[0] = scale_x(150);
    g_file_column_widths[1] = scale_x(110);
    g_file_column_widths[2] = scale_x(70);
    load_file_column_widths();
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = TEXT("Name");
    col.cx = g_file_column_widths[0];
    col.iSubItem = 0;
    ListView_InsertColumn(g_files, 0, &col);

    col.pszText = TEXT("Date Modified");
    col.cx = g_file_column_widths[1];
    col.iSubItem = 1;
    ListView_InsertColumn(g_files, 1, &col);

    col.pszText = TEXT("Size");
    col.cx = g_file_column_widths[2];
    col.iSubItem = 2;
    ListView_InsertColumn(g_files, 2, &col);

    SendMessage(g_files, LVM_SETEXTENDEDLISTVIEWSTYLE,
        LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
}

static void
setup_file_icons(void)
{
    HICON icon;
    int i;
    int icon_ids[4];

    if (g_files == 0 || g_file_images != 0) {
        return;
    }

    g_file_images = ImageList_Create(g_list_icon_size, g_list_icon_size,
        ILC_COLOR | ILC_MASK, 4, 1);
    if (g_file_images == 0) {
        return;
    }
    ImageList_SetBkColor(g_file_images, CLR_NONE);

    icon_ids[0] = IDI_MEGACE_FILE;
    icon_ids[1] = IDI_MEGACE_FOLDER;
    icon_ids[2] = IDI_MEGACE_UP;
    icon_ids[3] = IDI_MEGACE_FOLDER_SYNC;

    for (i = 0; i < 4; ++i) {
        icon = (HICON)LoadImage(GetModuleHandle(0),
            MAKEINTRESOURCE(icon_ids[i]), IMAGE_ICON,
            g_list_icon_size, g_list_icon_size, 0);
        if (icon == 0) {
            continue;
        }
        ImageList_AddIcon(g_file_images, icon);
        DestroyIcon(icon);
    }

    ListView_SetImageList(g_files, g_file_images, LVSIL_SMALL);
}

static void
add_file_list_item(
    const WCHAR *name,
    const WCHAR *modified,
    const WCHAR *size,
    int image_index,
    int node_index
)
{
    LVITEM item;
    int index;

    if (g_files == 0 || name == 0) {
        return;
    }

    memset(&item, 0, sizeof(item));
    item.mask = LVIF_TEXT;
    if (image_index >= 0) {
        item.mask |= LVIF_IMAGE;
        item.iImage = image_index;
    }
    item.iItem = ListView_GetItemCount(g_files);
    item.iSubItem = 0;
    item.pszText = (WCHAR *)name;
    index = ListView_InsertItem(g_files, &item);
    if (index >= 0 && ensure_file_item_capacity(index + 1)) {
        g_file_item_nodes[index] = node_index;
        if (modified != 0) {
            ListView_SetItemText(g_files, index, 1, (WCHAR *)modified);
        }
        if (size != 0) {
            ListView_SetItemText(g_files, index, 2, (WCHAR *)size);
        }
    }
}

typedef struct megace_input_dialog {
    HWND parent;
    HWND edit;
    const WCHAR *title;
    const WCHAR *label;
    const WCHAR *initial;
    WCHAR *result;
    unsigned int result_size;
    int accepted;
} megace_input_dialog;

static LRESULT CALLBACK
input_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    megace_input_dialog *data;

    data = (megace_input_dialog *)GetWindowLong(hwnd, GWL_USERDATA);
    switch (msg) {
    case WM_CREATE:
    {
        CREATESTRUCT *cs;
        HINSTANCE instance;

        cs = (CREATESTRUCT *)lParam;
        data = (megace_input_dialog *)cs->lpCreateParams;
        SetWindowLong(hwnd, GWL_USERDATA, (LONG)data);
        instance = cs->hInstance;

        CreateWindow(TEXT("STATIC"), data->label,
            WS_CHILD | WS_VISIBLE,
            scale_x(8), scale_y(8), scale_x(220), scale_y(20),
            hwnd, 0, instance, 0);
        data->edit = CreateWindow(TEXT("EDIT"),
            data->initial != 0 ? data->initial : TEXT(""),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            scale_x(8), scale_y(32), scale_x(220), scale_y(24),
            hwnd, (HMENU)1, instance, 0);
        CreateWindow(TEXT("BUTTON"), TEXT("OK"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            scale_x(36), scale_y(68), scale_x(72), scale_y(26),
            hwnd, (HMENU)IDOK, instance, 0);
        CreateWindow(TEXT("BUTTON"), TEXT("Cancel"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            scale_x(128), scale_y(68), scale_x(72), scale_y(26),
            hwnd, (HMENU)IDCANCEL, instance, 0);
        SetFocus(data->edit);
        SendMessage(data->edit, EM_SETSEL, 0, -1);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            if (data != 0 && data->result != 0 && data->result_size > 0) {
                GetWindowText(data->edit, data->result, data->result_size);
                data->result[data->result_size - 1] = L'\0';
            }
            if (data != 0) {
                data->accepted = 1;
            }
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static int
prompt_for_text(
    HWND parent,
    const WCHAR *title,
    const WCHAR *label,
    const WCHAR *initial,
    WCHAR *result,
    unsigned int result_size
)
{
    WNDCLASS wc;
    HINSTANCE instance;
    megace_input_dialog data;
    HWND dialog;
    RECT parent_rect;
    int dialog_width;
    int dialog_height;
    int x;
    int y;
    MSG msg;

    if (result == 0 || result_size == 0) {
        return 0;
    }
    result[0] = L'\0';

    instance = GetModuleHandle(0);
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = input_wnd_proc;
    wc.hInstance = instance;
    wc.lpszClassName = MEGACE_INPUT_CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(0, IDC_ARROW);
    RegisterClass(&wc);

    memset(&data, 0, sizeof(data));
    data.parent = parent;
    data.title = title;
    data.label = label;
    data.initial = initial;
    data.result = result;
    data.result_size = result_size;

    GetWindowRect(parent, &parent_rect);
    dialog_width = scale_x(240);
    dialog_height = scale_y(125);
    x = parent_rect.left
        + ((parent_rect.right - parent_rect.left) - dialog_width) / 2;
    y = parent_rect.top
        + ((parent_rect.bottom - parent_rect.top) - dialog_height) / 2;
    if (x < 0) {
        x = 0;
    }
    if (y < 0) {
        y = 0;
    }

    EnableWindow(parent, FALSE);
    dialog = CreateWindowEx(WS_EX_DLGMODALFRAME, MEGACE_INPUT_CLASS_NAME,
        title != 0 ? title : TEXT("MegaCE"),
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        x, y, dialog_width, dialog_height,
        parent, 0, instance, &data);
    if (dialog == 0) {
        EnableWindow(parent, TRUE);
        SetActiveWindow(parent);
        return 0;
    }

    while (IsWindow(dialog) && GetMessage(&msg, 0, 0, 0)) {
        if (!IsDialogMessage(dialog, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    EnableWindow(parent, TRUE);
    SetActiveWindow(parent);
    return data.accepted && result[0] != L'\0';
}

static int
wide_to_utf8_or_acp(const WCHAR *wide, char *out, unsigned int out_size)
{
    int len;

    if (wide == 0 || out == 0 || out_size == 0) {
        return 0;
    }
    out[0] = '\0';
    len = WideCharToMultiByte(CP_UTF8, 0, wide, -1,
        out, out_size, 0, 0);
    if (len <= 0) {
        len = WideCharToMultiByte(CP_ACP, 0, wide, -1,
            out, out_size, 0, 0);
    }
    if (len <= 0) {
        out[0] = '\0';
        return 0;
    }
    out[out_size - 1] = '\0';
    return 1;
}

static void
format_node_name(const mega_node_info *node, WCHAR *label, unsigned int label_size)
{
    WCHAR wide_name[128];
    const char *name;
    WCHAR *fallback;

    if (label == 0 || label_size == 0) {
        return;
    }

    label[0] = L'\0';
    if (node == 0) {
        return;
    }

    if (node->name[0] != '\0') {
        name = node->name;
        if (MultiByteToWideChar(CP_UTF8, 0, name, -1, wide_name,
            sizeof(wide_name) / sizeof(wide_name[0])) <= 0)
        {
            MultiByteToWideChar(CP_ACP, 0, name, -1, wide_name,
                sizeof(wide_name) / sizeof(wide_name[0]));
        }
        wide_name[(sizeof(wide_name) / sizeof(wide_name[0])) - 1] = L'\0';
    } else {
        fallback = node->type == 0 ? L"(unnamed file)" : L"(unnamed folder)";
        _snwprintf(wide_name, sizeof(wide_name) / sizeof(wide_name[0]),
            L"%s", fallback);
        wide_name[(sizeof(wide_name) / sizeof(wide_name[0])) - 1] = L'\0';
    }

    _snwprintf(label, label_size, L"%s", wide_name);
    label[label_size - 1] = L'\0';
}

static void
format_node_date(unsigned int timestamp, WCHAR *text, unsigned int text_size)
{
    FILETIME ft;
    FILETIME local_ft;
    SYSTEMTIME st;
    unsigned __int64 ticks;

    if (text == 0 || text_size == 0) {
        return;
    }
    text[0] = L'\0';
    if (timestamp == 0) {
        return;
    }

    ticks = ((unsigned __int64)timestamp + 11644473600ULL) * 10000000ULL;
    ft.dwLowDateTime = (DWORD)(ticks & 0xffffffff);
    ft.dwHighDateTime = (DWORD)(ticks >> 32);
    if (!FileTimeToLocalFileTime(&ft, &local_ft)) {
        local_ft = ft;
    }
    if (!FileTimeToSystemTime(&local_ft, &st)) {
        return;
    }

    _snwprintf(text, text_size, L"%04u-%02u-%02u %02u:%02u",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    text[text_size - 1] = L'\0';
}

static int
get_bottom_reserved_height(void)
{
    RECT bar_rect;
    int height;

    height = 0;
    if (g_menu_bar != 0 && GetWindowRect(g_menu_bar, &bar_rect)) {
        height = bar_rect.bottom - bar_rect.top;
    }
    if (height < scale_y(36)) {
        height = g_menu_bar != 0 ? scale_y(36) : 0;
    }
    if (height > 0) {
        height += scale_y(4);
    }
    return height;
}

static void
format_node_size(const mega_node_info *node, WCHAR *text, unsigned int text_size)
{
    unsigned __int64 value;
    const WCHAR *unit;

    if (text == 0 || text_size == 0) {
        return;
    }
    text[0] = L'\0';
    if (node == 0 || node->type != 0) {
        return;
    }

    value = node->size;
    unit = L"B";
    if (value >= 1024ULL) {
        value = (value + 512ULL) / 1024ULL;
        unit = L"KB";
    }
    if (value >= 1024ULL && unit[0] == L'K') {
        value = (value + 512ULL) / 1024ULL;
        unit = L"MB";
    }
    if (value >= 1024ULL && unit[0] == L'M') {
        value = (value + 512ULL) / 1024ULL;
        unit = L"GB";
    }

    _snwprintf(text, text_size, L"%lu %s", (unsigned long)value, unit);
    text[text_size - 1] = L'\0';
}

static int
compare_wide_names(const WCHAR *left, const WCHAR *right)
{
    int result;

    result = CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE,
        left != 0 ? left : L"", -1,
        right != 0 ? right : L"", -1);
    if (result == CSTR_LESS_THAN) {
        return -1;
    }
    if (result == CSTR_GREATER_THAN) {
        return 1;
    }
    return wcscmp(left != 0 ? left : L"", right != 0 ? right : L"");
}

static int __cdecl
compare_file_sort_entries(const void *left, const void *right)
{
    const file_sort_entry *a;
    const file_sort_entry *b;
    int result;

    a = (const file_sort_entry *)left;
    b = (const file_sort_entry *)right;

    if (g_file_sort_column == 0) {
        int a_group;
        int b_group;

        if (g_file_sort_reverse) {
            a_group = a->node.type == 0 ? 0 : 1;
            b_group = b->node.type == 0 ? 0 : 1;
        } else {
            a_group = a->node.type == 0 ? 1 : 0;
            b_group = b->node.type == 0 ? 1 : 0;
        }
        if (a_group != b_group) {
            return a_group - b_group;
        }
        return compare_wide_names(a->label, b->label);
    }

    if (g_file_sort_column == 1) {
        if (a->node.mtime < b->node.mtime) {
            result = -1;
        } else if (a->node.mtime > b->node.mtime) {
            result = 1;
        } else {
            result = 0;
        }
        if (g_file_sort_reverse) {
            result = -result;
        }
        if (result != 0) {
            return result;
        }
        return compare_wide_names(a->label, b->label);
    }

    if (a->node.size < b->node.size) {
        result = -1;
    } else if (a->node.size > b->node.size) {
        result = 1;
    } else {
        result = 0;
    }
    if (g_file_sort_reverse) {
        result = -result;
    }
    if (result != 0) {
        return result;
    }
    return compare_wide_names(a->label, b->label);
}

static void
sanitize_file_name(WCHAR *name)
{
    unsigned int i;

    if (name == 0 || name[0] == L'\0') {
        return;
    }

    for (i = 0; name[i] != L'\0'; ++i) {
        if (name[i] == L'\\' || name[i] == L'/' || name[i] == L':'
            || name[i] == L'*' || name[i] == L'?' || name[i] == L'"'
            || name[i] == L'<' || name[i] == L'>' || name[i] == L'|')
        {
            name[i] = L'_';
        }
    }
}

static void
node_name_to_wide(const mega_node_info *node, WCHAR *name, unsigned int name_size)
{
    const char *source;

    if (name == 0 || name_size == 0) {
        return;
    }
    name[0] = L'\0';
    if (node == 0) {
        return;
    }

    source = node->name[0] != '\0' ? node->name : node->handle;
    if (MultiByteToWideChar(CP_UTF8, 0, source, -1, name, name_size) <= 0) {
        MultiByteToWideChar(CP_ACP, 0, source, -1, name, name_size);
    }
    name[name_size - 1] = L'\0';
    sanitize_file_name(name);
}

static void
unix_time_to_filetime(unsigned int timestamp, FILETIME *ft)
{
    unsigned __int64 ticks;

    if (ft == 0) {
        return;
    }
    ticks = ((unsigned __int64)timestamp + 11644473600ULL) * 10000000ULL;
    ft->dwLowDateTime = (DWORD)(ticks & 0xffffffff);
    ft->dwHighDateTime = (DWORD)(ticks >> 32);
}

static int
ensure_directory_tree(const WCHAR *path)
{
    WCHAR partial[MAX_PATH];
    unsigned int i;
    unsigned int len;

    if (path == 0 || path[0] == L'\0') {
        return 0;
    }

    _snwprintf(partial, sizeof(partial) / sizeof(partial[0]), L"%s", path);
    partial[(sizeof(partial) / sizeof(partial[0])) - 1] = L'\0';
    len = (unsigned int)wcslen(partial);
    for (i = 1; i < len; ++i) {
        if (partial[i] == L'\\' || partial[i] == L'/') {
            WCHAR saved;

            saved = partial[i];
            partial[i] = L'\0';
            if (wcslen(partial) > 0) {
                CreateDirectory(partial, 0);
            }
            partial[i] = saved;
        }
    }
    return CreateDirectory(partial, 0) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static int
ensure_parent_directory(const WCHAR *file_path)
{
    WCHAR dir[MAX_PATH];
    int i;

    if (file_path == 0 || file_path[0] == L'\0') {
        return 0;
    }
    _snwprintf(dir, sizeof(dir) / sizeof(dir[0]), L"%s", file_path);
    dir[(sizeof(dir) / sizeof(dir[0])) - 1] = L'\0';
    for (i = (int)wcslen(dir) - 1; i >= 0; --i) {
        if (dir[i] == L'\\' || dir[i] == L'/') {
            dir[i] = L'\0';
            return ensure_directory_tree(dir);
        }
    }
    return 1;
}

static int
path_is_under_sync_directory(const WCHAR *path)
{
    unsigned int base_len;

    if (path == 0 || path[0] == L'\0' || g_sync_directory[0] == L'\0') {
        return 0;
    }
    base_len = (unsigned int)wcslen(g_sync_directory);
    if (_wcsnicmp(path, g_sync_directory, base_len) != 0) {
        return 0;
    }
    return path[base_len] == L'\0'
        || path[base_len] == L'\\'
        || path[base_len] == L'/';
}

static int
directory_exists(const WCHAR *path)
{
    DWORD attrs;

    if (path == 0 || path[0] == L'\0') {
        return 0;
    }
    attrs = GetFileAttributes(path);
    return attrs != 0xffffffffUL
        && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static int
get_local_directory_state(const WCHAR *path, unsigned int *mtime)
{
    WIN32_FILE_ATTRIBUTE_DATA data;

    if (mtime != 0) {
        *mtime = 0;
    }
    if (path == 0 || path[0] == L'\0') {
        return 0;
    }
    if (!GetFileAttributesEx(path, GetFileExInfoStandard, &data)
        || (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return 0;
    }
    if (mtime != 0) {
        *mtime = filetime_to_unix_time(&data.ftLastWriteTime);
    }
    return 1;
}

static int
delete_local_tree(const WCHAR *path)
{
    WCHAR search[MAX_PATH];
    HANDLE find;
    WIN32_FIND_DATA data;
    int ok;

    if (!path_is_under_sync_directory(path) || !directory_exists(path)) {
        return 0;
    }

    _snwprintf(search, sizeof(search) / sizeof(search[0]), L"%s\\*", path);
    search[(sizeof(search) / sizeof(search[0])) - 1] = L'\0';
    find = FindFirstFile(search, &data);
    ok = 1;
    if (find != INVALID_HANDLE_VALUE) {
        do {
            WCHAR child[MAX_PATH];

            if (wcscmp(data.cFileName, L".") == 0
                || wcscmp(data.cFileName, L"..") == 0)
            {
                continue;
            }
            _snwprintf(child, sizeof(child) / sizeof(child[0]), L"%s\\%s",
                path, data.cFileName);
            child[(sizeof(child) / sizeof(child[0])) - 1] = L'\0';
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                if (!delete_local_tree(child)) {
                    ok = 0;
                }
            } else if (!DeleteFile(child)) {
                ok = 0;
            }
        } while (FindNextFile(find, &data));
        FindClose(find);
    }
    if (!RemoveDirectory(path)) {
        ok = 0;
    }
    return ok;
}

static int
append_path_part(WCHAR *path, unsigned int path_size, const WCHAR *part)
{
    unsigned int len;

    if (path == 0 || path_size == 0 || part == 0 || part[0] == L'\0') {
        return 0;
    }
    len = (unsigned int)wcslen(path);
    if (len + 1 >= path_size) {
        return 0;
    }
    if (len > 0 && path[len - 1] != L'\\' && path[len - 1] != L'/') {
        path[len++] = L'\\';
        path[len] = L'\0';
    }
    if (len + wcslen(part) >= path_size) {
        return 0;
    }
    wcscat(path, part);
    return 1;
}

static int
build_node_relative_path(int node_index, WCHAR *path, unsigned int path_size)
{
    mega_node_info chain[64];
    mega_node_info node;
    int count;
    int i;
    int guard;

    if (path == 0 || path_size == 0) {
        return 0;
    }
    path[0] = L'\0';
    if (!mega_api_get_node(node_index, &node)) {
        return 0;
    }

    count = 0;
    guard = 0;
    while (guard++ < 128 && node.type != 2 && node.handle[0] != '\0') {
        if (count >= (int)(sizeof(chain) / sizeof(chain[0]))) {
            return 0;
        }
        chain[count++] = node;
        if (node.parent[0] == '\0'
            || !mega_api_get_node(mega_api_find_node_by_handle(node.parent), &node))
        {
            break;
        }
    }

    for (i = count - 1; i >= 0; --i) {
        WCHAR name[128];

        node_name_to_wide(&chain[i], name, sizeof(name) / sizeof(name[0]));
        if (!append_path_part(path, path_size, name)) {
            return 0;
        }
    }
    return path[0] != L'\0';
}

static int
build_base_plain_path(const WCHAR *base, int node_index, WCHAR *path, unsigned int path_size)
{
    WCHAR relative[MAX_PATH];

    if (base == 0 || base[0] == L'\0' || path == 0 || path_size == 0) {
        return 0;
    }
    _snwprintf(path, path_size, L"%s", base);
    path[path_size - 1] = L'\0';
    if (!build_node_relative_path(node_index, relative,
        sizeof(relative) / sizeof(relative[0])))
    {
        return 0;
    }
    return append_path_part(path, path_size, relative);
}

static int
build_sync_plain_path(int node_index, WCHAR *path, unsigned int path_size)
{
    if (g_sync_directory[0] == L'\0') {
        set_default_sync_directory();
    }
    return build_base_plain_path(g_sync_directory, node_index, path, path_size);
}

static int
build_download_tree_plain_path(int node_index, WCHAR *path, unsigned int path_size)
{
    WCHAR downloads_path[MAX_PATH];

    _snwprintf(downloads_path,
        sizeof(downloads_path) / sizeof(downloads_path[0]),
        L"\\My Documents\\Mega Downloads");
    downloads_path[(sizeof(downloads_path) / sizeof(downloads_path[0])) - 1] = L'\0';
    return build_base_plain_path(downloads_path, node_index, path, path_size);
}

static int
node_matches_handle_or_descendant(int node_index, const char *root_handle)
{
    mega_node_info node;
    int guard;

    if (root_handle == 0 || root_handle[0] == '\0') {
        return 0;
    }
    if (!mega_api_get_node(node_index, &node)) {
        return 0;
    }

    guard = 0;
    while (guard++ < 128 && node.handle[0] != '\0') {
        if (strcmp(node.handle, root_handle) == 0) {
            return 1;
        }
        if (node.parent[0] == '\0') {
            break;
        }
        node_index = mega_api_find_node_by_handle(node.parent);
        if (node_index < 0 || !mega_api_get_node(node_index, &node)) {
            break;
        }
    }
    return 0;
}

static int
node_is_in_current_sync(int node_index)
{
    int i;

    if (g_sync_handle_count <= 0) {
        return 1;
    }
    for (i = 0; i < g_sync_handle_count; ++i) {
        if (node_matches_handle_or_descendant(node_index, g_sync_handles[i])) {
            return 1;
        }
    }
    return 0;
}

static int
node_is_explicit_sync_selection(int node_index)
{
    mega_node_info node;
    int i;

    if (!mega_api_get_node(node_index, &node)) {
        return 0;
    }
    for (i = 0; i < g_sync_handle_count; ++i) {
        if (strcmp(g_sync_handles[i], node.handle) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
wide_name_equals(const WCHAR *left, const WCHAR *right)
{
    return compare_wide_names(left, right) == 0;
}

static int
find_remote_child_by_wide_name(
    const char *parent_handle,
    const WCHAR *name,
    int type,
    mega_node_info *found,
    int *found_index
)
{
    int offset;
    mega_node_info child;

    if (found_index != 0) {
        *found_index = -1;
    }
    if (parent_handle == 0 || parent_handle[0] == '\0'
        || name == 0 || name[0] == L'\0')
    {
        return 0;
    }

    offset = 0;
    while (mega_api_get_child_node(parent_handle, offset, &child)) {
        WCHAR child_name[128];

        if (child.type == type) {
            node_name_to_wide(&child, child_name,
                sizeof(child_name) / sizeof(child_name[0]));
            if (wide_name_equals(child_name, name)) {
                if (found != 0) {
                    *found = child;
                }
                if (found_index != 0) {
                    *found_index = mega_api_find_node_by_handle(child.handle);
                }
                return 1;
            }
        }
        offset++;
    }
    return 0;
}

static int
sync_should_skip_local_temp_file(const WCHAR *name)
{
    unsigned int len;

    if (name == 0) {
        return 1;
    }
    len = (unsigned int)wcslen(name);
    if (len >= 8 && _wcsicmp(name + len - 8, L".megaenc") == 0) {
        return 1;
    }
    if (len >= 11 && _wcsicmp(name + len - 11, L".megaupload") == 0) {
        return 1;
    }
    return 0;
}

static int
find_local_folder_rename_candidate(
    const WCHAR *old_path,
    const char *remote_parent,
    WCHAR *new_path,
    unsigned int new_path_size,
    WCHAR *new_name,
    unsigned int new_name_size
)
{
    WCHAR parent_path[MAX_PATH];
    WCHAR search[MAX_PATH];
    HANDLE find;
    WIN32_FIND_DATA data;
    int slash;
    int candidate_count;

    if (old_path == 0 || old_path[0] == L'\0'
        || remote_parent == 0 || remote_parent[0] == '\0'
        || new_path == 0 || new_path_size == 0
        || new_name == 0 || new_name_size == 0)
    {
        return 0;
    }

    _snwprintf(parent_path, sizeof(parent_path) / sizeof(parent_path[0]),
        L"%s", old_path);
    parent_path[(sizeof(parent_path) / sizeof(parent_path[0])) - 1] = L'\0';
    for (slash = (int)wcslen(parent_path) - 1; slash >= 0; --slash) {
        if (parent_path[slash] == L'\\' || parent_path[slash] == L'/') {
            parent_path[slash] = L'\0';
            break;
        }
    }
    if (slash < 0 || parent_path[0] == L'\0'
        || !path_is_under_sync_directory(parent_path))
    {
        return 0;
    }

    _snwprintf(search, sizeof(search) / sizeof(search[0]), L"%s\\*",
        parent_path);
    search[(sizeof(search) / sizeof(search[0])) - 1] = L'\0';
    find = FindFirstFile(search, &data);
    if (find == INVALID_HANDLE_VALUE) {
        return 0;
    }

    candidate_count = 0;
    do {
        WCHAR child_path[MAX_PATH];

        if (wcscmp(data.cFileName, L".") == 0
            || wcscmp(data.cFileName, L"..") == 0
            || (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
            || sync_should_skip_local_temp_file(data.cFileName))
        {
            continue;
        }
        _snwprintf(child_path, sizeof(child_path) / sizeof(child_path[0]),
            L"%s\\%s", parent_path, data.cFileName);
        child_path[(sizeof(child_path) / sizeof(child_path[0])) - 1] = L'\0';
        if (_wcsicmp(child_path, old_path) == 0) {
            continue;
        }
        if (find_remote_child_by_wide_name(remote_parent, data.cFileName,
            1, 0, 0))
        {
            continue;
        }

        candidate_count++;
        if (candidate_count == 1) {
            _snwprintf(new_path, new_path_size, L"%s", child_path);
            new_path[new_path_size - 1] = L'\0';
            _snwprintf(new_name, new_name_size, L"%s", data.cFileName);
            new_name[new_name_size - 1] = L'\0';
        } else {
            break;
        }
    } while (FindNextFile(find, &data));
    FindClose(find);

    return candidate_count == 1;
}

static void
sync_upload_local_tree(
    const char *parent_handle,
    const WCHAR *local_dir,
    int *folders_created,
    int *uploaded,
    int *skipped,
    int *failed
)
{
    WCHAR search[MAX_PATH];
    HANDLE find;
    WIN32_FIND_DATA data;

    if (parent_handle == 0 || parent_handle[0] == '\0'
        || local_dir == 0 || local_dir[0] == L'\0')
    {
        return;
    }

    _snwprintf(search, sizeof(search) / sizeof(search[0]), L"%s\\*",
        local_dir);
    search[(sizeof(search) / sizeof(search[0])) - 1] = L'\0';
    find = FindFirstFile(search, &data);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        WCHAR child_path[MAX_PATH];

        if (wcscmp(data.cFileName, L".") == 0
            || wcscmp(data.cFileName, L"..") == 0)
        {
            continue;
        }
        if (sync_should_skip_local_temp_file(data.cFileName)) {
            continue;
        }
        _snwprintf(child_path, sizeof(child_path) / sizeof(child_path[0]),
            L"%s\\%s", local_dir, data.cFileName);
        child_path[(sizeof(child_path) / sizeof(child_path[0])) - 1] = L'\0';

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            mega_node_info remote_folder;
            char new_handle[16];
            char utf8_name[128];
            mega_api_result create_result;

            if (find_remote_child_by_wide_name(parent_handle, data.cFileName,
                1, &remote_folder, 0))
            {
                sync_upload_local_tree(remote_folder.handle, child_path,
                    folders_created, uploaded, skipped, failed);
                continue;
            }

            if (!wide_to_utf8_or_acp(data.cFileName, utf8_name,
                sizeof(utf8_name)))
            {
                (*failed)++;
                continue;
            }
            memset(&create_result, 0, sizeof(create_result));
            new_handle[0] = '\0';
            post_sync_status(TEXT("Uploading folders"), 90);
            if (mega_api_create_folder(parent_handle, utf8_name, new_handle,
                sizeof(new_handle), &create_result))
            {
                mega_node_info created_folder;

                mega_api_add_local_folder_node(new_handle, parent_handle,
                    utf8_name);
                memset(&created_folder, 0, sizeof(created_folder));
                _snprintf(created_folder.handle, sizeof(created_folder.handle),
                    "%s", new_handle);
                created_folder.handle[sizeof(created_folder.handle) - 1] = '\0';
                _snprintf(created_folder.parent, sizeof(created_folder.parent),
                    "%s", parent_handle);
                created_folder.parent[sizeof(created_folder.parent) - 1] = '\0';
                _snprintf(created_folder.name, sizeof(created_folder.name),
                    "%s", utf8_name);
                created_folder.name[sizeof(created_folder.name) - 1] = '\0';
                created_folder.type = 1;
                sync_state_upsert_folder(&created_folder, child_path);
                (*folders_created)++;
                sync_upload_local_tree(new_handle, child_path,
                    folders_created, uploaded, skipped, failed);
            } else {
                post_log_ascii(create_result.error[0] != '\0'
                    ? create_result.error
                    : "Local folder upload failed.");
                (*failed)++;
            }
        } else {
            mega_node_info existing_file;
            WCHAR encrypted_path[MAX_PATH];
            char utf8_name[128];
            char new_handle[16];
            mega_api_result upload_result;
            mega_node_info uploaded_node;
            unsigned __int64 local_size;
            unsigned int local_mtime;

            if (find_remote_child_by_wide_name(parent_handle, data.cFileName,
                0, &existing_file, 0))
            {
                (*skipped)++;
                continue;
            }
            if (!wide_to_utf8_or_acp(data.cFileName, utf8_name,
                sizeof(utf8_name)))
            {
                (*failed)++;
                continue;
            }
            _snwprintf(encrypted_path,
                sizeof(encrypted_path) / sizeof(encrypted_path[0]),
                L"%s.megaupload", child_path);
            encrypted_path[(sizeof(encrypted_path)
                / sizeof(encrypted_path[0])) - 1] = L'\0';
            memset(&upload_result, 0, sizeof(upload_result));
            new_handle[0] = '\0';
            post_sync_status(TEXT("Uploading files"), 90);
            if (mega_api_upload_file_update("", parent_handle, utf8_name,
                child_path, encrypted_path, new_handle, sizeof(new_handle),
                &upload_result))
            {
                if (new_handle[0] != '\0') {
                    memset(&uploaded_node, 0, sizeof(uploaded_node));
                    _snprintf(uploaded_node.handle, sizeof(uploaded_node.handle),
                        "%s", new_handle);
                    uploaded_node.handle[sizeof(uploaded_node.handle) - 1] = '\0';
                    _snprintf(uploaded_node.parent, sizeof(uploaded_node.parent),
                        "%s", parent_handle);
                    uploaded_node.parent[sizeof(uploaded_node.parent) - 1] = '\0';
                    _snprintf(uploaded_node.name, sizeof(uploaded_node.name),
                        "%s", utf8_name);
                    uploaded_node.name[sizeof(uploaded_node.name) - 1] = '\0';
                    uploaded_node.type = 0;
                    if (get_local_file_state(child_path, &local_size,
                        &local_mtime))
                    {
                        uploaded_node.size = local_size;
                        uploaded_node.mtime = local_mtime;
                    }
                    sync_state_upsert_file(&uploaded_node, child_path);
                } else {
                    sync_state_upsert_pending_local(child_path);
                    post_log_ascii("Upload accepted; handle will be picked up on next refresh.");
                }
                (*uploaded)++;
            } else {
                post_log_ascii(upload_result.error[0] != '\0'
                    ? upload_result.error
                    : "Local file upload failed.");
                (*failed)++;
            }
        }
    } while (FindNextFile(find, &data));

    FindClose(find);
}

static int
node_is_in_download_root(int node_index)
{
    if (g_download_root_handle[0] == '\0') {
        return 1;
    }
    return node_matches_handle_or_descendant(node_index, g_download_root_handle);
}

static void
add_node_to_current_sync(int node_index)
{
    mega_node_info node;
    int i;
    char line[128];

    if (!mega_api_get_node(node_index, &node) || node.handle[0] == '\0') {
        append_log_text(TEXT("Sync This failed: invalid selection."));
        return;
    }
    for (i = 0; i < g_sync_handle_count; ++i) {
        if (strcmp(g_sync_handles[i], node.handle) == 0) {
            append_log_text(TEXT("Selection is already in the current sync."));
            return;
        }
    }
    if (g_sync_handle_count >= MEGACE_MAX_SYNC_HANDLES) {
        append_log_text(TEXT("Sync selection list is full."));
        return;
    }
    _snprintf(g_sync_handles[g_sync_handle_count],
        sizeof(g_sync_handles[g_sync_handle_count]), "%s", node.handle);
    g_sync_handles[g_sync_handle_count]
        [sizeof(g_sync_handles[g_sync_handle_count]) - 1] = '\0';
    g_sync_handle_count++;
    save_settings();
    populate_file_list();
    _snprintf(line, sizeof(line), "Added selection to current sync. Items=%d",
        g_sync_handle_count);
    line[sizeof(line) - 1] = '\0';
    append_log_ascii(line);
}

static void
sync_add_conflict(const mega_node_info *node, const WCHAR *path, const WCHAR *name)
{
    sync_conflict_entry *entry;

    if (node == 0 || path == 0 || name == 0) {
        return;
    }
    if (g_sync_conflict_count >= MEGACE_MAX_SYNC_CONFLICTS) {
        return;
    }
    entry = &g_sync_conflicts[g_sync_conflict_count++];
    memset(entry, 0, sizeof(*entry));
    entry->node = *node;
    _snwprintf(entry->path, sizeof(entry->path) / sizeof(entry->path[0]),
        L"%s", path);
    entry->path[(sizeof(entry->path) / sizeof(entry->path[0])) - 1] = L'\0';
    _snwprintf(entry->name, sizeof(entry->name) / sizeof(entry->name[0]),
        L"%s", name);
    entry->name[(sizeof(entry->name) / sizeof(entry->name[0])) - 1] = L'\0';
}

static void
remove_node_from_current_sync(int node_index)
{
    mega_node_info node;
    int i;
    int found;
    char line[128];

    if (!mega_api_get_node(node_index, &node) || node.handle[0] == '\0') {
        append_log_text(TEXT("Remove from sync failed: invalid selection."));
        return;
    }

    found = -1;
    for (i = 0; i < g_sync_handle_count; ++i) {
        if (strcmp(g_sync_handles[i], node.handle) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) {
        append_log_text(TEXT("Selection is not directly in the current sync."));
        return;
    }

    for (i = found; i < g_sync_handle_count - 1; ++i) {
        memcpy(g_sync_handles[i], g_sync_handles[i + 1],
            sizeof(g_sync_handles[i]));
    }
    memset(g_sync_handles[g_sync_handle_count - 1], 0,
        sizeof(g_sync_handles[g_sync_handle_count - 1]));
    g_sync_handle_count--;
    save_settings();
    populate_file_list();
    _snprintf(line, sizeof(line), "Removed selection from current sync. Items=%d",
        g_sync_handle_count);
    line[sizeof(line) - 1] = '\0';
    append_log_ascii(line);
}

static unsigned int
filetime_to_unix_time(const FILETIME *ft)
{
    unsigned __int64 ticks;
    unsigned __int64 seconds;

    if (ft == 0) {
        return 0;
    }
    ticks = (((unsigned __int64)ft->dwHighDateTime) << 32)
        | (unsigned __int64)ft->dwLowDateTime;
    seconds = ticks / 10000000ULL;
    if (seconds <= 11644473600ULL) {
        return 0;
    }
    return (unsigned int)(seconds - 11644473600ULL);
}

static int
get_local_file_state(
    const WCHAR *path,
    unsigned __int64 *size,
    unsigned int *mtime
)
{
    HANDLE file;
    DWORD size_low;
    DWORD size_high;
    FILETIME local_ft;

    if (size != 0) {
        *size = 0;
    }
    if (mtime != 0) {
        *mtime = 0;
    }
    if (path == 0 || path[0] == L'\0') {
        return 0;
    }

    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }

    size_high = 0;
    size_low = GetFileSize(file, &size_high);
    memset(&local_ft, 0, sizeof(local_ft));
    GetFileTime(file, 0, 0, &local_ft);
    CloseHandle(file);

    if (size != 0) {
        *size = (((unsigned __int64)size_high) << 32)
            | (unsigned __int64)size_low;
    }
    if (mtime != 0) {
        *mtime = filetime_to_unix_time(&local_ft);
    }
    return 1;
}

static void
sync_state_reset(void)
{
    if (g_sync_state_records != 0) {
        LocalFree((HLOCAL)g_sync_state_records);
    }
    g_sync_state_records = 0;
    g_sync_state_count = 0;
    g_sync_state_capacity = 0;
}

static int
sync_state_ensure_capacity(int required)
{
    sync_state_record *grown;
    int new_capacity;

    if (required <= g_sync_state_capacity) {
        return 1;
    }
    new_capacity = g_sync_state_capacity == 0 ? 128 : g_sync_state_capacity;
    while (new_capacity < required) {
        if (new_capacity > 0x3fffffff) {
            return 0;
        }
        new_capacity *= 2;
    }

    grown = (sync_state_record *)LocalAlloc(LPTR,
        sizeof(sync_state_record) * (unsigned int)new_capacity);
    if (grown == 0) {
        return 0;
    }
    if (g_sync_state_records != 0) {
        memcpy(grown, g_sync_state_records,
            sizeof(sync_state_record) * (unsigned int)g_sync_state_count);
        LocalFree((HLOCAL)g_sync_state_records);
    }
    g_sync_state_records = grown;
    g_sync_state_capacity = new_capacity;
    return 1;
}

static sync_state_record *
sync_state_find_by_handle(const char *handle)
{
    int i;

    if (handle == 0 || handle[0] == '\0') {
        return 0;
    }
    for (i = 0; i < g_sync_state_count; ++i) {
        if (strcmp(g_sync_state_records[i].handle, handle) == 0) {
            return &g_sync_state_records[i];
        }
    }
    return 0;
}

static sync_state_record *
sync_state_find_by_path(const WCHAR *plain_path)
{
    int i;

    if (plain_path == 0 || plain_path[0] == L'\0') {
        return 0;
    }
    for (i = 0; i < g_sync_state_count; ++i) {
        if (g_sync_state_records[i].local_path[0] != L'\0'
            && _wcsicmp(g_sync_state_records[i].local_path, plain_path) == 0)
        {
            return &g_sync_state_records[i];
        }
    }
    return 0;
}

static void
sync_state_remove_by_handle(const char *handle)
{
    int i;

    if (handle == 0 || handle[0] == '\0') {
        return;
    }
    for (i = 0; i < g_sync_state_count; ++i) {
        if (strcmp(g_sync_state_records[i].handle, handle) == 0) {
            if (i + 1 < g_sync_state_count) {
                memmove(&g_sync_state_records[i], &g_sync_state_records[i + 1],
                    sizeof(sync_state_record)
                    * (unsigned int)(g_sync_state_count - i - 1));
            }
            g_sync_state_count--;
            if (g_sync_state_count >= 0) {
                memset(&g_sync_state_records[g_sync_state_count], 0,
                    sizeof(sync_state_record));
            }
            return;
        }
    }
}

static int
sync_state_upsert_pending_local(const WCHAR *plain_path)
{
    sync_state_record *record;
    unsigned __int64 local_size;
    unsigned int local_mtime;

    if (plain_path == 0 || plain_path[0] == L'\0') {
        return 0;
    }
    if (!get_local_file_state(plain_path, &local_size, &local_mtime)) {
        return 0;
    }

    record = sync_state_find_by_path(plain_path);
    if (record == 0) {
        if (!sync_state_ensure_capacity(g_sync_state_count + 1)) {
            return 0;
        }
        record = &g_sync_state_records[g_sync_state_count++];
        memset(record, 0, sizeof(*record));
    }
    record->remote_size = local_size;
    record->remote_mtime = local_mtime;
    record->local_size = local_size;
    record->local_mtime = local_mtime;
    record->type = 0;
    _snwprintf(record->local_path,
        sizeof(record->local_path) / sizeof(record->local_path[0]),
        L"%s", plain_path);
    record->local_path[
        (sizeof(record->local_path) / sizeof(record->local_path[0])) - 1] = L'\0';
    return 1;
}

static int
sync_state_upsert_folder(const mega_node_info *node, const WCHAR *plain_path)
{
    sync_state_record *record;
    unsigned int local_mtime;

    if (node == 0 || node->handle[0] == '\0' || plain_path == 0) {
        return 0;
    }
    if (!get_local_directory_state(plain_path, &local_mtime)) {
        return 0;
    }

    record = sync_state_find_by_handle(node->handle);
    if (record == 0) {
        record = sync_state_find_by_path(plain_path);
    }
    if (record == 0) {
        if (!sync_state_ensure_capacity(g_sync_state_count + 1)) {
            return 0;
        }
        record = &g_sync_state_records[g_sync_state_count++];
        memset(record, 0, sizeof(*record));
    }

    _snprintf(record->handle, sizeof(record->handle), "%s", node->handle);
    record->handle[sizeof(record->handle) - 1] = '\0';
    record->remote_size = 0;
    record->remote_mtime = node->mtime;
    record->local_size = 0;
    record->local_mtime = local_mtime;
    record->type = node->type;
    _snwprintf(record->local_path,
        sizeof(record->local_path) / sizeof(record->local_path[0]),
        L"%s", plain_path);
    record->local_path[
        (sizeof(record->local_path) / sizeof(record->local_path[0])) - 1] = L'\0';
    return 1;
}

static int
sync_state_upsert_file(const mega_node_info *node, const WCHAR *plain_path)
{
    sync_state_record *record;
    unsigned __int64 local_size;
    unsigned int local_mtime;

    if (node == 0 || node->handle[0] == '\0' || plain_path == 0) {
        return 0;
    }
    if (!get_local_file_state(plain_path, &local_size, &local_mtime)) {
        return 0;
    }

    record = sync_state_find_by_handle(node->handle);
    if (record == 0) {
        record = sync_state_find_by_path(plain_path);
    }
    if (record == 0) {
        if (!sync_state_ensure_capacity(g_sync_state_count + 1)) {
            return 0;
        }
        record = &g_sync_state_records[g_sync_state_count++];
        memset(record, 0, sizeof(*record));
    }
    _snprintf(record->handle, sizeof(record->handle), "%s", node->handle);
    record->handle[sizeof(record->handle) - 1] = '\0';

    record->remote_size = node->size;
    record->remote_mtime = node->mtime;
    record->local_size = local_size;
    record->local_mtime = local_mtime;
    record->type = node->type;
    _snwprintf(record->local_path,
        sizeof(record->local_path) / sizeof(record->local_path[0]),
        L"%s", plain_path);
    record->local_path[
        (sizeof(record->local_path) / sizeof(record->local_path[0])) - 1] = L'\0';
    return 1;
}

static int
sync_times_differ(unsigned int a, unsigned int b)
{
    unsigned int diff;

    diff = a > b ? a - b : b - a;
    return diff > 2;
}

static void
sync_state_load(void)
{
    WCHAR path[MAX_PATH];
    HANDLE file;
    sync_state_header header;
    DWORD read_bytes;
    unsigned int bytes_to_read;

    sync_state_reset();
    if (!build_app_file_path(L"syncstate.dat", path,
        sizeof(path) / sizeof(path[0])))
    {
        return;
    }

    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    memset(&header, 0, sizeof(header));
    if (!ReadFile(file, &header, sizeof(header), &read_bytes, 0)
        || read_bytes != sizeof(header)
        || memcmp(header.magic, MEGACE_SYNC_STATE_MAGIC, 7) != 0
        || header.version != MEGACE_SYNC_STATE_VERSION
        || header.count > 100000)
    {
        CloseHandle(file);
        sync_state_reset();
        return;
    }

    if (header.count > 0 && sync_state_ensure_capacity((int)header.count)) {
        bytes_to_read = sizeof(sync_state_record) * header.count;
        if (ReadFile(file, g_sync_state_records, bytes_to_read, &read_bytes, 0)
            && read_bytes == bytes_to_read)
        {
            g_sync_state_count = (int)header.count;
        } else {
            unsigned int old_bytes_to_read;
            sync_state_record_v1 *old_records;

            SetFilePointer(file, sizeof(header), 0, FILE_BEGIN);
            old_bytes_to_read = sizeof(sync_state_record_v1) * header.count;
            old_records = (sync_state_record_v1 *)LocalAlloc(LPTR,
                old_bytes_to_read);
            if (old_records != 0
                && ReadFile(file, old_records, old_bytes_to_read,
                    &read_bytes, 0)
                && read_bytes == old_bytes_to_read)
            {
                unsigned int i;

                for (i = 0; i < header.count; ++i) {
                    memcpy(g_sync_state_records[i].handle,
                        old_records[i].handle,
                        sizeof(g_sync_state_records[i].handle));
                    g_sync_state_records[i].remote_size =
                        old_records[i].remote_size;
                    g_sync_state_records[i].remote_mtime =
                        old_records[i].remote_mtime;
                    g_sync_state_records[i].local_size =
                        old_records[i].local_size;
                    g_sync_state_records[i].local_mtime =
                        old_records[i].local_mtime;
                    g_sync_state_records[i].type = old_records[i].type;
                }
                g_sync_state_count = (int)header.count;
            } else {
                sync_state_reset();
            }
            if (old_records != 0) {
                LocalFree((HLOCAL)old_records);
            }
        }
    }
    CloseHandle(file);
}

static void
sync_state_save(void)
{
    WCHAR path[MAX_PATH];
    HANDLE file;
    sync_state_header header;
    DWORD written;
    unsigned int bytes_to_write;

    if (!build_app_file_path(L"syncstate.dat", path,
        sizeof(path) / sizeof(path[0])))
    {
        return;
    }

    file = CreateFile(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, MEGACE_SYNC_STATE_MAGIC, 7);
    header.version = MEGACE_SYNC_STATE_VERSION;
    header.count = (unsigned int)g_sync_state_count;

    WriteFile(file, &header, sizeof(header), &written, 0);
    if (g_sync_state_count > 0) {
        bytes_to_write = sizeof(sync_state_record)
            * (unsigned int)g_sync_state_count;
        WriteFile(file, g_sync_state_records, bytes_to_write, &written, 0);
    }
    CloseHandle(file);
}

static void
sync_reconcile_missing_remote_folders(int *skipped, int *failed)
{
    int i;

    i = 0;
    while (i < g_sync_state_count) {
        sync_state_record *record;

        record = &g_sync_state_records[i];
        if (record->type == 1
            && record->handle[0] != '\0'
            && mega_api_find_node_by_handle(record->handle) < 0)
        {
            if (record->local_path[0] != L'\0'
                && directory_exists(record->local_path))
            {
                post_log_ascii("Deleting local folder removed from MEGA.");
                if (delete_local_tree(record->local_path)) {
                    if (skipped != 0) {
                        (*skipped)++;
                    }
                } else if (failed != 0) {
                    (*failed)++;
                }
            }
            sync_state_remove_by_handle(record->handle);
            continue;
        }
        i++;
    }
}

static int
local_file_is_current(const WCHAR *path, const mega_node_info *node)
{
    HANDLE file;
    FILETIME local_ft;
    FILETIME mega_ft;
    int cmp;

    if (path == 0 || node == 0) {
        return 0;
    }
    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    memset(&local_ft, 0, sizeof(local_ft));
    GetFileTime(file, 0, 0, &local_ft);
    CloseHandle(file);
    unix_time_to_filetime(node->mtime, &mega_ft);
    cmp = CompareFileTime(&local_ft, &mega_ft);
    return cmp >= 0;
}

static void
set_local_file_mtime(const WCHAR *path, unsigned int mtime)
{
    HANDLE file;
    FILETIME ft;

    if (path == 0 || mtime == 0) {
        return;
    }
    file = CreateFile(path, GENERIC_WRITE, 0, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    unix_time_to_filetime(mtime, &ft);
    SetFileTime(file, 0, 0, &ft);
    CloseHandle(file);
}

static int
build_download_file_path(
    const mega_node_info *node,
    int encrypted,
    WCHAR *path,
    unsigned int path_size
)
{
    WCHAR downloads_path[MAX_PATH];
    WCHAR file_name[128];
    const char *name;

    if (node == 0 || path == 0 || path_size == 0) {
        return 0;
    }

    _snwprintf(downloads_path,
        sizeof(downloads_path) / sizeof(downloads_path[0]),
        L"\\My Documents\\Mega Downloads");
    downloads_path[(sizeof(downloads_path) / sizeof(downloads_path[0])) - 1] = L'\0';
    CreateDirectory(downloads_path, 0);

    name = node->name[0] != '\0' ? node->name : node->handle;
    MultiByteToWideChar(CP_ACP, 0, name, -1, file_name,
        sizeof(file_name) / sizeof(file_name[0]));
    file_name[(sizeof(file_name) / sizeof(file_name[0])) - 1] = L'\0';
    sanitize_file_name(file_name);

    _snwprintf(path, path_size, encrypted
        ? L"%s\\%s.megaenc"
        : L"%s\\%s",
        downloads_path, file_name);
    path[path_size - 1] = L'\0';
    return 1;
}

static void
set_counter_be64(unsigned char *dst, unsigned __int64 value)
{
    int i;

    for (i = 7; i >= 0; --i) {
        dst[i] = (unsigned char)(value & 0xff);
        value >>= 8;
    }
}

static int
decrypt_download_file(
    const WCHAR *encrypted_path,
    const WCHAR *plain_path,
    const mega_node_info *node
)
{
    HANDLE in_file;
    HANDLE out_file;
    unsigned char transfer_key[16];
    unsigned char ctr[16];
    unsigned char buffer[2048];
    unsigned __int64 block_index;
    DWORD read_bytes;
    int ok;
    int i;

    if (encrypted_path == 0 || plain_path == 0 || node == 0
        || !node->file_key_valid)
    {
        return 0;
    }

    for (i = 0; i < 16; ++i) {
        transfer_key[i] = (unsigned char)(node->file_key[i] ^ node->file_key[i + 16]);
    }
    memcpy(ctr, node->file_key + 16, 8);
    memset(ctr + 8, 0, 8);

    in_file = CreateFile(encrypted_path, GENERIC_READ, FILE_SHARE_READ,
        0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (in_file == INVALID_HANDLE_VALUE) {
        mega_crypto_zero(transfer_key, sizeof(transfer_key));
        mega_crypto_zero(ctr, sizeof(ctr));
        return 0;
    }

    out_file = CreateFile(plain_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (out_file == INVALID_HANDLE_VALUE) {
        CloseHandle(in_file);
        mega_crypto_zero(transfer_key, sizeof(transfer_key));
        mega_crypto_zero(ctr, sizeof(ctr));
        return 0;
    }

    block_index = 0;
    ok = 1;
    while (ReadFile(in_file, buffer, sizeof(buffer), &read_bytes, 0)
        && read_bytes > 0)
    {
        DWORD offset;
        DWORD written;

        offset = 0;
        while (offset < read_bytes) {
            unsigned char stream[16];
            DWORD b;
            DWORD available;

            memcpy(stream, ctr, 16);
            set_counter_be64(stream + 8, block_index);
            if (!mega_crypto_aes128_encrypt_block(transfer_key, stream)) {
                ok = 0;
                break;
            }

            available = read_bytes - offset;
            if (available > 16) {
                available = 16;
            }
            for (b = 0; b < available; ++b) {
                buffer[offset + b] ^= stream[b];
            }
            offset += available;
            block_index++;
        }

        if (!ok) {
            break;
        }

        written = 0;
        if (!WriteFile(out_file, buffer, read_bytes, &written, 0)
            || written != read_bytes)
        {
            ok = 0;
            break;
        }
    }

    CloseHandle(out_file);
    CloseHandle(in_file);
    mega_crypto_zero(transfer_key, sizeof(transfer_key));
    mega_crypto_zero(ctr, sizeof(ctr));
    mega_crypto_zero(buffer, sizeof(buffer));
    return ok;
}

static int
download_node_to_plain_path(
    const mega_node_info *node,
    const WCHAR *plain_path,
    int delete_encrypted_on_success
)
{
    mega_api_result api_result;
    mega_http_result http_result;
    char url[2048];
    WCHAR encrypted_path[MAX_PATH];
    char line[256];

    if (node == 0 || plain_path == 0 || plain_path[0] == L'\0') {
        post_log_ascii("Download failed: invalid destination.");
        return 0;
    }
    if (!node->file_key_valid) {
        post_log_ascii("Download failed: file key is not available.");
        return 0;
    }
    if (!ensure_parent_directory(plain_path)) {
        post_log_ascii("Download failed: could not create destination folder.");
        return 0;
    }

    url[0] = '\0';
    if (!mega_api_get_download_url(node->handle, url, sizeof(url), &api_result)) {
        post_log_ascii(api_result.error[0] != '\0'
            ? api_result.error
            : "Download URL request failed.");
        return 0;
    }

    _snwprintf(encrypted_path, sizeof(encrypted_path) / sizeof(encrypted_path[0]),
        L"%s.megaenc", plain_path);
    encrypted_path[(sizeof(encrypted_path) / sizeof(encrypted_path[0])) - 1] = L'\0';

    if (!mega_http_download_url_to_file(url, encrypted_path, &http_result)) {
        post_log_ascii(http_result.error[0] != '\0'
            ? http_result.error
            : "Encrypted download failed.");
        return 0;
    }

    _snprintf(line, sizeof(line), "Downloaded encrypted file: %d bytes",
        http_result.body_bytes);
    line[sizeof(line) - 1] = '\0';
    post_log_ascii(line);

    if (!decrypt_download_file(encrypted_path, plain_path, node)) {
        post_log_ascii("Decrypt failed; encrypted .megaenc file was kept.");
        return 0;
    }

    set_local_file_mtime(plain_path, node->mtime);
    if (delete_encrypted_on_success) {
        DeleteFile(encrypted_path);
    }
    return 1;
}

static DWORD WINAPI
download_file_thread(LPVOID param)
{
    mega_node_info node;
    WCHAR plain_path[MAX_PATH];
    int node_index;

    (void)param;

    node_index = g_download_node_index;
    if (!mega_api_get_node(node_index, &node) || node.type != 0) {
        post_log_ascii("Download failed: invalid file selection.");
        PostMessage(g_main_window, WM_MEGACE_DOWNLOAD_DONE, 0, 0);
        return 0;
    }

    post_log_ascii("Requesting MEGA download URL...");
    if (!build_download_file_path(&node, 0, plain_path,
            sizeof(plain_path) / sizeof(plain_path[0])))
    {
        post_log_ascii("Download failed: could not build local file path.");
        PostMessage(g_main_window, WM_MEGACE_DOWNLOAD_DONE, 0, 0);
        return 0;
    }

    post_log_ascii("Downloading encrypted file...");
    mega_http_set_progress_callback(http_progress_callback, 0);
    if (download_node_to_plain_path(&node, plain_path, 0)) {
        post_log_ascii("Decrypted file saved under Mega Downloads.");
    } else {
        post_log_ascii("Download failed.");
    }
    mega_http_set_progress_callback(0, 0);

    PostMessage(g_main_window, WM_MEGACE_DOWNLOAD_DONE, 0, 0);
    return 0;
}

static void
start_download_node(HWND hwnd, int node_index)
{
    HANDLE thread_handle;

    if (InterlockedCompareExchange(&g_probe_running, 1, 0) != 0) {
        append_log_text(TEXT("Another MEGA operation is already running."));
        return;
    }

    g_download_node_index = node_index;
    set_view_mode(hwnd, MEGACE_VIEW_LOGS);

    thread_handle = CreateThread(0, 0, download_file_thread, 0, 0, 0);
    if (thread_handle == 0) {
        InterlockedExchange(&g_probe_running, 0);
        append_log_text(TEXT("Could not start download thread."));
        return;
    }
    CloseHandle(thread_handle);
}

static DWORD WINAPI
sync_thread(LPVOID param)
{
    WCHAR fetch_nodes_path[MAX_PATH];
    mega_fetch_nodes_summary summary;
    mega_api_result result;
    int total;
    int i;
    int downloaded;
    int uploaded;
    int folders_created;
    int skipped;
    int failed;
    int upload_pending;
    int conflicts;
    int files_seen;
    int files_in_scope;
    int files_no_key;
    char line[160];

    (void)param;

    downloaded = 0;
    uploaded = 0;
    folders_created = 0;
    skipped = 0;
    failed = 0;
    upload_pending = 0;
    conflicts = 0;
    files_seen = 0;
    files_in_scope = 0;
    files_no_key = 0;
    g_sync_conflict_count = 0;
    memset(g_sync_conflicts, 0, sizeof(g_sync_conflicts));

    post_log_ascii(g_download_mode == MEGACE_DOWNLOAD_MODE_MANUAL
        ? "Starting selected download..."
        : "Starting two way sync...");
    if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
        post_sync_status(TEXT("Checking for changes"), 5);
    }
    if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
        if (g_sync_directory[0] == L'\0') {
            set_default_sync_directory();
        }
        if (!ensure_directory_tree(g_sync_directory)) {
            post_log_ascii("Sync failed: could not create sync directory.");
            PostMessage(g_main_window, WM_MEGACE_SYNC_DONE, 0, 0);
            return 0;
        }
    } else if (g_download_root_index < 0) {
        post_log_ascii("Download failed: no selection.");
        PostMessage(g_main_window, WM_MEGACE_SYNC_DONE, 0, 0);
        return 0;
    }

    if (build_app_file_path(L"fetch_nodes.tmp", fetch_nodes_path,
        sizeof(fetch_nodes_path) / sizeof(fetch_nodes_path[0])))
    {
        DeleteFile(fetch_nodes_path);
        memset(&summary, 0, sizeof(summary));
        if (!mega_api_fetch_nodes_file(fetch_nodes_path, &summary, &result)) {
            post_log_ascii(result.error[0] != '\0'
                ? result.error
                : "Sync failed: could not fetch MEGA nodes.");
            DeleteFile(fetch_nodes_path);
            PostMessage(g_main_window, WM_MEGACE_SYNC_DONE, 0, 0);
            return 0;
        }
        DeleteFile(fetch_nodes_path);
        _snprintf(line, sizeof(line),
            "Sync node refresh: files=%d folders=%d",
            summary.file_count, summary.folder_count);
        line[sizeof(line) - 1] = '\0';
        post_log_ascii(line);
    } else {
        post_log_ascii("Sync failed: could not build node cache path.");
        PostMessage(g_main_window, WM_MEGACE_SYNC_DONE, 0, 0);
        return 0;
    }

    if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
        sync_state_load();
        sync_reconcile_missing_remote_folders(&skipped, &failed);
        post_sync_status(TEXT("Checking local files"), 20);
    }

    mega_http_set_progress_callback(http_progress_callback, 0);
    total = mega_api_get_node_count();
    for (i = 0; i < total; ++i) {
        mega_node_info node;
        WCHAR folder_path[MAX_PATH];
        sync_state_record *previous_folder;
        int folder_exists;
        int remote_changed;

        if (!mega_api_get_node(i, &node) || node.type != 1) {
            continue;
        }
        if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
            if (!node_is_in_current_sync(i)) {
                continue;
            }
            if (!build_sync_plain_path(i, folder_path,
                sizeof(folder_path) / sizeof(folder_path[0])))
            {
                failed++;
                continue;
            }
        } else {
            if (!node_is_in_download_root(i)) {
                continue;
            }
            if (!build_download_tree_plain_path(i, folder_path,
                sizeof(folder_path) / sizeof(folder_path[0])))
            {
                failed++;
                continue;
            }
        }
        previous_folder = 0;
        folder_exists = directory_exists(folder_path);
        remote_changed = 0;
        if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
            previous_folder = sync_state_find_by_handle(node.handle);
            if (previous_folder == 0 && folder_exists) {
                previous_folder = sync_state_find_by_path(folder_path);
            }
            if (previous_folder != 0) {
                remote_changed = sync_times_differ(
                    previous_folder->remote_mtime, node.mtime);
                if (!folder_exists
                    && previous_folder->local_path[0] != L'\0'
                    && directory_exists(previous_folder->local_path))
                {
                    if (ensure_parent_directory(folder_path)
                        && MoveFile(previous_folder->local_path, folder_path))
                    {
                        WCHAR folder_name[128];

                        node_name_to_wide(&node, folder_name,
                            sizeof(folder_name) / sizeof(folder_name[0]));
                        post_log_ascii("Renamed local folder to match MEGA:");
                        post_log_text(folder_name);
                        folder_exists = 1;
                    }
                }
                if (!remote_changed && !folder_exists) {
                    WCHAR rename_path[MAX_PATH];
                    WCHAR rename_name[128];
                    char rename_utf8[128];
                    mega_api_result rename_result;

                    if (find_local_folder_rename_candidate(
                        previous_folder->local_path, node.parent,
                        rename_path, sizeof(rename_path) / sizeof(rename_path[0]),
                        rename_name, sizeof(rename_name) / sizeof(rename_name[0]))
                        && wide_to_utf8_or_acp(rename_name, rename_utf8,
                            sizeof(rename_utf8)))
                    {
                        post_log_ascii("Renaming MEGA folder from local rename:");
                        post_log_text(rename_name);
                        memset(&rename_result, 0, sizeof(rename_result));
                        if (mega_api_rename_node(node.handle, rename_utf8,
                            &rename_result))
                        {
                            mega_node_info renamed_node;

                            mega_api_rename_local_node(node.handle,
                                rename_utf8);
                            renamed_node = node;
                            _snprintf(renamed_node.name,
                                sizeof(renamed_node.name), "%s", rename_utf8);
                            renamed_node.name[
                                sizeof(renamed_node.name) - 1] = '\0';
                            sync_state_upsert_folder(&renamed_node,
                                rename_path);
                            skipped++;
                            continue;
                        }
                        post_log_ascii(rename_result.error[0] != '\0'
                            ? rename_result.error
                            : "Folder rename on MEGA failed.");
                    }
                }

                if (!remote_changed && !folder_exists) {
                    mega_api_result delete_result;
                    WCHAR folder_name[128];

                    node_name_to_wide(&node, folder_name,
                        sizeof(folder_name) / sizeof(folder_name[0]));
                    post_log_ascii("Deleting MEGA folder removed locally:");
                    post_log_text(folder_name);
                    memset(&delete_result, 0, sizeof(delete_result));
                    if (mega_api_delete_node(node.handle, &delete_result)) {
                        sync_state_remove_by_handle(node.handle);
                        skipped++;
                    } else {
                        post_log_ascii(delete_result.error[0] != '\0'
                            ? delete_result.error
                            : "Delete folder from MEGA failed.");
                        failed++;
                    }
                    continue;
                }
                if (remote_changed && !folder_exists) {
                    WCHAR folder_name[128];

                    node_name_to_wide(&node, folder_name,
                        sizeof(folder_name) / sizeof(folder_name[0]));
                    post_log_ascii("Conflict skipped, local folder deleted and MEGA changed:");
                    post_log_text(folder_name);
                    skipped++;
                    conflicts++;
                    continue;
                }
            }
        }
        if (ensure_directory_tree(folder_path)) {
            if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
                sync_state_upsert_folder(&node, folder_path);
            }
            folders_created++;
        } else {
            failed++;
        }
    }

    for (i = 0; i < total; ++i) {
        mega_node_info node;
        WCHAR plain_path[MAX_PATH];
        WCHAR name[128];
        int progress;

        if (!mega_api_get_node(i, &node) || node.type != 0) {
            continue;
        }
        if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC && total > 0) {
            progress = 25 + (i * 65) / total;
            post_sync_status(TEXT("Checking for changes"), progress);
        }
        files_seen++;
        if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
            sync_state_record *previous;
            unsigned __int64 local_size;
            unsigned int local_mtime;
            int local_exists;
            int remote_changed;
            int local_changed;
            int local_deleted;

            if (!node_is_in_current_sync(i)) {
                continue;
            }
            files_in_scope++;
            if (!build_sync_plain_path(i, plain_path,
                sizeof(plain_path) / sizeof(plain_path[0])))
            {
                failed++;
                continue;
            }

            local_exists = get_local_file_state(plain_path,
                &local_size, &local_mtime);
            previous = sync_state_find_by_handle(node.handle);
            if (previous == 0 && local_exists) {
                previous = sync_state_find_by_path(plain_path);
            }
            if (previous == 0) {
                if (local_exists && local_size == node.size) {
                    sync_state_upsert_file(&node, plain_path);
                    skipped++;
                    continue;
                }
                if (local_exists) {
                    node_name_to_wide(&node, name, sizeof(name) / sizeof(name[0]));
                    post_log_ascii("No previous sync state; recording current local/MEGA pair:");
                    post_log_text(name);
                    sync_state_upsert_file(&node, plain_path);
                    skipped++;
                    continue;
                }
            } else {
                remote_changed = previous->remote_size != node.size
                    || sync_times_differ(previous->remote_mtime, node.mtime);
                local_changed = local_exists
                    && (previous->local_size != local_size
                        || sync_times_differ(previous->local_mtime, local_mtime));
                local_deleted = !local_exists && previous->local_path[0] != L'\0';

                if (!remote_changed && !local_exists
                    && previous->local_path[0] != L'\0'
                    && get_local_file_state(previous->local_path,
                        &local_size, &local_mtime))
                {
                    if (ensure_parent_directory(plain_path)
                        && MoveFile(previous->local_path, plain_path))
                    {
                        node_name_to_wide(&node, name,
                            sizeof(name) / sizeof(name[0]));
                        post_log_ascii("Renamed local file to match MEGA:");
                        post_log_text(name);
                        sync_state_upsert_file(&node, plain_path);
                        skipped++;
                        continue;
                    }
                }

                if (!remote_changed && local_deleted) {
                    mega_api_result delete_result;

                    node_name_to_wide(&node, name, sizeof(name) / sizeof(name[0]));
                    post_log_ascii("Deleting MEGA file removed locally:");
                    post_log_text(name);
                    memset(&delete_result, 0, sizeof(delete_result));
                    if (mega_api_delete_node(node.handle, &delete_result)) {
                        sync_state_remove_by_handle(node.handle);
                        skipped++;
                    } else {
                        post_log_ascii(delete_result.error[0] != '\0'
                            ? delete_result.error
                            : "Delete from MEGA failed.");
                        failed++;
                    }
                    continue;
                }
                if (remote_changed && local_deleted) {
                    node_name_to_wide(&node, name, sizeof(name) / sizeof(name[0]));
                    post_log_ascii("Conflict skipped, local deleted and MEGA changed:");
                    post_log_text(name);
                    sync_add_conflict(&node, plain_path, name);
                    conflicts++;
                    skipped++;
                    continue;
                }
                if (remote_changed && local_changed) {
                    node_name_to_wide(&node, name, sizeof(name) / sizeof(name[0]));
                    post_log_ascii("Conflict skipped, local and MEGA both changed:");
                    post_log_text(name);
                    sync_add_conflict(&node, plain_path, name);
                    conflicts++;
                    skipped++;
                    continue;
                }
                if (!remote_changed && local_changed) {
                    WCHAR encrypted_path[MAX_PATH];
                    mega_api_result upload_result;
                    char new_handle[16];

                    node_name_to_wide(&node, name, sizeof(name) / sizeof(name[0]));
                    post_log_ascii("Uploading local change:");
                    post_log_text(name);
                    post_sync_status(TEXT("Uploading files"), progress);
                    _snwprintf(encrypted_path,
                        sizeof(encrypted_path) / sizeof(encrypted_path[0]),
                        L"%s.megaupload", plain_path);
                    encrypted_path[(sizeof(encrypted_path)
                        / sizeof(encrypted_path[0])) - 1] = L'\0';
                    new_handle[0] = '\0';
                    memset(&upload_result, 0, sizeof(upload_result));
                    if (mega_api_upload_file_update(node.handle, node.parent,
                        node.name, plain_path, encrypted_path,
                        new_handle, sizeof(new_handle), &upload_result))
                    {
                        _snprintf(line, sizeof(line), new_handle[0] != '\0'
                            ? "Upload accepted by MEGA: %s"
                            : "Upload accepted by MEGA.", new_handle);
                        line[sizeof(line) - 1] = '\0';
                        post_log_ascii(line);
                        if (new_handle[0] != '\0') {
                            _snprintf(node.handle, sizeof(node.handle), "%s",
                                new_handle);
                            node.handle[sizeof(node.handle) - 1] = '\0';
                        }
                        node.size = local_size;
                        node.mtime = local_mtime;
                        sync_state_upsert_file(&node, plain_path);
                        uploaded++;
                    } else {
                        post_log_ascii(upload_result.error[0] != '\0'
                            ? upload_result.error
                            : "Upload failed.");
                        upload_pending++;
                        failed++;
                    }
                    continue;
                }
                if (!remote_changed && local_exists) {
                    sync_state_upsert_file(&node, plain_path);
                    skipped++;
                    continue;
                }
            }

            if (local_file_is_current(plain_path, &node) && previous == 0) {
                sync_state_upsert_file(&node, plain_path);
                skipped++;
                continue;
            }
        } else {
            if (!node_is_in_download_root(i)) {
                continue;
            }
            files_in_scope++;
            if (!build_download_tree_plain_path(i, plain_path,
                sizeof(plain_path) / sizeof(plain_path[0])))
            {
                failed++;
                continue;
            }
        }

        node_name_to_wide(&node, name, sizeof(name) / sizeof(name[0]));
        post_log_text(name);
        if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
            post_sync_status(TEXT("Downloading files"), progress);
        }
        if (!node.file_key_valid) {
            files_no_key++;
        }
        if (download_node_to_plain_path(&node, plain_path, 1)) {
            if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
                sync_state_upsert_file(&node, plain_path);
            }
            downloaded++;
        } else {
            failed++;
        }
    }
    mega_http_set_progress_callback(0, 0);

    if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC) {
        post_sync_status(TEXT("Uploading local-only files"), 90);
        if (g_sync_handle_count <= 0) {
            int root_index;
            mega_node_info root;

            root_index = mega_api_find_root_node();
            if (root_index >= 0 && mega_api_get_node(root_index, &root)) {
                sync_upload_local_tree(root.handle, g_sync_directory,
                    &folders_created, &uploaded, &skipped, &failed);
            }
        } else {
            int selected;

            for (selected = 0; selected < g_sync_handle_count; ++selected) {
                int node_index;
                mega_node_info selected_node;
                WCHAR selected_path[MAX_PATH];

                node_index = mega_api_find_node_by_handle(
                    g_sync_handles[selected]);
                if (node_index < 0
                    || !mega_api_get_node(node_index, &selected_node)
                    || selected_node.type != 1)
                {
                    continue;
                }
                if (!build_sync_plain_path(node_index, selected_path,
                    sizeof(selected_path) / sizeof(selected_path[0])))
                {
                    continue;
                }
                sync_upload_local_tree(selected_node.handle, selected_path,
                    &folders_created, &uploaded, &skipped, &failed);
            }
        }
        sync_state_save();
        if (g_sync_conflict_count > 0) {
            post_sync_status(TEXT("Sync complete; conflicts need review"), 100);
        } else {
            post_sync_status(TEXT("Sync complete"), 100);
        }
    }

    if (g_download_mode == MEGACE_DOWNLOAD_MODE_MANUAL) {
        _snprintf(line, sizeof(line),
            "Selected download finished: folders=%d files=%d/%d no_key=%d downloaded=%d skipped=%d failed=%d",
            folders_created, files_in_scope, files_seen, files_no_key,
            downloaded, skipped, failed);
    } else {
        _snprintf(line, sizeof(line),
            "Sync finished: folders=%d files=%d/%d no_key=%d downloaded=%d uploaded=%d skipped=%d upload_pending=%d conflicts=%d failed=%d",
            folders_created, files_in_scope, files_seen, files_no_key,
            downloaded, uploaded, skipped, upload_pending, conflicts, failed);
    }
    line[sizeof(line) - 1] = '\0';
    post_log_ascii(line);

    PostMessage(g_main_window, WM_MEGACE_SYNC_DONE, 0, 0);
    return 0;
}

static DWORD WINAPI
sync_conflict_resolution_thread(LPVOID param)
{
    int i;
    int resolved;
    int failed;

    (void)param;

    resolved = 0;
    failed = 0;
    post_sync_status(TEXT("Resolving conflicts"), 0);
    sync_state_load();
    mega_http_set_progress_callback(http_progress_callback, 0);
    for (i = 0; i < g_sync_conflict_count; ++i) {
        sync_conflict_entry *entry;
        int progress;

        entry = &g_sync_conflicts[i];
        progress = g_sync_conflict_count > 0
            ? (i * 100) / g_sync_conflict_count
            : 0;
        if (entry->choice == 1) {
            WCHAR encrypted_path[MAX_PATH];
            mega_api_result upload_result;
            char new_handle[16];

            post_sync_status(TEXT("Uploading conflict file"), progress);
            _snwprintf(encrypted_path,
                sizeof(encrypted_path) / sizeof(encrypted_path[0]),
                L"%s.megaupload", entry->path);
            encrypted_path[(sizeof(encrypted_path)
                / sizeof(encrypted_path[0])) - 1] = L'\0';
            new_handle[0] = '\0';
            memset(&upload_result, 0, sizeof(upload_result));
            if (mega_api_upload_file_update(entry->node.handle,
                entry->node.parent, entry->node.name, entry->path,
                encrypted_path, new_handle, sizeof(new_handle), &upload_result))
            {
                if (new_handle[0] != '\0') {
                    _snprintf(entry->node.handle, sizeof(entry->node.handle),
                        "%s", new_handle);
                    entry->node.handle[sizeof(entry->node.handle) - 1] = '\0';
                }
                sync_state_upsert_file(&entry->node, entry->path);
                resolved++;
            } else {
                post_log_ascii(upload_result.error[0] != '\0'
                    ? upload_result.error
                    : "Conflict upload failed.");
                failed++;
            }
        } else if (entry->choice == 2) {
            post_sync_status(TEXT("Downloading conflict file"), progress);
            if (download_node_to_plain_path(&entry->node, entry->path, 1)) {
                sync_state_upsert_file(&entry->node, entry->path);
                resolved++;
            } else {
                failed++;
            }
        }
    }
    mega_http_set_progress_callback(0, 0);
    sync_state_save();
    post_sync_status(failed == 0
        ? TEXT("Conflict resolution complete")
        : TEXT("Conflict resolution finished with errors"),
        100);
    PostMessage(g_main_window, WM_MEGACE_CONFLICT_DONE,
        (WPARAM)resolved, (LPARAM)failed);
    return 0;
}

static void
ask_and_resolve_sync_conflicts(HWND hwnd)
{
    int i;
    int choices;
    HANDLE thread_handle;

    if (g_sync_conflict_count <= 0) {
        return;
    }

    choices = 0;
    for (i = 0; i < g_sync_conflict_count; ++i) {
        WCHAR message[384];
        int answer;

        _snwprintf(message, sizeof(message) / sizeof(message[0]),
            L"Sync conflict:\r\n%s\r\n\r\nYes: replace server with local file\r\nNo: replace local file with server file\r\nCancel: skip remaining conflicts",
            g_sync_conflicts[i].name);
        message[(sizeof(message) / sizeof(message[0])) - 1] = L'\0';
        answer = MessageBox(hwnd, message, TEXT("Sync Conflict"),
            MB_YESNOCANCEL | MB_ICONQUESTION);
        if (answer == IDYES) {
            g_sync_conflicts[i].choice = 1;
            choices++;
        } else if (answer == IDNO) {
            g_sync_conflicts[i].choice = 2;
            choices++;
        } else {
            break;
        }
    }

    if (choices <= 0) {
        post_sync_status(TEXT("Conflicts skipped"), 100);
        return;
    }
    if (InterlockedCompareExchange(&g_probe_running, 1, 0) != 0) {
        append_log_text(TEXT("Cannot resolve conflicts: another operation is running."));
        return;
    }
    thread_handle = CreateThread(0, 0, sync_conflict_resolution_thread,
        0, 0, 0);
    if (thread_handle == 0) {
        InterlockedExchange(&g_probe_running, 0);
        append_log_text(TEXT("Could not start conflict resolver."));
        return;
    }
    CloseHandle(thread_handle);
}

static void
start_one_way_sync(HWND hwnd)
{
    HANDLE thread_handle;

    save_settings();
    if (InterlockedCompareExchange(&g_probe_running, 1, 0) != 0) {
        append_log_text(TEXT("Another MEGA operation is already running."));
        return;
    }

    g_download_mode = MEGACE_DOWNLOAD_MODE_SYNC;
    g_download_root_index = -1;
    g_download_root_handle[0] = '\0';
    reset_sync_page(TEXT("Checking for changes"));
    set_view_mode(hwnd, MEGACE_VIEW_SYNC);
    thread_handle = CreateThread(0, 0, sync_thread, 0, 0, 0);
    if (thread_handle == 0) {
        InterlockedExchange(&g_probe_running, 0);
        append_log_text(TEXT("Could not start sync thread."));
        return;
    }
    CloseHandle(thread_handle);
}

static void
start_selected_download(HWND hwnd, int node_index)
{
    HANDLE thread_handle;
    mega_node_info node;

    if (InterlockedCompareExchange(&g_probe_running, 1, 0) != 0) {
        append_log_text(TEXT("Another MEGA operation is already running."));
        return;
    }

    if (!mega_api_get_node(node_index, &node)) {
        InterlockedExchange(&g_probe_running, 0);
        append_log_text(TEXT("Download failed: invalid selection."));
        return;
    }
    g_download_mode = MEGACE_DOWNLOAD_MODE_MANUAL;
    g_download_root_index = node_index;
    _snprintf(g_download_root_handle, sizeof(g_download_root_handle),
        "%s", node.handle);
    g_download_root_handle[sizeof(g_download_root_handle) - 1] = '\0';
    set_view_mode(hwnd, MEGACE_VIEW_LOGS);
    thread_handle = CreateThread(0, 0, sync_thread, 0, 0, 0);
    if (thread_handle == 0) {
        InterlockedExchange(&g_probe_running, 0);
        append_log_text(TEXT("Could not start download thread."));
        return;
    }
    CloseHandle(thread_handle);
}

static DWORD WINAPI
server_operation_thread(LPVOID param)
{
    mega_api_result result;
    char line[160];
    char created_handle[16];
    char target_handle[16];
    int ok;

    (void)param;

    memset(&result, 0, sizeof(result));
    created_handle[0] = '\0';
    target_handle[0] = '\0';
    ok = 0;
    if (g_server_op_type == MEGACE_SERVER_OP_CREATE_FOLDER) {
        char new_handle[16];

        post_log_ascii("Creating folder on MEGA...");
        new_handle[0] = '\0';
        ok = mega_api_create_folder(g_server_op_parent, g_server_op_name,
            new_handle, sizeof(new_handle), &result);
        if (ok && new_handle[0] != '\0') {
            _snprintf(line, sizeof(line), "Created folder handle: %s",
                new_handle);
            line[sizeof(line) - 1] = '\0';
            post_log_ascii(line);
            _snprintf(created_handle, sizeof(created_handle), "%s", new_handle);
            created_handle[sizeof(created_handle) - 1] = '\0';
        }
    } else if (g_server_op_type == MEGACE_SERVER_OP_RENAME) {
        mega_node_info node;

        post_log_ascii("Renaming MEGA node...");
        if (mega_api_get_node(g_server_op_node_index, &node)) {
            _snprintf(target_handle, sizeof(target_handle), "%s", node.handle);
            target_handle[sizeof(target_handle) - 1] = '\0';
            ok = mega_api_rename_node(node.handle, g_server_op_name, &result);
        } else {
            _snprintf(result.error, sizeof(result.error),
                "Rename failed: invalid selection");
            result.error[sizeof(result.error) - 1] = '\0';
        }
    } else if (g_server_op_type == MEGACE_SERVER_OP_DELETE) {
        mega_node_info node;

        post_log_ascii("Deleting MEGA node...");
        if (mega_api_get_node(g_server_op_node_index, &node)) {
            _snprintf(target_handle, sizeof(target_handle), "%s", node.handle);
            target_handle[sizeof(target_handle) - 1] = '\0';
            ok = mega_api_delete_node(node.handle, &result);
        } else {
            _snprintf(result.error, sizeof(result.error),
                "Delete failed: invalid selection");
            result.error[sizeof(result.error) - 1] = '\0';
        }
    }

    if (ok) {
        post_log_ascii("MEGA server operation succeeded.");
        if (g_server_op_type == MEGACE_SERVER_OP_CREATE_FOLDER
            && created_handle[0] != '\0')
        {
            if (!mega_api_add_local_folder_node(created_handle,
                g_server_op_parent, g_server_op_name))
            {
                post_log_ascii("Local file list update failed after create.");
            }
        } else if (g_server_op_type == MEGACE_SERVER_OP_RENAME
            && target_handle[0] != '\0')
        {
            if (!mega_api_rename_local_node(target_handle, g_server_op_name)) {
                post_log_ascii("Local file list update failed after rename.");
            }
        } else if (g_server_op_type == MEGACE_SERVER_OP_DELETE
            && target_handle[0] != '\0')
        {
            if (!mega_api_remove_local_node(target_handle)) {
                post_log_ascii("Local file list update failed after delete.");
            }
        }
    } else {
        post_log_ascii(result.error[0] != '\0'
            ? result.error
            : "MEGA server operation failed.");
    }

    InterlockedExchange(&g_probe_running, 0);
    PostMessage(g_main_window, WM_MEGACE_SERVER_OP_DONE, 0, 0);
    return 0;
}

static void
start_server_operation(HWND hwnd, int op_type, int node_index)
{
    HANDLE thread_handle;
    WCHAR input[128];
    mega_node_info node;

    if (!mega_api_has_session()) {
        MessageBox(hwnd, TEXT("No session. Use Menu > Login."),
            TEXT("MegaCE"), MB_OK | MB_ICONINFORMATION);
        append_log_text(TEXT("No session. Use Menu > Login."));
        return;
    }
    if (InterlockedCompareExchange(&g_probe_running, 1, 0) != 0) {
        MessageBox(hwnd, TEXT("Another MEGA operation is already running."),
            TEXT("MegaCE"), MB_OK | MB_ICONINFORMATION);
        append_log_text(TEXT("Another MEGA operation is already running."));
        return;
    }

    memset(g_server_op_name, 0, sizeof(g_server_op_name));
    g_server_op_parent[0] = '\0';
    g_server_op_node_index = node_index;
    g_server_op_type = op_type;

    if (op_type == MEGACE_SERVER_OP_CREATE_FOLDER) {
        set_current_parent_from_root();
        if (g_current_parent[0] == '\0') {
            InterlockedExchange(&g_probe_running, 0);
            MessageBox(hwnd, TEXT("Refresh files before creating a folder."),
                TEXT("Create Folder"), MB_OK | MB_ICONINFORMATION);
            append_log_text(TEXT("Create folder failed: refresh files first."));
            return;
        }
        input[0] = L'\0';
        if (g_create_folder_name != 0) {
            GetWindowText(g_create_folder_name, input,
                sizeof(input) / sizeof(input[0]));
            input[(sizeof(input) / sizeof(input[0])) - 1] = L'\0';
        }
        if (input[0] == L'\0') {
            InterlockedExchange(&g_probe_running, 0);
            MessageBox(hwnd, TEXT("Enter a folder name first."),
                TEXT("Create Folder"), MB_OK | MB_ICONINFORMATION);
            append_log_text(TEXT("Create folder failed: no folder name."));
            return;
        }
        if (!wide_to_utf8_or_acp(input, g_server_op_name,
            sizeof(g_server_op_name)))
        {
            InterlockedExchange(&g_probe_running, 0);
            MessageBox(hwnd, TEXT("The folder name could not be converted."),
                TEXT("Create Folder"), MB_OK | MB_ICONINFORMATION);
            append_log_text(TEXT("Create folder failed: invalid name."));
            return;
        }
        _snprintf(g_server_op_parent, sizeof(g_server_op_parent),
            "%s", g_current_parent);
        g_server_op_parent[sizeof(g_server_op_parent) - 1] = '\0';
    } else if (op_type == MEGACE_SERVER_OP_RENAME) {
        if (!mega_api_get_node(node_index, &node)) {
            InterlockedExchange(&g_probe_running, 0);
            append_log_text(TEXT("Rename failed: invalid selection."));
            return;
        }
        input[0] = L'\0';
        if (g_rename_name != 0) {
            GetWindowText(g_rename_name, input,
                sizeof(input) / sizeof(input[0]));
            input[(sizeof(input) / sizeof(input[0])) - 1] = L'\0';
        }
        if (input[0] == L'\0') {
            InterlockedExchange(&g_probe_running, 0);
            MessageBox(hwnd, TEXT("Enter a new name first."),
                TEXT("Rename"), MB_OK | MB_ICONINFORMATION);
            append_log_text(TEXT("Rename failed: no name."));
            return;
        }
        if (!wide_to_utf8_or_acp(input, g_server_op_name,
            sizeof(g_server_op_name)))
        {
            InterlockedExchange(&g_probe_running, 0);
            MessageBox(hwnd, TEXT("The new name could not be converted."),
                TEXT("Rename"), MB_OK | MB_ICONINFORMATION);
            append_log_text(TEXT("Rename failed: invalid name."));
            return;
        }
    } else if (op_type == MEGACE_SERVER_OP_DELETE) {
        if (!mega_api_get_node(node_index, &node)) {
            InterlockedExchange(&g_probe_running, 0);
            append_log_text(TEXT("Delete failed: invalid selection."));
            return;
        }
        if (MessageBox(hwnd,
            node.type == 0
                ? TEXT("Delete this file from MEGA?")
                : TEXT("Delete this folder from MEGA?"),
            TEXT("Delete"), MB_YESNO | MB_ICONQUESTION) != IDYES)
        {
            InterlockedExchange(&g_probe_running, 0);
            return;
        }
    }

    set_view_mode(hwnd, MEGACE_VIEW_LOGS);
    thread_handle = CreateThread(0, 0, server_operation_thread, 0, 0, 0);
    if (thread_handle == 0) {
        InterlockedExchange(&g_probe_running, 0);
        append_log_text(TEXT("Could not start MEGA server operation."));
        return;
    }
    CloseHandle(thread_handle);
}

static void
set_current_parent_from_root(void)
{
    int root_index;
    mega_node_info root;

    if (g_current_parent[0] != '\0') {
        return;
    }

    root_index = mega_api_find_root_node();
    if (root_index >= 0 && mega_api_get_node(root_index, &root)) {
        _snprintf(g_current_parent, sizeof(g_current_parent), "%s", root.handle);
        g_current_parent[sizeof(g_current_parent) - 1] = '\0';
        g_parent_depth = 0;
    }
}

static void
populate_file_list(void)
{
    int child_offset;
    int node_count;
    mega_node_info child;
    file_sort_entry *entries;
    int entry_count;
    int entry_capacity;
    int i;

    if (g_files == 0) {
        return;
    }

    ListView_DeleteAllItems(g_files);
    reset_file_item_nodes();

    node_count = mega_api_get_node_count();
    if (node_count <= 0) {
        if (mega_api_has_session()) {
            add_file_list_item(TEXT("Refresh files to view files on the server."),
                TEXT(""), TEXT(""), -1, -2);
        } else {
            add_file_list_item(TEXT("No session. Use Menu > Login."),
                TEXT(""), TEXT(""), -1, -2);
        }
        return;
    }

    set_current_parent_from_root();
    if (g_current_parent[0] == '\0') {
        add_file_list_item(TEXT("Root folder not found."), TEXT(""), TEXT(""), -1, -2);
        return;
    }

    if (g_parent_depth > 0) {
        add_file_list_item(TEXT("Up"), TEXT(""), TEXT(""),
            MEGACE_FILE_ICON_UP, -1);
    }

    entries = 0;
    entry_count = 0;
    entry_capacity = 0;
    child_offset = 0;
    while (mega_api_get_child_node(g_current_parent, child_offset, &child)) {
        file_sort_entry *grown;
        int node_index;

        if (entry_count >= entry_capacity) {
            int new_capacity;

            new_capacity = entry_capacity == 0 ? 32 : entry_capacity * 2;
            grown = (file_sort_entry *)LocalAlloc(LPTR,
                sizeof(file_sort_entry) * (unsigned int)new_capacity);
            if (grown == 0) {
                break;
            }
            if (entries != 0) {
                memcpy(grown, entries,
                    sizeof(file_sort_entry) * (unsigned int)entry_count);
                LocalFree((HLOCAL)entries);
            }
            entries = grown;
            entry_capacity = new_capacity;
        }
        node_index = mega_api_find_node_by_handle(child.handle);
        entries[entry_count].node_index = node_index;
        entries[entry_count].node = child;
        format_node_name(&child, entries[entry_count].label,
            sizeof(entries[entry_count].label) / sizeof(entries[entry_count].label[0]));
        entry_count++;
        child_offset++;
    }

    if (entry_count > 1) {
        qsort(entries, (size_t)entry_count, sizeof(file_sort_entry),
            compare_file_sort_entries);
    }

    for (i = 0; i < entry_count; ++i) {
        WCHAR date_text[32];
        WCHAR size_text[32];
        int image_index;

        format_node_date(entries[i].node.mtime, date_text,
            sizeof(date_text) / sizeof(date_text[0]));
        format_node_size(&entries[i].node, size_text,
            sizeof(size_text) / sizeof(size_text[0]));
        image_index = entries[i].node.type == 0
            ? MEGACE_FILE_ICON_FILE
            : MEGACE_FILE_ICON_FOLDER;
        if (entries[i].node.type != 0
            && node_is_explicit_sync_selection(entries[i].node_index))
        {
            image_index = MEGACE_FILE_ICON_FOLDER_SYNC;
        }
        add_file_list_item(entries[i].label, date_text, size_text,
            image_index, entries[i].node_index);
    }
    if (entries != 0) {
        LocalFree((HLOCAL)entries);
    }

    if (entry_count == 0) {
        add_file_list_item(TEXT("This folder is empty."), TEXT(""), TEXT(""), -1, -2);
    }
}

static void
show_refreshing_indicator(void)
{
    if (g_files == 0) {
        return;
    }
    ListView_DeleteAllItems(g_files);
    reset_file_item_nodes();
    add_file_list_item(TEXT("Refreshing files..."), TEXT(""), TEXT(""), -1, -2);
}

static void
open_selected_file_item(void)
{
    int selection;
    int node_index;
    mega_node_info node;

    if (g_files == 0) {
        return;
    }

    selection = ListView_GetNextItem(g_files, -1, LVNI_SELECTED);
    if (selection < 0 || selection >= g_file_item_capacity
        || g_file_item_nodes == 0)
    {
        return;
    }

    node_index = g_file_item_nodes[selection];
    if (node_index == -1) {
        if (g_parent_depth > 0) {
            g_parent_depth--;
            _snprintf(g_current_parent, sizeof(g_current_parent),
                "%s", g_parent_stack[g_parent_depth]);
            g_current_parent[sizeof(g_current_parent) - 1] = '\0';
            populate_file_list();
        }
        return;
    }

    if (node_index < 0 || !mega_api_get_node(node_index, &node)) {
        return;
    }

    if (node.type == 0) {
        start_download_node(g_main_window, node_index);
        return;
    }

    if (g_parent_depth < 32) {
        _snprintf(g_parent_stack[g_parent_depth],
            sizeof(g_parent_stack[g_parent_depth]), "%s", g_current_parent);
        g_parent_stack[g_parent_depth][sizeof(g_parent_stack[g_parent_depth]) - 1] = '\0';
        g_parent_depth++;
    }
    _snprintf(g_current_parent, sizeof(g_current_parent), "%s", node.handle);
    g_current_parent[sizeof(g_current_parent) - 1] = '\0';
    populate_file_list();
}

static void
show_rename_page(HWND hwnd, int node_index)
{
    mega_node_info node;
    WCHAR name[160];

    if (!mega_api_get_node(node_index, &node)) {
        append_log_text(TEXT("Rename failed: invalid selection."));
        return;
    }
    format_node_name(&node, name, sizeof(name) / sizeof(name[0]));
    g_rename_node_index = node_index;
    if (g_rename_name != 0) {
        SetWindowText(g_rename_name, name);
        SetFocus(g_rename_name);
        SendMessage(g_rename_name, EM_SETSEL, 0, -1);
    }
    set_view_mode(hwnd, MEGACE_VIEW_RENAME);
}

static void
dispatch_context_menu_command(HWND hwnd, UINT command)
{
    if (command == IDC_MEGACE_CREATEFOLDER) {
        set_view_mode(hwnd, MEGACE_VIEW_CREATE_FOLDER);
    } else if (command == IDC_MEGACE_CONTEXT_DOWNLOAD) {
        start_selected_download(hwnd, g_context_node_index);
    } else if (command == IDC_MEGACE_CONTEXT_RENAME) {
        show_rename_page(hwnd, g_context_node_index);
    } else if (command == IDC_MEGACE_CONTEXT_DELETE) {
        start_server_operation(hwnd, MEGACE_SERVER_OP_DELETE,
            g_context_node_index);
    } else if (command == IDC_MEGACE_CONTEXT_SYNCTHIS) {
        add_node_to_current_sync(g_context_node_index);
    } else if (command == IDC_MEGACE_CONTEXT_REMOVEFROMSYNC) {
        remove_node_from_current_sync(g_context_node_index);
    }
}

static void
show_file_context_menu(HWND hwnd)
{
    HMENU menu;
    POINT pt;
    POINT client_pt;
    LVHITTESTINFO hit;
    int item_index;

    if (hwnd == 0 || g_files == 0) {
        return;
    }

    GetCursorPos(&pt);
    client_pt = pt;
    ScreenToClient(g_files, &client_pt);
    memset(&hit, 0, sizeof(hit));
    hit.pt = client_pt;
    item_index = ListView_HitTest(g_files, &hit);
    menu = CreatePopupMenu();
    if (menu == 0) {
        return;
    }

    if (item_index < 0 || item_index >= g_file_item_capacity
        || g_file_item_nodes == 0)
    {
        g_context_node_index = -1;
        AppendMenu(menu, MF_STRING, IDC_MEGACE_CREATEFOLDER,
            TEXT("Create Folder"));
        {
            UINT command;

            command = TrackPopupMenu(menu,
                TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
                pt.x, pt.y, 0, hwnd, 0);
            if (command != 0) {
                dispatch_context_menu_command(g_main_window, command);
            }
        }
        DestroyMenu(menu);
        return;
    }

    g_context_node_index = g_file_item_nodes[item_index];
    if (g_context_node_index < 0) {
        g_context_node_index = -1;
        AppendMenu(menu, MF_STRING, IDC_MEGACE_CREATEFOLDER,
            TEXT("Create Folder"));
        {
            UINT command;

            command = TrackPopupMenu(menu,
                TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
                pt.x, pt.y, 0, hwnd, 0);
            if (command != 0) {
                dispatch_context_menu_command(g_main_window, command);
            }
        }
        DestroyMenu(menu);
        return;
    }

    ListView_SetItemState(g_files, item_index,
        LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);

    AppendMenu(menu, MF_STRING, IDC_MEGACE_CREATEFOLDER, TEXT("Create Folder"));
    AppendMenu(menu, MF_STRING, IDC_MEGACE_CONTEXT_DOWNLOAD, TEXT("Download"));
    AppendMenu(menu, MF_STRING, IDC_MEGACE_CONTEXT_RENAME, TEXT("Rename"));
    AppendMenu(menu, MF_STRING, IDC_MEGACE_CONTEXT_DELETE, TEXT("Delete"));
    if (node_is_explicit_sync_selection(g_context_node_index)) {
        AppendMenu(menu, MF_STRING, IDC_MEGACE_CONTEXT_REMOVEFROMSYNC,
            TEXT("Remove from sync"));
    } else {
        AppendMenu(menu, MF_STRING, IDC_MEGACE_CONTEXT_SYNCTHIS, TEXT("Sync This"));
    }
    {
        UINT command;

        command = TrackPopupMenu(menu,
            TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
            pt.x, pt.y, 0, hwnd, 0);
        if (command != 0) {
            dispatch_context_menu_command(g_main_window, command);
        }
    }
    DestroyMenu(menu);
}

static LRESULT CALLBACK
files_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_CONTEXTMENU) {
        show_file_context_menu(g_main_window);
        return 0;
    }
    return CallWindowProc(g_files_old_proc, hwnd, msg, wParam, lParam);
}

static void
http_progress_callback(const char *message, void *user_data)
{
    (void)user_data;
    if (message == 0) {
        return;
    }
    if (strncmp(message, "Loading TLS", 11) == 0
        || strncmp(message, "Opening TLS", 11) == 0
        || strncmp(message, "Sending HTTP", 12) == 0
        || strncmp(message, "Reading HTTP", 12) == 0
        || strncmp(message, "Received ", 9) == 0
        || strncmp(message, "Closing TLS", 11) == 0
        || strncmp(message, "PBKDF2-SHA512 ", 14) == 0
        || strncmp(message, "BearSSL hashcash nonce ", 23) == 0
        || strncmp(message, "BearSSL hashcash tried ", 23) == 0
        || strcmp(message, "Using BearSSL hashcash solver...") == 0)
    {
        return;
    }
    post_log_ascii(message);
}

static const char *
mega_api_error_name(int code)
{
    switch (code) {
    case -1: return "API_EINTERNAL";
    case -2: return "API_EARGS";
    case -3: return "API_EAGAIN";
    case -4: return "API_ERATELIMIT";
    case -5: return "API_EFAILED";
    case -6: return "API_ETOOMANY";
    case -7: return "API_ERANGE";
    case -8: return "API_EEXPIRED";
    case -9: return "API_ENOENT";
    case -10: return "API_ECIRCULAR";
    case -11: return "API_EACCESS";
    case -12: return "API_EEXIST";
    case -13: return "API_EINCOMPLETE";
    case -14: return "API_EKEY";
    case -15: return "API_ESID";
    case -16: return "API_EBLOCKED";
    case -17: return "API_EOVERQUOTA";
    case -18: return "API_ETEMPUNAVAIL";
    case -19: return "API_ETOOMANYCONNECTIONS";
    case -20: return "API_EWRITE";
    case -21: return "API_EREAD";
    case -22: return "API_EAPPKEY";
    case -23: return "API_ESSL";
    case -24: return "API_EGOINGOVERQUOTA";
    case -26: return "API_EMFAREQUIRED";
    default: return 0;
    }
}

static int
mega_response_single_error(const char *response_body)
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

    return *p == ']' ? sign * value : 0;
}

static DWORD WINAPI
mega_probe_thread(LPVOID param)
{
    char *response_body;
    unsigned int response_body_size;
    mega_api_result result;
    mega_fetch_nodes_summary fetch_summary;
    char line[256];
    WCHAR fetch_nodes_path[MAX_PATH];

    (void)param;

    post_log_text(g_probe_mode == 1
        ? TEXT("Requesting MEGA login salt...")
        : (g_probe_mode == 2
            ? TEXT("Logging in to MEGA...")
            : (g_probe_mode == 3
                ? TEXT("Fetching MEGA nodes...")
                : TEXT("Connecting to MEGA API..."))));

    response_body_size = MEGACE_RESPONSE_SMALL_SIZE;
    response_body = (char *)LocalAlloc(LPTR, response_body_size);
    if (response_body == 0) {
        post_log_ascii("Could not allocate MEGA response buffer.");
        PostMessage(g_main_window, WM_MEGACE_DONE, 0, 0);
        return 0;
    }
    response_body[0] = '\0';
    memset(&fetch_summary, 0, sizeof(fetch_summary));

    mega_http_set_progress_callback(http_progress_callback, 0);
    if (g_probe_mode == 1) {
        mega_api_get_user_salt(g_probe_email, response_body, response_body_size, &result);
    } else if (g_probe_mode == 2) {
        mega_api_login_v1(g_probe_email, g_probe_password,
            response_body, response_body_size, &result);
    } else if (g_probe_mode == 3) {
        if (build_app_file_path(L"fetch_nodes.tmp", fetch_nodes_path,
            sizeof(fetch_nodes_path) / sizeof(fetch_nodes_path[0])))
        {
            DeleteFile(fetch_nodes_path);
            mega_api_fetch_nodes_file(fetch_nodes_path, &fetch_summary, &result);
            DeleteFile(fetch_nodes_path);
        } else {
            memset(&result, 0, sizeof(result));
            _snprintf(result.error, sizeof(result.error),
                "Could not build fetch_nodes.tmp path.");
            result.error[sizeof(result.error) - 1] = '\0';
        }
    } else {
        mega_api_probe(response_body, response_body_size, &result);
    }
    mega_http_set_progress_callback(0, 0);

    _snprintf(line, sizeof(line), "MEGA request finished: HTTP %d",
        result.http.status_code);
    line[sizeof(line) - 1] = '\0';
    post_log_ascii(line);

    if (result.account_version > 0) {
        _snprintf(line, sizeof(line), "MEGA account version: v%d",
            result.account_version);
        line[sizeof(line) - 1] = '\0';
        post_log_ascii(line);
    }

    if (result.error[0] != '\0') {
        post_log_ascii(result.error);
    }

    if (result.diagnostic[0] != '\0') {
        post_log_ascii(result.diagnostic);
    }

    if (result.http.status_line[0] != '\0' && !result.login_success) {
        post_log_ascii(result.http.status_line);
    }

    if (result.http.headers[0] != '\0' && !result.ok) {
        post_log_ascii(result.http.headers);
    }

    if (result.login_success) {
        post_log_ascii("MEGA login successful.");
        if (mega_api_has_session()) {
            post_log_ascii("Session retained in memory.");
            save_session_to_file();
        }
        post_log_ascii("Sensitive login response redacted.");
    } else if (g_probe_mode == 3 && result.ok) {
        int api_error;
        const char *api_error_name;

        api_error = mega_response_single_error(response_body);
        api_error_name = mega_api_error_name(api_error);
        if (api_error_name != 0) {
            _snprintf(line, sizeof(line),
                "MEGA API error: %s (%d)",
                api_error_name, api_error);
            line[sizeof(line) - 1] = '\0';
            post_log_ascii(line);
            post_log_ascii(response_body);
        } else {
            _snprintf(line, sizeof(line),
                "Fetch nodes: nodes=%d parsed=%d folders=%d files=%d roots=%d incoming=%d rubbish=%d",
                fetch_summary.node_count,
                fetch_summary.parsed_nodes,
                fetch_summary.folder_count,
                fetch_summary.file_count,
                fetch_summary.root_count,
                fetch_summary.incoming_count,
                fetch_summary.rubbish_count);
            line[sizeof(line) - 1] = '\0';
            post_log_ascii(line);
            _snprintf(line, sizeof(line),
                "Node names decrypted: %d", fetch_summary.decrypted_names);
            line[sizeof(line) - 1] = '\0';
            post_log_ascii(line);
            if (fetch_summary.undecrypted_files != 0
                || fetch_summary.undecrypted_folders != 0
                || fetch_summary.undecrypted_specials != 0)
            {
                _snprintf(line, sizeof(line),
                    "Node names not decrypted: files=%d folders=%d special=%d",
                    fetch_summary.undecrypted_files,
                    fetch_summary.undecrypted_folders,
                    fetch_summary.undecrypted_specials);
                line[sizeof(line) - 1] = '\0';
                post_log_ascii(line);
            }
            if (fetch_summary.first_names[0] != '\0') {
                _snprintf(line, sizeof(line), "Sample names: %s",
                    fetch_summary.first_names);
                line[sizeof(line) - 1] = '\0';
                post_log_ascii(line);
            }
            if (fetch_summary.truncated) {
                post_log_ascii("Fetch nodes response was incomplete or could not be fully parsed.");
            }
            post_log_ascii("Node response retained only for summary.");
        }
    } else if (result.sensitive_response) {
        post_log_ascii("Sensitive login response redacted.");
    } else if (response_body[0] != '\0') {
        int api_error;
        const char *api_error_name;

        api_error = mega_response_single_error(response_body);
        api_error_name = mega_api_error_name(api_error);
        if (api_error_name != 0) {
            char api_error_line[96];

            _snprintf(api_error_line, sizeof(api_error_line),
                "MEGA API error: %s (%d)",
                api_error_name, api_error);
            api_error_line[sizeof(api_error_line) - 1] = '\0';
            post_log_ascii(api_error_line);
        }
        post_log_ascii(response_body);
    }

    LocalFree((HLOCAL)response_body);
    PostMessage(g_main_window, WM_MEGACE_DONE, 0, 0);
    return 0;
}

static void
start_mega_probe(HWND hwnd)
{
    HANDLE thread_handle;

    if (InterlockedCompareExchange(&g_probe_running, 1, 0) != 0) {
        append_log_text(TEXT("MEGA API test is already running."));
        return;
    }

    if (g_probe_mode == 3) {
        g_current_parent[0] = '\0';
        g_parent_depth = 0;
        set_view_mode(hwnd, MEGACE_VIEW_FILES);
        show_refreshing_indicator();
        start_spinner(hwnd);
    }

    EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_PING), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_US0), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_LOGIN), FALSE);

    thread_handle = CreateThread(0, 0, mega_probe_thread, 0, 0, 0);
    if (thread_handle == 0) {
        InterlockedExchange(&g_probe_running, 0);
        EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_PING), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_US0), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_LOGIN), TRUE);
        append_log_text(TEXT("Could not start worker thread."));
        return;
    }

    CloseHandle(thread_handle);
}

static void
start_mega_probe_mode(HWND hwnd, int mode)
{
    g_probe_email[0] = '\0';
    g_probe_password[0] = '\0';
    if ((mode == 1 || mode == 2) && g_email != 0) {
        WCHAR wide_email[256];

        wide_email[0] = L'\0';
        GetWindowText(g_email, wide_email,
            sizeof(wide_email) / sizeof(wide_email[0]));
        WideCharToMultiByte(CP_ACP, 0, wide_email, -1, g_probe_email,
            sizeof(g_probe_email), 0, 0);
        g_probe_email[sizeof(g_probe_email) - 1] = '\0';
    }
    if (mode == 2 && g_password != 0) {
        WCHAR wide_password[256];

        wide_password[0] = L'\0';
        GetWindowText(g_password, wide_password,
            sizeof(wide_password) / sizeof(wide_password[0]));
        WideCharToMultiByte(CP_ACP, 0, wide_password, -1, g_probe_password,
            sizeof(g_probe_password), 0, 0);
        g_probe_password[sizeof(g_probe_password) - 1] = '\0';
    }

    g_probe_mode = mode;
    start_mega_probe(hwnd);
}

static void
run_crypto_self_test(void)
{
    char report[128];

    report[0] = '\0';
    mega_crypto_self_test(report, sizeof(report));
    append_log_ascii(report);
}

static int
build_app_file_path(const WCHAR *file_name, WCHAR *path, unsigned int path_size)
{
    int i;

    if (file_name == 0 || path == 0 || path_size == 0) {
        return 0;
    }

    path[0] = L'\0';
    GetModuleFileName(0, path, path_size);
    path[path_size - 1] = L'\0';

    for (i = (int)wcslen(path) - 1; i >= 0; --i) {
        if (path[i] == L'\\' || path[i] == L'/') {
            path[i + 1] = L'\0';
            break;
        }
    }
    if (i < 0) {
        path[0] = L'\0';
    }

    _snwprintf(path + wcslen(path), path_size - (unsigned int)wcslen(path),
        L"%s", file_name);
    path[path_size - 1] = L'\0';
    return 1;
}

static void
save_session_to_file(void)
{
    WCHAR session_path[MAX_PATH];

    if (!build_app_file_path(L"session.dat", session_path,
        sizeof(session_path) / sizeof(session_path[0])))
    {
        append_log_text(TEXT("Could not build session.dat path."));
        return;
    }

    if (mega_api_save_session_file(session_path)) {
        post_log_text(TEXT("Saved session.dat beside the executable."));
    } else {
        post_log_text(TEXT("Could not save session.dat."));
    }
}

static int
load_session_from_file(void)
{
    WCHAR session_path[MAX_PATH];

    if (!build_app_file_path(L"session.dat", session_path,
        sizeof(session_path) / sizeof(session_path[0])))
    {
        return 0;
    }

    if (mega_api_load_session_file(session_path)) {
        append_log_text(TEXT("Loaded saved MEGA session."));
        return 1;
    }
    return 0;
}

static void
show_session_status(void)
{
    char status[384];

    status[0] = '\0';
    if (mega_api_get_session_status(status, sizeof(status))) {
        append_log_ascii(status);
    }
}

static void
save_log_to_file(void)
{
    WCHAR log_path[MAX_PATH];
    WCHAR *wide_log;
    char *ansi_log;
    int wide_len;
    int ansi_len;
    HANDLE file;
    DWORD written;

    if (g_log == 0) {
        return;
    }

    wide_len = GetWindowTextLength(g_log);
    if (wide_len <= 0) {
        append_log_text(TEXT("No log text to save."));
        return;
    }

    wide_log = (WCHAR *)LocalAlloc(LPTR, (wide_len + 1) * sizeof(WCHAR));
    if (wide_log == 0) {
        append_log_text(TEXT("Could not allocate memory for log save."));
        return;
    }

    GetWindowText(g_log, wide_log, wide_len + 1);
    ansi_len = WideCharToMultiByte(CP_ACP, 0, wide_log, -1, 0, 0, 0, 0);
    if (ansi_len <= 1) {
        LocalFree((HLOCAL)wide_log);
        append_log_text(TEXT("Could not convert log text."));
        return;
    }

    ansi_log = (char *)LocalAlloc(LPTR, ansi_len);
    if (ansi_log == 0) {
        LocalFree((HLOCAL)wide_log);
        append_log_text(TEXT("Could not allocate memory for log save."));
        return;
    }

    WideCharToMultiByte(CP_ACP, 0, wide_log, -1, ansi_log, ansi_len, 0, 0);
    LocalFree((HLOCAL)wide_log);

    if (!build_app_file_path(L"log.txt", log_path,
        sizeof(log_path) / sizeof(log_path[0])))
    {
        LocalFree((HLOCAL)ansi_log);
        append_log_text(TEXT("Could not build log.txt path."));
        return;
    }

    file = CreateFile(log_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        LocalFree((HLOCAL)ansi_log);
        append_log_text(TEXT("Could not create log.txt beside the executable."));
        return;
    }

    written = 0;
    WriteFile(file, ansi_log, (DWORD)(ansi_len - 1), &written, 0);
    CloseHandle(file);
    LocalFree((HLOCAL)ansi_log);

    append_log_text(TEXT("Saved log.txt beside the executable."));
}

static void
layout_children(HWND hwnd)
{
    RECT rc;
    int margin;
    int button_height;
    int log_top;
    int content_top;
    int content_height;
    int bottom_reserved;
    int usable_bottom;
    int spinner_size;

    GetClientRect(hwnd, &rc);
    margin = scale_x(6);
    button_height = scale_y(28);
    spinner_size = scale_y(22);
    if (spinner_size < 16) {
        spinner_size = 16;
    }
    bottom_reserved = get_bottom_reserved_height();
    usable_bottom = rc.bottom - rc.top - bottom_reserved;
    if (usable_bottom < margin * 2 + scale_y(40)) {
        usable_bottom = rc.bottom - rc.top - margin;
    }
    content_top = margin;
    content_height = usable_bottom - content_top - margin;
    if (content_height < scale_y(40)) {
        content_height = scale_y(40);
    }

    MoveWindow(g_files,
        margin, content_top,
        rc.right - rc.left - margin * 2,
        content_height,
        TRUE);

    MoveWindow(g_spinner,
        rc.right - rc.left - margin - scale_x(90),
        content_top + scale_y(2),
        scale_x(90),
        spinner_size,
        TRUE);
    if (g_spinner_active) {
        SetWindowPos(g_spinner, HWND_TOP, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    MoveWindow(GetDlgItem(hwnd, IDC_MEGACE_LOGIN),
        margin, margin,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_email,
        margin, margin * 2 + button_height,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_password,
        margin, margin * 3 + button_height * 2,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_sync_label,
        margin, margin,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_sync_dir,
        margin, margin * 2 + button_height,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(GetDlgItem(hwnd, IDC_MEGACE_SAVESETTINGS),
        margin, margin * 5 + button_height * 4,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_text_size_label,
        margin, margin * 3 + button_height * 2,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_text_size_edit,
        margin, margin * 4 + button_height * 3,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_sync_status_label,
        margin, margin,
        rc.right - rc.left - margin * 2,
        button_height * 2,
        TRUE);

    MoveWindow(g_sync_progress,
        margin, margin * 3 + button_height * 2,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_create_folder_label,
        margin, margin,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_create_folder_name,
        margin, margin * 2 + button_height,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(GetDlgItem(hwnd, IDC_MEGACE_CREATEFOLDERGO),
        margin, margin * 3 + button_height * 2,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_rename_label,
        margin, margin,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(g_rename_name,
        margin, margin * 2 + button_height,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    MoveWindow(GetDlgItem(hwnd, IDC_MEGACE_RENAMEGO),
        margin, margin * 3 + button_height * 2,
        rc.right - rc.left - margin * 2,
        button_height,
        TRUE);

    log_top = margin * 4 + button_height * 3;
    content_height = usable_bottom - log_top - margin;
    if (content_height < scale_y(40)) {
        content_height = scale_y(40);
    }

    MoveWindow(g_log,
        margin, margin,
        rc.right - rc.left - margin * 2,
        usable_bottom - margin * 2,
        TRUE);

}

static LRESULT CALLBACK
main_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
    {
        SHMENUBARINFO mbi;

        g_main_window = hwnd;
        init_ui_metrics(hwnd);

        memset(&mbi, 0, sizeof(mbi));
        mbi.cbSize = sizeof(mbi);
        mbi.hwndParent = hwnd;
        mbi.nToolBarId = IDR_MEGACE_MENU;
        mbi.hInstRes = ((LPCREATESTRUCT)lParam)->hInstance;
        if (SHCreateMenuBar(&mbi)) {
            g_menu_bar = mbi.hwndMB;
        } else {
            g_menu_bar = 0;
        }
        load_settings();

        g_files = CreateWindow(WC_LISTVIEW, TEXT(""),
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
            LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_FILES,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);
        g_files_old_proc = (WNDPROC)SetWindowLong(g_files, GWL_WNDPROC,
            (LONG)files_wnd_proc);
        setup_file_columns();

        g_spinner = CreateWindow(TEXT("STATIC"), TEXT("Working |"),
            WS_CHILD | WS_BORDER | SS_CENTER,
            0, 0, 0, 0,
            hwnd, 0,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);
        ShowWindow(g_spinner, SW_HIDE);

        CreateWindow(TEXT("BUTTON"), TEXT("Login"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_LOGIN,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_email = CreateWindow(TEXT("EDIT"), TEXT(""),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_EMAIL,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_password = CreateWindow(TEXT("EDIT"), TEXT(""),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_PASSWORD,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_sync_label = CreateWindow(TEXT("STATIC"), TEXT("Sync directory"),
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hwnd, 0,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_sync_dir = CreateWindow(TEXT("EDIT"), g_sync_directory,
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_SYNCDIR,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_text_size_label = CreateWindow(TEXT("STATIC"), TEXT("Text size"),
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hwnd, 0,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_text_size_edit = CreateWindow(TEXT("EDIT"), TEXT(""),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_TEXTSIZE,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);
        update_text_size_controls();

        g_sync_status_label = CreateWindow(TEXT("STATIC"), TEXT("Ready to sync"),
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_SYNCSTATUS,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_sync_progress = CreateWindow(PROGRESS_CLASS, TEXT(""),
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_SYNCPROGRESS,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);
        SendMessage(g_sync_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(g_sync_progress, PBM_SETPOS, 0, 0);

        CreateWindow(TEXT("BUTTON"), TEXT("Save Settings"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_SAVESETTINGS,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_create_folder_label = CreateWindow(TEXT("STATIC"), TEXT("Folder name"),
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hwnd, 0,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_create_folder_name = CreateWindow(TEXT("EDIT"), TEXT("New Folder"),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_CREATEFOLDERNAME,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        CreateWindow(TEXT("BUTTON"), TEXT("Create Folder"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_CREATEFOLDERGO,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_rename_label = CreateWindow(TEXT("STATIC"), TEXT("New name"),
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0,
            hwnd, 0,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_rename_name = CreateWindow(TEXT("EDIT"), TEXT(""),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_RENAMENAME,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        CreateWindow(TEXT("BUTTON"), TEXT("Rename"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_RENAMEGO,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);

        g_log = CreateWindow(TEXT("EDIT"), TEXT("MegaCE ready.\r\n"),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE |
            ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            0, 0, 0, 0,
            hwnd, (HMENU)IDC_MEGACE_LOG,
            ((LPCREATESTRUCT)lParam)->hInstance, 0);
        apply_text_size(hwnd);
        if (load_session_from_file()) {
            g_current_parent[0] = '\0';
            g_parent_depth = 0;
        }
        populate_file_list();
        set_view_mode(hwnd, MEGACE_VIEW_FILES);
        return 0;
    }

    case WM_SIZE:
        layout_children(hwnd);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_MEGACE_PING) {
            start_mega_probe_mode(hwnd, 0);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_US0) {
            start_mega_probe_mode(hwnd, 1);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_LOGIN) {
            start_mega_probe_mode(hwnd, 2);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SHOWFILES) {
            set_view_mode(hwnd, MEGACE_VIEW_FILES);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SHOWLOGIN) {
            set_view_mode(hwnd, MEGACE_VIEW_LOGIN);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SHOWSETTINGS) {
            set_view_mode(hwnd, MEGACE_VIEW_SETTINGS);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SHOWLOGS) {
            set_view_mode(hwnd, MEGACE_VIEW_LOGS);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CRYPTO) {
            run_crypto_self_test();
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SESSION) {
            show_session_status();
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_FETCH) {
            start_mega_probe_mode(hwnd, 3);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SAVELOG) {
            save_log_to_file();
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SAVESETTINGS) {
            save_settings();
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_SYNCNOW) {
            start_one_way_sync(hwnd);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CREATEFOLDER) {
            set_view_mode(hwnd, MEGACE_VIEW_CREATE_FOLDER);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CREATEFOLDERGO) {
            start_server_operation(hwnd, MEGACE_SERVER_OP_CREATE_FOLDER, -1);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_RENAMEGO) {
            start_server_operation(hwnd, MEGACE_SERVER_OP_RENAME,
                g_rename_node_index);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CONTEXT_DOWNLOAD) {
            start_selected_download(hwnd, g_context_node_index);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CONTEXT_RENAME) {
            show_rename_page(hwnd, g_context_node_index);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CONTEXT_DELETE) {
            start_server_operation(hwnd, MEGACE_SERVER_OP_DELETE,
                g_context_node_index);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CONTEXT_SYNCTHIS) {
            add_node_to_current_sync(g_context_node_index);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_CONTEXT_REMOVEFROMSYNC) {
            remove_node_from_current_sync(g_context_node_index);
            return 0;
        }
        if (LOWORD(wParam) == IDC_MEGACE_EXIT) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;

    case WM_NOTIFY:
    {
        NMHDR *hdr;

        hdr = (NMHDR *)lParam;
        if (hdr != 0 && hdr->idFrom == IDC_MEGACE_FILES
            && hdr->code == NM_DBLCLK)
        {
            open_selected_file_item();
            return 0;
        }
        if (hdr != 0 && hdr->idFrom == IDC_MEGACE_FILES
            && hdr->code == NM_RCLICK)
        {
            show_file_context_menu(hwnd);
            return 0;
        }
        if (hdr != 0 && hdr->idFrom == IDC_MEGACE_FILES
            && hdr->code == LVN_COLUMNCLICK)
        {
            NMLISTVIEW *list_view;

            list_view = (NMLISTVIEW *)lParam;
            if (list_view->iSubItem >= 0 && list_view->iSubItem <= 2) {
                if (g_file_sort_column == list_view->iSubItem) {
                    g_file_sort_reverse = !g_file_sort_reverse;
                } else {
                    g_file_sort_column = list_view->iSubItem;
                    g_file_sort_reverse = 0;
                }
                populate_file_list();
            }
            return 0;
        }
        if (hdr != 0
            && (hdr->code == HDN_ENDTRACK || hdr->code == HDN_ENDTRACKW))
        {
            schedule_file_column_width_save(hwnd);
            return 0;
        }
        break;
    }

    case WM_TIMER:
        if (wParam == MEGACE_COLUMN_SAVE_TIMER) {
            KillTimer(hwnd, MEGACE_COLUMN_SAVE_TIMER);
            save_file_column_widths();
            return 0;
        }
        if (wParam == MEGACE_SPINNER_TIMER) {
            advance_spinner();
            return 0;
        }
        break;

    case WM_CONTEXTMENU:
        if ((HWND)wParam == g_files || wParam == 0) {
            show_file_context_menu(hwnd);
            return 0;
        }
        break;

    case WM_MEGACE_LOG:
        if (lParam != 0) {
            append_log_text((const WCHAR *)lParam);
            LocalFree((HLOCAL)lParam);
        }
        return 0;

    case WM_MEGACE_SYNC_STATUS:
        if (lParam != 0) {
            if (g_sync_status_label != 0) {
                SetWindowText(g_sync_status_label, (const WCHAR *)lParam);
            }
            LocalFree((HLOCAL)lParam);
        }
        if (g_sync_progress != 0) {
            SendMessage(g_sync_progress, PBM_SETPOS, wParam, 0);
        }
        return 0;

    case WM_MEGACE_DONE:
        stop_spinner(hwnd);
        InterlockedExchange(&g_probe_running, 0);
        EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_PING), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_US0), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_MEGACE_LOGIN), TRUE);
        if (g_probe_mode == 3) {
            populate_file_list();
            set_view_mode(hwnd, MEGACE_VIEW_FILES);
        }
        append_log_text(TEXT("MEGA API test finished."));
        return 0;

    case WM_MEGACE_DOWNLOAD_DONE:
        InterlockedExchange(&g_probe_running, 0);
        append_log_text(TEXT("Download operation finished."));
        return 0;

    case WM_MEGACE_SYNC_DONE:
        InterlockedExchange(&g_probe_running, 0);
        populate_file_list();
        append_log_text(TEXT("Sync operation finished."));
        if (g_download_mode == MEGACE_DOWNLOAD_MODE_SYNC
            && g_sync_conflict_count > 0)
        {
            ask_and_resolve_sync_conflicts(hwnd);
        }
        return 0;

    case WM_MEGACE_CONFLICT_DONE:
    {
        WCHAR message[96];

        InterlockedExchange(&g_probe_running, 0);
        _snwprintf(message, sizeof(message) / sizeof(message[0]),
            L"Conflicts resolved: %u, failed: %u",
            (unsigned int)wParam, (unsigned int)lParam);
        message[(sizeof(message) / sizeof(message[0])) - 1] = L'\0';
        append_log_text(message);
        return 0;
    }

    case WM_MEGACE_SERVER_OP_DONE:
        stop_spinner(hwnd);
        InterlockedExchange(&g_probe_running, 0);
        populate_file_list();
        set_view_mode(hwnd, MEGACE_VIEW_FILES);
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, MEGACE_COLUMN_SAVE_TIMER);
        save_file_column_widths();
        if (g_files != 0 && g_files_old_proc != 0) {
            SetWindowLong(g_files, GWL_WNDPROC, (LONG)g_files_old_proc);
            g_files_old_proc = 0;
        }
        if (g_file_images != 0) {
            ImageList_Destroy(g_file_images);
            g_file_images = 0;
        }
        if (g_menu_bar != 0) {
            CommandBar_Destroy(g_menu_bar);
            g_menu_bar = 0;
        }
        free_file_item_nodes();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    WNDCLASS wc;
    HWND hwnd;
    MSG msg;

    (void)hPrevInstance;
    (void)lpCmdLine;

    hwnd = FindWindow(MEGACE_CLASS_NAME, MEGACE_TITLE);
    if (hwnd != 0) {
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        return 0;
    }

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = main_wnd_proc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MEGACE_APP));
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = MEGACE_CLASS_NAME;

    InitCommonControls();

    if (!RegisterClass(&wc)) {
        return 1;
    }

    hwnd = CreateWindow(MEGACE_CLASS_NAME, MEGACE_TITLE,
        WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT,
        0, 0, hInstance, 0);

    if (hwnd == 0) {
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, 0, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
