/* generated_c_functions.c  (phien ban 2)
 * Sinh tu iot_gateway_memaudit_spec.xlsx (sheet HamSinhMa): 35 ham C + cac hang so/kieu cua gateway.
 * Quy uoc: ham KHONG co hau to _safe CO LOI CO Y
 *   (buffer-overflow / memory-leak / double-free / use-after-free / integer-overflow).
 * Chi dung de kiem toan hoc tap, KHONG dua vao san pham.
 *
 * Thay doi so voi phien ban 1:
 *   - Them hang so gateway (khop sheet GiaDinhGateway), kieu goi tin packet_t (khop DinhNghiaGoiTin),
 *     enum trang thai pkt_state_t (khop MoHinhTrangThai).
 *   - parse_*_safe: tra ma loi (-1 = NULL, -2 = qua dai), KHONG cat bot im lang.
 *   - sum_telemetry_bytes / compute_packet_total duoc ghi nhan la loi integer-overflow, co ban _safe.
 *   - Them 5 ban _safe con thieu: write_audit_record, buffer_telemetry_batch, close_tls_context,
 *     close_mqtt_channel, drop_pending_packet.
 *   - Them close_shared_session (race -> double-free) va close_shared_session_safe (atomic_exchange).
 *   - Them gateway_process_packet_safe: hien thuc cac statement ST-1..ST-7 va vong doi goi tin.
 *
 * Cach dung:
 *   1) Quet / dua vao cong cu:   SecLabFramework.exe --cli-cwrap generated_c_functions.c
 *   2) Chay thuc te voi ASan:
 *        gcc -g -O0 -Wall -Wextra -std=c11 -DAUDIT_MAIN -fsanitize=address,undefined \
 *            generated_c_functions.c -o audit -pthread
 *        ./audit parse_device_id 16            # buffer_copy: tham so 2 la DO DAI chuoi dau vao
 *        ./audit parse_device_id_safe 16       # in rc=-2 (tu choi)
 *        ./audit parse_device_id_safe 0 null   # truyen con tro NULL -> rc=-1
 *        ./audit write_log_entry               # alloc_release: khong can tham so
 *        ./audit close_shared_session          # 2 luong cung dong phien (lap 1000 lan)
 *        ./audit sum_telemetry_bytes 2147483647 1
 *        ./audit sum_telemetry_bytes_safe 2147483647 1
 *        ./audit gateway_process_packet_safe 5 10 8   # id_len payload_len token_len
 *        ./audit --list                        # liet ke ten ham va loai
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sched.h>

/* ------------------------------------------------------------------ */
/* Gia dinh gateway (sheet GiaDinhGateway) - doi o day thi doi ca sheet */
/* ------------------------------------------------------------------ */
#define GW_MAX_PKT          4096u       /* GD: kich thuoc goi tin toi da (byte)            */
#define GW_STACK_BYTES      65536u      /* GD: stack moi luong (byte)                      */
#define GW_PENDING_QUEUE    64u         /* GD: so goi toi da trong hang doi cho            */
#define GW_HEAP_BYTES       (64u * 1024u * 1024u) /* NFR-8: tong heap toi da               */
#define GW_MAX_DEVICES      200u        /* NFR-8: so thiet bi dong thoi                    */

/* Bo dem C (gom ky tu NUL) cho tung truong chuoi; so ky tu toi da = bo dem - 1 */
#define DEVICE_ID_BUF       16
#define SESSION_TOKEN_BUF   32
#define FW_VERSION_BUF      8
#define MQTT_TOPIC_BUF      64
#define REGION_CODE_BUF     4

#define PKT_MAGIC           0xA55Au

/* ------------------------------------------------------------------ */
/* Goi tin di qua gateway (sheet DinhNghiaGoiTin)                       */
/* Cac *_len la gia tri DO NGUOI GUI KHAI BAO -> khong duoc tin ma phai kiem tra. */
/* ------------------------------------------------------------------ */
typedef struct {
    uint16_t magic;
    uint8_t  version;
    uint8_t  type;                      /* 1=AUTH_REQ 2=AUTH_RESP 3=TELEMETRY 4=LOG 5=FW_UPDATE 6=CLOSE */
    uint16_t header_len;
    uint16_t payload_len;
    uint8_t  device_id_len;     char device_id[DEVICE_ID_BUF];
    uint8_t  token_len;         char session_token[SESSION_TOKEN_BUF];
    uint8_t  fw_len;            char fw_version[FW_VERSION_BUF];
    uint8_t  region_len;        char region[REGION_CODE_BUF];
    uint8_t  topic_len;         char mqtt_topic[MQTT_TOPIC_BUF];
    const uint8_t *payload;
} packet_t;

/* Trang thai goi tin (khop sheet MoHinhTrangThai) */
typedef enum {
    PKT_IDLE = 0, PKT_RECEIVED, PKT_VALIDATING, PKT_PARSED, PKT_AUTHENTICATING,
    PKT_FORWARDED, PKT_DROPPED, PKT_REJECTED, PKT_RELEASED
} pkt_state_t;

/* Ma tra ve cua gateway_process_packet_safe */
enum {
    PKT_OK = 0, PKT_ERR_NULL = -1, PKT_ERR_LEN = -2, PKT_ERR_SIZE = -3,
    PKT_ERR_NOMEM = -4, PKT_ERR_AUTH = -5, PKT_ERR_MAGIC = -6
};

/* ================================================================== */
/* 1. buffer_copy                                                       */
/* ================================================================== */

/* parse_device_id | Loai=buffer_copy | Loi=buffer-overflow | KichThuocBuffer=16 */
void parse_device_id(const char *raw_id) {
    char buf[16];
    strcpy(buf, raw_id);
    (void)buf;
}

/* parse_device_id_safe | Loai=buffer_copy | Loi=(khong loi) | KichThuocBuffer=16 | ST-1, ST-13 */
int parse_device_id_safe(const char *raw_id) {
    char buf[16];
    size_t n;
    if (raw_id == NULL) return -1;
    n = strlen(raw_id);
    if (n > sizeof(buf) - 1) return -2;
    memcpy(buf, raw_id, n + 1);
    (void)buf;
    return 0;
}

/* parse_session_token | Loai=buffer_copy | Loi=buffer-overflow | KichThuocBuffer=32 */
void parse_session_token(const char *raw_token) {
    char buf[32];
    strcpy(buf, raw_token);
    (void)buf;
}

/* parse_session_token_safe | Loai=buffer_copy | Loi=(khong loi) | KichThuocBuffer=32 | ST-1, ST-13 */
int parse_session_token_safe(const char *raw_token) {
    char buf[32];
    size_t n;
    if (raw_token == NULL) return -1;
    n = strlen(raw_token);
    if (n > sizeof(buf) - 1) return -2;
    memcpy(buf, raw_token, n + 1);
    (void)buf;
    return 0;
}

/* parse_firmware_version | Loai=buffer_copy | Loi=buffer-overflow | KichThuocBuffer=8 */
void parse_firmware_version(const char *raw_version) {
    char buf[8];
    strcpy(buf, raw_version);
    (void)buf;
}

/* parse_firmware_version_safe | Loai=buffer_copy | Loi=(khong loi) | KichThuocBuffer=8 | ST-1, ST-13 */
int parse_firmware_version_safe(const char *raw_version) {
    char buf[8];
    size_t n;
    if (raw_version == NULL) return -1;
    n = strlen(raw_version);
    if (n > sizeof(buf) - 1) return -2;
    memcpy(buf, raw_version, n + 1);
    (void)buf;
    return 0;
}

/* parse_mqtt_topic | Loai=buffer_copy | Loi=buffer-overflow | KichThuocBuffer=64 */
void parse_mqtt_topic(const char *raw_topic) {
    char buf[64];
    strcpy(buf, raw_topic);
    (void)buf;
}

/* parse_mqtt_topic_safe | Loai=buffer_copy | Loi=(khong loi) | KichThuocBuffer=64 | ST-1, ST-13 */
int parse_mqtt_topic_safe(const char *raw_topic) {
    char buf[64];
    size_t n;
    if (raw_topic == NULL) return -1;
    n = strlen(raw_topic);
    if (n > sizeof(buf) - 1) return -2;
    memcpy(buf, raw_topic, n + 1);
    (void)buf;
    return 0;
}

/* parse_region_code | Loai=buffer_copy | Loi=buffer-overflow | KichThuocBuffer=4 */
void parse_region_code(const char *raw_region) {
    char buf[4];
    strcpy(buf, raw_region);
    (void)buf;
}

/* parse_region_code_safe | Loai=buffer_copy | Loi=(khong loi) | KichThuocBuffer=4 | ST-1, ST-13 */
int parse_region_code_safe(const char *raw_region) {
    char buf[4];
    size_t n;
    if (raw_region == NULL) return -1;
    n = strlen(raw_region);
    if (n > sizeof(buf) - 1) return -2;
    memcpy(buf, raw_region, n + 1);
    (void)buf;
    return 0;
}

/* ================================================================== */
/* 2. alloc_release - ban loi                                           */
/* ================================================================== */

/* write_log_entry | Loai=alloc_release | Loi=memory-leak | KichThuocBuffer=32 */
void write_log_entry(void) {
    char *p = malloc(32);
    if (!p) return;
    memset(p, 'A', 32);
}

/* write_audit_record | Loai=alloc_release | Loi=memory-leak | KichThuocBuffer=64 */
void write_audit_record(void) {
    char *p = malloc(64);
    if (!p) return;
    memset(p, 'A', 64);
}

/* buffer_telemetry_batch | Loai=alloc_release | Loi=memory-leak | KichThuocBuffer=128 */
void buffer_telemetry_batch(void) {
    char *p = malloc(128);
    if (!p) return;
    memset(p, 'A', 128);
}

/* close_session | Loai=alloc_release | Loi=double-free | KichThuocBuffer=4 */
void close_session(void) {
    char *p = malloc(4);
    if (!p) return;
    memset(p, 'A', 4);
    free(p);
    free(p);
}

/* close_tls_context | Loai=alloc_release | Loi=double-free | KichThuocBuffer=16 */
void close_tls_context(void) {
    char *p = malloc(16);
    if (!p) return;
    memset(p, 'A', 16);
    free(p);
    free(p);
}

/* close_mqtt_channel | Loai=alloc_release | Loi=double-free | KichThuocBuffer=8 */
void close_mqtt_channel(void) {
    char *p = malloc(8);
    if (!p) return;
    memset(p, 'A', 8);
    free(p);
    free(p);
}

/* release_session_buffer | Loai=alloc_release | Loi=use-after-free | KichThuocBuffer=8 */
void release_session_buffer(void) {
    char *p = malloc(8);
    if (!p) return;
    memset(p, 'A', 8);
    free(p);
    p[0] = 'x';
}

/* release_cache_entry | Loai=alloc_release | Loi=use-after-free | KichThuocBuffer=24 */
void release_cache_entry(void) {
    char *p = malloc(24);
    if (!p) return;
    memset(p, 'A', 24);
    free(p);
    p[0] = 'x';
}

/* drop_pending_packet | Loai=alloc_release | Loi=use-after-free | KichThuocBuffer=48 */
void drop_pending_packet(void) {
    char *p = malloc(48);
    if (!p) return;
    memset(p, 'A', 48);
    free(p);
    p[0] = 'x';
}

/* ================================================================== */
/* 3. alloc_release - ban vA (free dung 1 lan + gan NULL, CON-8)        */
/* ================================================================== */

/* write_log_entry_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=32 */
void write_log_entry_safe(void) {
    char *p = malloc(32);
    if (!p) return;
    memset(p, 'A', 32);
    free(p);
    p = NULL;
}

/* write_audit_record_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=64 */
void write_audit_record_safe(void) {
    char *p = malloc(64);
    if (!p) return;
    memset(p, 'A', 64);
    free(p);
    p = NULL;
}

/* buffer_telemetry_batch_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=128 */
void buffer_telemetry_batch_safe(void) {
    char *p = malloc(128);
    if (!p) return;
    memset(p, 'A', 128);
    free(p);
    p = NULL;
}

/* close_session_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=4 */
void close_session_safe(void) {
    char *p = malloc(4);
    if (!p) return;
    memset(p, 'A', 4);
    free(p);
    p = NULL;
}

/* close_tls_context_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=16 */
void close_tls_context_safe(void) {
    char *p = malloc(16);
    if (!p) return;
    memset(p, 'A', 16);
    free(p);
    p = NULL;
}

/* close_mqtt_channel_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=8 */
void close_mqtt_channel_safe(void) {
    char *p = malloc(8);
    if (!p) return;
    memset(p, 'A', 8);
    free(p);
    p = NULL;
}

/* release_session_buffer_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=8 */
void release_session_buffer_safe(void) {
    char *p = malloc(8);
    if (!p) return;
    memset(p, 'A', 8);
    free(p);
    p = NULL;
}

/* release_cache_entry_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=24 */
void release_cache_entry_safe(void) {
    char *p = malloc(24);
    if (!p) return;
    memset(p, 'A', 24);
    free(p);
    p = NULL;
}

/* drop_pending_packet_safe | Loai=alloc_release | Loi=(khong loi) | KichThuocBuffer=48 */
void drop_pending_packet_safe(void) {
    char *p = malloc(48);
    if (!p) return;
    memset(p, 'A', 48);
    free(p);
    p = NULL;
}

/* ================================================================== */
/* 4. shared_session - con tro DUNG CHUNG giua 2 luong (REQ-15, REQ-41) */
/* ================================================================== */
static _Atomic(char *) g_shared_session = NULL;

/* shared_session_open | ham ho tro (khong tinh vao 34 ham kiem toan) */
void shared_session_open(void) {
    char *p = malloc(16);
    if (!p) return;
    memset(p, 'A', 16);
    atomic_store(&g_shared_session, p);
}

/* close_shared_session | Loai=shared_session | Loi=double-free (race check-then-act) | KichThuocBuffer=16 */
void close_shared_session(void) {
    char *p = atomic_load(&g_shared_session);
    if (p != NULL) {
        sched_yield();                          /* mo rong cua so race */
        free(p);
        atomic_store(&g_shared_session, NULL);
    }
}

/* close_shared_session_safe | Loai=shared_session | Loi=(khong loi) | KichThuocBuffer=16 | ST-11 */
void close_shared_session_safe(void) {
    char *p = atomic_exchange(&g_shared_session, NULL);   /* chi 1 luong lay duoc con tro */
    if (p != NULL) { free(p); p = NULL; }
}

/* ================================================================== */
/* 5. arithmetic                                                        */
/* ================================================================== */

/* sum_telemetry_bytes | Loai=arithmetic | Loi=integer-overflow | KichThuocBuffer=16 */
int sum_telemetry_bytes(int a, int b) {
    return a + b;
}

/* sum_telemetry_bytes_safe | Loai=arithmetic | Loi=(khong loi) | KichThuocBuffer=16 | ST-10 */
int sum_telemetry_bytes_safe(int a, int b, int *out) {
    int r;
    if (out == NULL) return -1;
    if (__builtin_add_overflow(a, b, &r)) return -1;
    *out = r;
    return 0;
}

/* compute_packet_total | Loai=arithmetic | Loi=integer-overflow | KichThuocBuffer=16 */
int compute_packet_total(int header_len, int payload_len) {
    return header_len + payload_len;
}

/* compute_packet_total_safe | Loai=arithmetic | Loi=(khong loi) | KichThuocBuffer=16 | ST-3, ST-10 */
int compute_packet_total_safe(int header_len, int payload_len, int *out) {
    int r;
    if (out == NULL) return -1;
    if (header_len < 0 || payload_len < 0) return -1;
    if (__builtin_add_overflow(header_len, payload_len, &r)) return -1;
    if (r > (int)GW_MAX_PKT) return -1;
    *out = r;
    return 0;
}

/* ================================================================== */
/* 6. packet_process - vong doi goi tin (ST-1..ST-7)                    */
/* ================================================================== */

/* Tra ve 1 neu truong chuoi hop le: do dai khai bao < bo dem, co NUL trong bo dem, strlen khop. */
static int field_ok(const char *f, size_t cap, uint8_t claimed) {
    return (size_t)claimed < cap && memchr(f, '\0', cap) != NULL && strlen(f) == (size_t)claimed;
}

/* gateway_process_packet_safe | Loai=packet_process | Loi=(khong loi) | ST-1..ST-7
 * Trang thai: RECEIVED -> VALIDATING -> (REJECTED | PARSED -> AUTHENTICATING -> (DROPPED | FORWARDED)).
 * *state_out nhan trang thai quyet dinh cuoi; sau do goi tin luon duoc giai phong (RELEASED -> IDLE). */
int gateway_process_packet_safe(const packet_t *pkt, pkt_state_t *state_out) {
    pkt_state_t st = PKT_RECEIVED;
    int rc = PKT_OK;
    uint8_t *work = NULL;               /* khoi nho lam viec: blk_allocated -> blk_in_use -> blk_freed */
    unsigned total;

    if (pkt == NULL) {                  /* ST-4 */
        if (state_out != NULL) *state_out = PKT_IDLE;
        return PKT_ERR_NULL;
    }

    st = PKT_VALIDATING;
    if (pkt->magic != PKT_MAGIC) {                                   /* ST-2 */
        st = PKT_REJECTED; rc = PKT_ERR_MAGIC; goto done;
    }
    if (!field_ok(pkt->device_id,     sizeof pkt->device_id,     pkt->device_id_len) ||
        !field_ok(pkt->session_token, sizeof pkt->session_token, pkt->token_len)     ||
        !field_ok(pkt->fw_version,    sizeof pkt->fw_version,    pkt->fw_len)        ||
        !field_ok(pkt->region,        sizeof pkt->region,        pkt->region_len)    ||
        !field_ok(pkt->mqtt_topic,    sizeof pkt->mqtt_topic,    pkt->topic_len)) {  /* ST-1 */
        st = PKT_REJECTED; rc = PKT_ERR_LEN; goto done;
    }
    total = (unsigned)pkt->header_len + (unsigned)pkt->payload_len;
    if (total > GW_MAX_PKT) {                                        /* ST-3 */
        st = PKT_REJECTED; rc = PKT_ERR_SIZE; goto done;
    }
    if (pkt->payload_len > 0 && pkt->payload == NULL) {              /* ST-4 */
        st = PKT_REJECTED; rc = PKT_ERR_NULL; goto done;
    }

    st = PKT_PARSED;
    work = malloc(pkt->payload_len > 0 ? pkt->payload_len : 1u);
    if (work == NULL) {                                              /* ST-5 */
        st = PKT_DROPPED; rc = PKT_ERR_NOMEM; goto done;
    }
    if (pkt->payload_len > 0) memcpy(work, pkt->payload, pkt->payload_len);

    st = PKT_AUTHENTICATING;
    if (pkt->device_id_len == 0 || pkt->token_len == 0) {            /* ST-6 (gia lap xac thuc) */
        st = PKT_DROPPED; rc = PKT_ERR_AUTH; goto done;
    }
    if (parse_device_id_safe(pkt->device_id) != 0 ||
        parse_session_token_safe(pkt->session_token) != 0 ||
        parse_firmware_version_safe(pkt->fw_version) != 0 ||
        parse_region_code_safe(pkt->region) != 0 ||
        parse_mqtt_topic_safe(pkt->mqtt_topic) != 0) {
        st = PKT_REJECTED; rc = PKT_ERR_LEN; goto done;
    }
    st = PKT_FORWARDED;

done:                                                                /* ST-7: moi duong thoat deu giai phong */
    free(work);
    work = NULL;
    if (state_out != NULL) *state_out = st;
    return rc;
}

/* ================================================================== */
#ifdef AUDIT_MAIN
#include <pthread.h>

/* Loai: B=parse loi(void), S=parse safe(int), A=alloc(void), M=so hoc(int,int),
 *       O=so hoc safe(int,int,int*), T=2 luong dong phien chung, P=xu ly goi tin */
typedef struct { const char *name; char kind; void *fn; } Entry;
static const Entry TABLE[] = {
    {"parse_device_id", 'B', (void *)parse_device_id},
    {"parse_device_id_safe", 'S', (void *)parse_device_id_safe},
    {"parse_session_token", 'B', (void *)parse_session_token},
    {"parse_session_token_safe", 'S', (void *)parse_session_token_safe},
    {"parse_firmware_version", 'B', (void *)parse_firmware_version},
    {"parse_firmware_version_safe", 'S', (void *)parse_firmware_version_safe},
    {"parse_mqtt_topic", 'B', (void *)parse_mqtt_topic},
    {"parse_mqtt_topic_safe", 'S', (void *)parse_mqtt_topic_safe},
    {"parse_region_code", 'B', (void *)parse_region_code},
    {"parse_region_code_safe", 'S', (void *)parse_region_code_safe},
    {"write_log_entry", 'A', (void *)write_log_entry},
    {"write_audit_record", 'A', (void *)write_audit_record},
    {"buffer_telemetry_batch", 'A', (void *)buffer_telemetry_batch},
    {"close_session", 'A', (void *)close_session},
    {"close_tls_context", 'A', (void *)close_tls_context},
    {"close_mqtt_channel", 'A', (void *)close_mqtt_channel},
    {"release_session_buffer", 'A', (void *)release_session_buffer},
    {"release_cache_entry", 'A', (void *)release_cache_entry},
    {"drop_pending_packet", 'A', (void *)drop_pending_packet},
    {"write_log_entry_safe", 'A', (void *)write_log_entry_safe},
    {"write_audit_record_safe", 'A', (void *)write_audit_record_safe},
    {"buffer_telemetry_batch_safe", 'A', (void *)buffer_telemetry_batch_safe},
    {"close_session_safe", 'A', (void *)close_session_safe},
    {"close_tls_context_safe", 'A', (void *)close_tls_context_safe},
    {"close_mqtt_channel_safe", 'A', (void *)close_mqtt_channel_safe},
    {"release_session_buffer_safe", 'A', (void *)release_session_buffer_safe},
    {"release_cache_entry_safe", 'A', (void *)release_cache_entry_safe},
    {"drop_pending_packet_safe", 'A', (void *)drop_pending_packet_safe},
    {"close_shared_session", 'T', (void *)close_shared_session},
    {"close_shared_session_safe", 'T', (void *)close_shared_session_safe},
    {"sum_telemetry_bytes", 'M', (void *)sum_telemetry_bytes},
    {"sum_telemetry_bytes_safe", 'O', (void *)sum_telemetry_bytes_safe},
    {"compute_packet_total", 'M', (void *)compute_packet_total},
    {"compute_packet_total_safe", 'O', (void *)compute_packet_total_safe},
    {"gateway_process_packet_safe", 'P', (void *)gateway_process_packet_safe},
};

static const char *PKT_STATE_NAME[] = {
    "pkt_idle", "pkt_received", "pkt_validating", "pkt_parsed", "pkt_authenticating",
    "pkt_forwarded", "pkt_dropped", "pkt_rejected", "pkt_released"
};

static void *close_thread(void *arg) {
    ((void (*)(void))arg)();
    return NULL;
}

static void fill_field(char *dst, size_t cap, size_t want, char c) {
    size_t n = want < cap - 1 ? want : cap - 1;
    memset(dst, c, n);
}

int main(int argc, char **argv) {
    size_t n = sizeof TABLE / sizeof TABLE[0];
    if (argc >= 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < n; i++) printf("%-32s %c\n", TABLE[i].name, TABLE[i].kind);
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "dung: %s <ten_ham> [do_dai [null] | a b | id_len payload_len token_len]   hoac --list\n", argv[0]);
        return 2;
    }
    for (size_t i = 0; i < n; i++) {
        if (strcmp(argv[1], TABLE[i].name) != 0) continue;
        switch (TABLE[i].kind) {
        case 'B':
        case 'S': {
            size_t len = argc > 2 ? (size_t)atol(argv[2]) : 0;
            int use_null = argc > 3 && strcmp(argv[3], "null") == 0;
            char *s = malloc(len + 1);
            if (!s) return 2;
            memset(s, 'A', len); s[len] = '\0';
            if (TABLE[i].kind == 'B') {
                ((void (*)(const char *))TABLE[i].fn)(use_null ? NULL : s);
            } else {
                int rc = ((int (*)(const char *))TABLE[i].fn)(use_null ? NULL : s);
                printf("rc=%d\n", rc);
            }
            free(s);
            break;
        }
        case 'A':
            ((void (*)(void))TABLE[i].fn)();
            break;
        case 'T':
            for (int k = 0; k < 1000; k++) {
                pthread_t t1, t2;
                shared_session_open();
                pthread_create(&t1, NULL, close_thread, TABLE[i].fn);
                pthread_create(&t2, NULL, close_thread, TABLE[i].fn);
                pthread_join(t1, NULL);
                pthread_join(t2, NULL);
            }
            printf("done 1000 vong\n");
            break;
        case 'M': {
            int a = argc > 2 ? atoi(argv[2]) : 0, b = argc > 3 ? atoi(argv[3]) : 0;
            printf("%d\n", ((int (*)(int, int))TABLE[i].fn)(a, b));
            break;
        }
        case 'O': {
            int a = argc > 2 ? atoi(argv[2]) : 0, b = argc > 3 ? atoi(argv[3]) : 0, out = 0;
            int rc = ((int (*)(int, int, int *))TABLE[i].fn)(a, b, &out);
            printf("rc=%d out=%d\n", rc, out);
            break;
        }
        case 'P': {
            size_t idl  = argc > 2 ? (size_t)atol(argv[2]) : 5;
            long   plen = argc > 3 ? atol(argv[3]) : 10;
            size_t tokl = argc > 4 ? (size_t)atol(argv[4]) : 8;
            packet_t pk;
            pkt_state_t st = PKT_IDLE;
            uint8_t *payload = malloc(plen > 0 ? (size_t)plen : 1u);
            if (!payload) return 2;
            memset(payload, 0x5A, plen > 0 ? (size_t)plen : 1u);
            memset(&pk, 0, sizeof pk);
            pk.magic = PKT_MAGIC; pk.version = 1; pk.type = 3;
            pk.header_len = 32; pk.payload_len = (uint16_t)plen; pk.payload = payload;
            pk.device_id_len = (uint8_t)idl;  fill_field(pk.device_id, sizeof pk.device_id, idl, 'D');
            pk.token_len = (uint8_t)tokl;     fill_field(pk.session_token, sizeof pk.session_token, tokl, 'T');
            pk.fw_len = 6;     memcpy(pk.fw_version, "v1.0.0", 6);
            pk.region_len = 2; memcpy(pk.region, "VN", 2);
            pk.topic_len = 9;  memcpy(pk.mqtt_topic, "gw/auth/1", 9);
            int rc = ((int (*)(const packet_t *, pkt_state_t *))TABLE[i].fn)(&pk, &st);
            printf("rc=%d state=%s\n", rc, PKT_STATE_NAME[st]);
            free(payload);
            break;
        }
        }
        return 0;
    }
    fprintf(stderr, "khong co ham '%s' (dung --list)\n", argv[1]);
    return 2;
}
#endif
