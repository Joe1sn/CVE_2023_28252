// clfs_types.h
// 严格依据 "CLFS Internals.txt" 整理，自包含，可直接被 IDA 解析
#ifndef _CLFS_TYPES_H_
#define _CLFS_TYPES_H_

// ============================================================
// 编译环境下优先使用 Windows SDK 的官方 CLFS 定义。
// clfsw32.h -> clfs.h 已经定义了 CLFS_LSN / CLFS_NODE_ID /
// CLFS_CONTAINER_STATE / CLFS_CONTAINER_ID / CLFS_LOG_ID，
// 若本文件再定义会触发 C2371/C2011 等重定义错误。
// 定义 CLFS_TYPES_STANDALONE 可强制使用本文件的独立定义（供 IDA 解析）。
// ============================================================
#if defined(_WIN32) && !defined(CLFS_TYPES_STANDALONE)
#include <windows.h>
#include <clfsw32.h>
#define CLFS_TYPES_HAS_SDK_TYPES 1
#endif

#ifndef CLFS_TYPES_HAS_SDK_TYPES
// ============================================================
// 基础类型定义（替代 windows.h）
// ============================================================
typedef unsigned char       UCHAR;
typedef unsigned char       BYTE;
typedef unsigned short      USHORT;
typedef unsigned long       ULONG;
typedef unsigned long long  ULONGLONG;
typedef long long           LONGLONG;
typedef long                LONG;
typedef void* PVOID;
typedef void* HANDLE;
typedef UCHAR               BOOLEAN;
#endif // CLFS_TYPES_HAS_SDK_TYPES

// typedef struct _GUID {
//     ULONG  Data1;
//     USHORT Data2;
//     USHORT Data3;
//     UCHAR  Data4[8];
// } GUID, * PGUID;

// typedef union _LARGE_INTEGER {
//     struct {
//         ULONG LowPart;
//         LONG  HighPart;
//     };
//     LONGLONG QuadPart;
// } LARGE_INTEGER, * PLARGE_INTEGER;

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

// ============================================================
// CLFS 基础类型
// ============================================================
typedef UCHAR       CLFS_CLIENT_ID;
typedef ULONGLONG   CLFS_USN;
#ifndef CLFS_TYPES_HAS_SDK_TYPES
typedef ULONG       CLFS_CONTAINER_ID;
typedef ULONGLONG   CLFS_LSN;
typedef GUID        CLFS_LOG_ID;
#endif // CLFS_TYPES_HAS_SDK_TYPES
typedef UCHAR       CLFS_LOG_STATE, * PCLFS_LOG_STATE;

// CLFS 日志状态常量
#define CLFS_LOG_UNINITIALIZED          0x01
#define CLFS_LOG_INITIALIZED            0x02
#define CLFS_LOG_ACTIVE                 0x04
#define CLFS_LOG_PENDING_DELETE         0x08
#define CLFS_LOG_PENDING_ARCHIVE        0x10
#define CLFS_LOG_SHUTDOWN               0x20
#define CLFS_LOG_MULTIPLEXED            0x40
#define CLFS_LOG_SECURE                 0x80

// ============================================================
// CLFS_NODE_ID — 每个 CLFS 结构均以此为前缀
// ============================================================
#ifndef CLFS_TYPES_HAS_SDK_TYPES
typedef struct _CLFS_NODE_ID {
    ULONG cType;    // 节点类型码
    ULONG cbNode;   // 节点总大小
} CLFS_NODE_ID, * PCLFS_NODE_ID;
#endif // CLFS_TYPES_HAS_SDK_TYPES

// 节点类型码常量（"C1FD" + 标识符，leetspeak）
#define CLFS_NODE_TYPE_FCB                      0xC1FDF001
#define CLFS_NODE_TYPE_VCB                      0xC1FDF002
#define CLFS_NODE_TYPE_CCB                      0xC1FDF003
#define CLFS_NODE_TYPE_REQ                      0xC1FDF004
#define CLFS_NODE_TYPE_CCA                      0xC1FDF005
#define CLFS_NODE_TYPE_SYMBOL                   0xC1FDF006
#define CLFS_NODE_TYPE_CLIENT_CONTEXT           0xC1FDF007
#define CLFS_NODE_TYPE_CONTAINER_CONTEXT        0xC1FDF008
#define CLFS_NODE_TYPE_DEVICE_EXTENSION         0xC1FDF009
#define CLFS_NODE_TYPE_MARSHALING_AREA          0xC1FDF00A
#define CLFS_NODE_TYPE_ARCHIVE_CONTEXT          0xC1FDF00C
#define CLFS_NODE_TYPE_SHARED_SECURITY_CONTEXT  0xC1FDF00D
#define CLFS_NODE_TYPE_SCAN_CONTEXT             0xC1FDF00E
#define CLFS_NODE_TYPE_LOG_READ_IOCB            0xC1FDF00F
#define CLFS_NODE_TYPE_LOG_WRITE_IOCB           0xC1FDF010

// ============================================================
// 扇区与日志块相关常量
// ============================================================
#define CLFS_SECTOR_SIZE                0x00000200
#define SECTORSHIFT                     9

#define SECTOR_BLOCK_NONE               0x00
#define SECTOR_BLOCK_DATA               0x04
#define SECTOR_BLOCK_OWNER              0x08
#define SECTOR_BLOCK_BASE               0x10
#define SECTOR_BLOCK_END                0x20
#define SECTOR_BLOCK_BEGIN              0x40

// CLFS_LOG_BLOCK_HEADER 版本与标志
#define MAJORVERSION                    0x15
#define MINORVERSION                    0x00

#define CLFS_BLOCK_RESET                0x00000000
#define CLFS_BLOCK_ENCODED              0x00000001
#define CLFS_BLOCK_DECODED              0x00000002
#define CLFS_BLOCK_LATCHED              0x00000004
#define CLFS_BLOCK_TRUNCATE_DISCARD     0x00000008

// 元数据块数量与 Magic
#define CLFS_METADATA_BLOCK_COUNT       6
#define CLFS_CONTROL_BLOCK_RAW_SECTORS  2
#define CLFS_CONTROL_RECORD_MAGIC_VALUE 0xC1F5C1F500005F1CULL
#define MAJORVERSION_CONTROL            0x01

// 客户端与容器上限
#define MAX_CLIENTS_DEFAULT             124
#define HIGHEST_CLIENT_ID               96
#define CLIENT_SYMTBL_SIZE              11
#define MAX_CONTAINERS_DEFAULT          1024
#define CONTAINER_SYMTBL_SIZE           11
#define SHARED_SECURITY_SYMTBL_SIZE     11

// ============================================================
// CLFS_METADATA_RECORD_HEADER — 每个元数据记录均以此开头
// （文档明确指出只有 ullDumpCount 一个字段）
// ============================================================
typedef struct _CLFS_METADATA_RECORD_HEADER {
    ULONGLONG ullDumpCount;    // 元数据记录序列号，用于识别最新/最新鲜副本
} CLFS_METADATA_RECORD_HEADER, * PCLFS_METADATA_RECORD_HEADER;

// ============================================================
// CLFS_METADATA_BLOCK_TYPE — 6 种元数据块类型
// ============================================================
typedef enum _CLFS_METADATA_BLOCK_TYPE {
    ClfsMetaBlockControl = 0,    // 控制记录
    ClfsMetaBlockControlShadow = 1,    // 控制记录影子块
    ClfsMetaBlockGeneral = 2,    // 通用（基础）记录
    ClfsMetaBlockGeneralShadow = 3,    // 通用记录影子块
    ClfsMetaBlockScratch = 4,    // 临时（截断）记录
    ClfsMetaBlockScratchShadow = 5     // 临时记录影子块
} CLFS_METADATA_BLOCK_TYPE, * PCLFS_METADATA_BLOCK_TYPE;

// ============================================================
// CLFS_METADATA_BLOCK — 元数据块描述符
// ============================================================
typedef struct _CLFS_METADATA_BLOCK {
    union {
        UCHAR* pbImage;      // 内存中：块数据指针
        ULONGLONG ullAlignment; // 对齐
    };
    ULONG                      cbImage;     // 块大小
    ULONG                      cbOffset;    // 距 Base Log File 起始偏移
    CLFS_METADATA_BLOCK_TYPE   eBlockType;  // 块类型
} CLFS_METADATA_BLOCK, * PCLFS_METADATA_BLOCK;

// ============================================================
// CLFS_EXTEND_STATE — 日志扩展状态
// ============================================================
typedef enum _CLFS_EXTEND_STATE {
    ClfsExtendStateNone = 0,
    ClfsExtendStateExtendingFsd = 1,
    ClfsExtendStateFlushingBlock = 2
} CLFS_EXTEND_STATE, * PCLFS_EXTEND_STATE;

// ============================================================
// CLFS_TRUNCATE_STATE — 截断状态
// ============================================================
typedef enum _CLFS_TRUNCATE_STATE {
    ClfsTruncateStateNone = 0,
    ClfsTruncateStateModifyingStream = 1,
    ClfsTruncateStateSavingOwner = 2,
    ClfsTruncateStateModifyingOwner = 3,
    ClfsTruncateStateSavingDiscardBlock = 4,
    ClfsTruncateStateModifyingDiscardBlock = 5
} CLFS_TRUNCATE_STATE, * PCLFS_TRUNCATE_STATE;

// ============================================================
// CLFS_TRUNCATE_CONTEXT — 截断上下文
// ============================================================
typedef struct _CLFS_TRUNCATE_CONTEXT {
    CLFS_TRUNCATE_STATE eTruncateState;   // 当前截断状态
    CLFS_CLIENT_ID      cClients;         // 被截断的客户端数量
    CLFS_CLIENT_ID      iClient;          // 当前正在截断的客户端索引
    CLFS_LSN            lsnOwnerPage;     // 当前 owner page 的 LSN
    CLFS_LSN            lsnLastOwnerPage; // 最后 owner page 的 LSN
    ULONG               cInvalidSector;   // 正在处理的无效扇区索引
} CLFS_TRUNCATE_CONTEXT, * PCLFS_TRUNCATE_CONTEXT;

// ============================================================
// CLFS_CONTROL_RECORD — 控制记录（控制元数据块的主内容）
// ============================================================
typedef struct _CLFS_CONTROL_RECORD {
    CLFS_METADATA_RECORD_HEADER hdrControlRecord;
    ULONGLONG                   ullMagicValue;      // 固定 Magic 0xC1F5C1F500005F1C
    UCHAR                       Version;            // 当前为 1
    CLFS_EXTEND_STATE           eExtendState;
    USHORT                      iExtendBlock;
    USHORT                      iFlushBlock;
    ULONG                       cNewBlockSectors;
    ULONG                       cExtendStartSectors;
    ULONG                       cExtendSectors;
    CLFS_TRUNCATE_CONTEXT       cxTruncate;
    USHORT                      cBlocks;            // rgBlocks 中的块数
    ULONG                       cReserved;
    CLFS_METADATA_BLOCK         rgBlocks[ANYSIZE_ARRAY];
} CLFS_CONTROL_RECORD, * PCLFS_CONTROL_RECORD;

// ============================================================
// CLFS_LOG_BLOCK_HEADER — 每个日志块（= 多个扇区）开头
// ============================================================
typedef struct _CLFS_LOG_BLOCK_HEADER {
    UCHAR          MajorVersion;
    UCHAR          MinorVersion;
    UCHAR          Usn;
    CLFS_CLIENT_ID ClientId;
    USHORT         TotalSectorCount;
    USHORT         ValidSectorCount;
    ULONG          Padding;
    ULONG          Checksum;          // 多项式 0x04C11DB7
    ULONG          Flags;
    CLFS_LSN       CurrentLsn;        // Base 块固定为 CLFS_LSN_INVALID
    CLFS_LSN       NextLsn;           // Base 块固定为 CLFS_LSN_INVALID
    ULONG          RecordOffsets[16]; // RecordOffsets[0] 是唯一使用的记录偏移
    ULONG          SignaturesOffset;  // 签名回填数组的偏移
} CLFS_LOG_BLOCK_HEADER, * PCLFS_LOG_BLOCK_HEADER;


typedef struct _CLFS_BASE_RECORD_HEADER
{
    CLFS_METADATA_RECORD_HEADER hdrBaseRecord;
    CLFS_LOG_ID cidLog;
    ULONGLONG rgClientSymTbl[CLIENT_SYMTBL_SIZE];
    ULONGLONG rgContainerSymTbl[CONTAINER_SYMTBL_SIZE];
    ULONGLONG rgSecuritySymTbl[SHARED_SECURITY_SYMTBL_SIZE];
    ULONG cNextContainer;
    CLFS_CLIENT_ID cNextClient;
    ULONG cFreeContainers;
    ULONG cActiveContainers;
    ULONG cbFreeContainers;
    ULONG cbBusyContainers;
    ULONG rgClients[MAX_CLIENTS_DEFAULT];
    ULONG rgContainers[MAX_CONTAINERS_DEFAULT];
    ULONG cbSymbolZone;
    ULONG cbSector;
    USHORT bUnused;
    CLFS_LOG_STATE eLogState;
    UCHAR cUsn;
    UCHAR cClients;
} CLFS_BASE_RECORD_HEADER, * PCLFS_BASE_RECORD_HEADER;

// ============================================================
// CLFS_CONTAINER_STATE — 容器状态（MSDN 公开枚举）
// ============================================================
#ifndef CLFS_TYPES_HAS_SDK_TYPES
// SDK 中 CLFS_CONTAINER_STATE 为 UINT32，并有 ClfsContainer* 位标志常量，
// 二者不能混用，因此仅在独立解析模式下定义本枚举。
typedef enum _CLFS_CONTAINER_STATE {
    ClfsContainerInactive = 0,
    ClfsContainerActive = 1,
    ClfsContainerActivePendingDelete = 2,
    ClfsContainerPendingArchive = 3,
    ClfsContainerPendingArchiveAndDelete = 4
} CLFS_CONTAINER_STATE, * PCLFS_CONTAINER_STATE;
#endif // CLFS_TYPES_HAS_SDK_TYPES

// ============================================================
// CLFSHASHSYM — 符号表条目
// ============================================================
typedef struct _CLFSHASHSYM {
    CLFS_NODE_ID cidNode;      // 类型必须为 CLFS_NODE_TYPE_SYMBOL
    ULONG        ulHash;       // Hollub PJW 哈希值
    ULONG        cbHash;       // 符号数据大小
    ULONGLONG    ulBelow;      // 哈希冲突时二叉搜索树下节点偏移
    ULONGLONG    ulAbove;      // 哈希冲突时二叉搜索树上节点偏移
    LONG         cbSymName;    // 符号名所在偏移
    LONG         cbOffset;     // 符号数据起始偏移
    BOOLEAN      fDeleted;     // 是否已删除
} CLFSHASHSYM, * PCLFSHASHSYM;

// ============================================================
// CLFS_CLIENT_CONTEXT — 客户端上下文
// ============================================================
typedef struct _CLFS_CLIENT_CONTEXT {
    CLFS_NODE_ID    cidNode;
    CLFS_CLIENT_ID  cidClient;
    USHORT          fAttributes;         // FILE_ATTRIBUTE 位
    ULONG           cbFlushThreshold;    // 默认 40000
    ULONG           cShadowSectors;
    ULONGLONG       cbUndoCommitment;
    LARGE_INTEGER   llCreateTime;
    LARGE_INTEGER   llAccessTime;
    LARGE_INTEGER   llWriteTime;
    CLFS_LSN        lsnOwnerPage;
    CLFS_LSN        lsnArchiveTail;
    CLFS_LSN        lsnBase;
    CLFS_LSN        lsnLast;
    CLFS_LSN        lsnRestart;
    CLFS_LSN        lsnPhysicalBase;
    CLFS_LSN        lsnUnused1;
    CLFS_LSN        lsnUnused2;
    CLFS_LOG_STATE  eState;
    union {
        HANDLE    hSecurityContext;     // 内存中：指向共享安全上下文
        ULONGLONG ullAlignment;
    };
} CLFS_CLIENT_CONTEXT, * PCLFS_CLIENT_CONTEXT;

// 前向声明
struct _CClfsContainer;
struct _CClfsBaseFile;

// ============================================================
// CLFS_CONTAINER_CONTEXT — 容器上下文
// ============================================================
typedef struct _CLFS_CONTAINER_CONTEXT {
    CLFS_NODE_ID   cidNode;
    ULONGLONG      cbContainer;      // 容器大小
    CLFS_CONTAINER_ID cidContainer;  // 容器 ID（从 0 开始）
    CLFS_CONTAINER_ID cidQueue;      // 容器队列中的 ID
    union {
        struct _CClfsContainer* pContainer; // 内存中：内核指针（磁盘上必须为 0）
        ULONGLONG               ullAlignment;
    };
    CLFS_USN             usnCurrent;
    CLFS_CONTAINER_STATE eState;     // 磁盘上通常为 ClfsContainerInactive
    ULONG                cbPrevOffset;
    ULONG                cbNextOffset;
} CLFS_CONTAINER_CONTEXT, * PCLFS_CONTAINER_CONTEXT;

// ============================================================
// CLFS_SHARED_SECURITY_CONTEXT — 共享安全上下文（通常仅存在于内存）
// ============================================================
typedef struct _CLFS_SHARED_SECURITY_CONTEXT {
    CLFS_NODE_ID cidNode;
    ULONG        cRef;           // 引用计数
    ULONG        cRefActive;     // 活跃引用计数
    ULONG        coffDescriptor; // 通常等于 offsetof(... rgbSecurityDescriptor)
    ULONG        cbDescriptor;   // 安全描述符大小
    UCHAR        rgbSecurityDescriptor[ANYSIZE_ARRAY];
} CLFS_SHARED_SECURITY_CONTEXT, * PCLFS_SHARED_SECURITY_CONTEXT;

// ============================================================
// CLFSHASHTBL — 内存中哈希表（base record 的 3 个符号表）
// ============================================================
typedef struct _CLFSHASHTBL {
    ULONGLONG* rgSymHash;    // 哈希桶数组
    LONG                     cHashElt;     // 桶数
    struct _CClfsBaseFile* pBaseFile;    // 回指 CClfsBaseFile
} CLFSHASHTBL, * PCLFSHASHTBL;

// ============================================================
// CClfsBaseFile — 内存中 Base Log File 的表示
// ============================================================
typedef struct _CClfsBaseFile {
    ULONG                   m_cRef;
    UCHAR* m_pbImage;              // Base Log File 在内存中的映像
    ULONG                   m_cbImage;              // 映像大小
    PVOID                   m_presImage;            // PERESOURCE
    USHORT                  m_cBlocks;
    struct _CLFS_METADATA_BLOCK* m_rgBlocks;        // 元数据块数组
    USHORT* m_rgcBlockReferences;   // 每块引用计数（上限 65535）
    CLFSHASHTBL             m_symtblClient;
    CLFSHASHTBL             m_symtblContainer;
    CLFSHASHTBL             m_symtblSecurity;
    ULONGLONG               m_cbContainer;
    ULONG                   m_cbRawSectorSize;
    BOOLEAN                 m_fGeneralBlockReferenced;
} CClfsBaseFile, * PCLFSBASEFILE;

// ============================================================
// CLFS_SECTOR_CHANGE — 单个扇区的变更描述
// ============================================================
typedef struct _CLFS_SECTOR_CHANGE {
    ULONG iSector;                       // 目标扇区索引
    ULONG ulUnused;
    BYTE  rgbSector[CLFS_SECTOR_SIZE];   // 新的扇区数据
} CLFS_SECTOR_CHANGE, * PCLFS_SECTOR_CHANGE;

// ============================================================
// CLFS_TRUNCATE_CLIENT_CHANGE — 某个客户端的截断变更
// ============================================================
typedef struct _CLFS_TRUNCATE_CLIENT_CHANGE {
    CLFS_CLIENT_ID cidClient;       // 被修改的客户端（流）ID
    CLFS_LSN       lsn;             // 替换块的物理 LSN
    CLFS_LSN       lsnClient;       // 客户端 LSN
    CLFS_LSN       lsnRestart;      // 截断完成后：新 restart area 的 LSN
    USHORT         cLength;         // 新块大小
    USHORT         cOldLength;      // 旧块大小
    ULONG          cSectors;        // rgSectors 中的条目数
    CLFS_SECTOR_CHANGE rgSectors[ANYSIZE_ARRAY];
} CLFS_TRUNCATE_CLIENT_CHANGE, * PCLFS_TRUNCATE_CLIENT_CHANGE;

// ============================================================
// CLFS_TRUNCATE_RECORD_HEADER — 截断记录头（临时块）
// 注：该结构不在公共符号中，字段由 ValidateTruncateRecord /
//     TruncateLogRewriteOwnerPages / TruncateLogStart 推断而来
// ============================================================
typedef struct _CLFS_TRUNCATE_RECORD_HEADER {
    CLFS_METADATA_RECORD_HEADER hdrBaseRecord;
    ULONG                       coffClientChange;  // 第一个 CLFS_TRUNCATE_CLIENT_CHANGE 的偏移
    ULONG                       coffOwnerPage;     // 第一个 owner page 的偏移
} CLFS_TRUNCATE_RECORD_HEADER, * PCLFS_TRUNCATE_RECORD_HEADER;

#endif // _CLFS_TYPES_H_