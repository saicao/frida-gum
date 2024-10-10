
#ifndef __GUM_ITRANSFORMER_H__
#define __GUM_ITRANSFORMER_H__
#include "aarch64.h"
#include "capstone.h"
#include "gum/gumstalker.h"
#include "gio/gio.h"
#include "gumarm64writer.h"
#include "gumdefs.h"
#include "gummemory.h"
#include <gum/gummodulemap.h>

G_BEGIN_DECLS
#define SCRATCH_REG_BOTTOM AArch64_REG_X20
#define SCRATCH_REG_TOP AArch64_REG_X28
#define SCRATCH_REG_MAX SCRATCH_REG_TOP - SCRATCH_REG_BOTTOM + 1
#define SCRATCH_REG_INDEX(r) ((r)-SCRATCH_REG_BOTTOM)
#define SCRATCH_REG_OFFSET(r) (SCRATCH_REG_INDEX(r) * 8)
#define CS_INS_UINT32(cs_insn) *((gint32 *)(cs_insn->bytes))

#define IMSG_MSG_BLOCK_COMPILE 1
#define IMSG_BLOCK_EXEC 2
#define IMSG_MSG_CONTEXT 3
#define IMSG_MSG_PADDDING 0xdeadbeefdeadbeefULL
// #define IMSG_LOAD 4
// #define IMSG_STORE 5
#define IMSG_PRE_INSTR 6
#define IMSG_POST_INSTR 7
#define VREG_FREE -1
#define VREG_USED -2
#define VREG_TEMP -3
#define VREG_REALLOC -4
#define TRANSFROMER_REG_IDX 0
#define BUF_OFFSET_REG_IDX 1
#define REG_TRANSFROMER(tm) tm->tf_regs[TRANSFROMER_REG_IDX]
#define REG_BUF_OFFSET(tm) tm->tf_regs[BUF_OFFSET_REG_IDX]
#define DEFAULT_TRANSFORMER_REG SCRATCH_REG_TOP
#define DEFAULT_BUF_OFFSET_REG SCRATCH_REG_TOP-1
#define VREG_INVALID -1
#define REG_SPEC_PADDING 0
typedef enum _ITraceState ITraceState;

typedef struct _ImsgBlockCompile ImsgBlockCompile;
// typedef struct _Itransformer Itransformer;
typedef struct _ImsgRegSpec ImsgRegSpec;

typedef struct _ImsgBlockExec ImsgBlockExec;
typedef struct _ImsgContext ImsgContext;
typedef struct _ImsgHeader ImsgHeader;
#define GUM_TYPE_STALKER_ITRANSFORMER (gum_stalker_itransformer_get_type())

GUM_DECLARE_FINAL_TYPE(GumStalkerItransformer, gum_stalker_itransformer, GUM,
                       STALKER_ITRANSFORMER, GObject)
// struct _paddding {

// };
struct _ImsgBlockCompile {
  guint32 id;
  GumAddress address;
  guint size;
  GumAddress compiled_address;
  guint compiled_size;
  guint32 spec_size;
  // register [] RegSpec ;
};
struct _ImsgBlockExec {
  guint64 type;
  //GumAddress address;
  guint64 id;
  // register metas  
  // guint8 *meta;
};
union meta {
  guint8 x [8] ;
  guint8 v [16] ;
  //padding
  guint8 p [8] ;
};

struct _ImsgContext {
  guint64 type;
  GumArm64CpuContext cpu_context;
  guint64 fpcr;
  guint64 fpsr;
};

enum _ITraceState {
  ITRACE_STATE_CREATED,
  ITRACE_STATE_STARTING,
  ITRACE_STATE_STARTED,
  ITRACE_STATE_ENDED,
};
struct _ImsgRegSpec {
  guint64 address;
  guint32 reg_id;
};
void gum_stalker_itransformer_set_buf(GumStalkerItransformer *tm, gsize size);
void gum_stalker_itransformer_sink_channel(GumStalkerItransformer *self,
                                           GOutputStream *block_channel,
                                           GOutputStream *event_channel);
G_END_DECLS
#endif