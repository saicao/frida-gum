
#ifndef __GUM_ITRANSFORMER_H__
#define __GUM_ITRANSFORMER_H__
#include "aarch64.h"
#include "capstone.h"
#include "gum/gumstalker.h"
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
// #define IMSG_LOAD 4
// #define IMSG_STORE 5
#define IMSG_PRE_INSTR 6
#define IMSG_POST_INSTR 7
#define VREG_FREE -1
#define VREG_USED -2
#define VREG_TRANSFROM 0
#define REG_TRANSFROMER(tm) tm->vir_regs[VREG_TRANSFROM]
#define VREG_INVALID -1

typedef enum _ITraceState ITraceState;

typedef struct _ImsgBlockCompile ImsgBlockCompile;
// typedef struct _Itransformer Itransformer;
typedef struct _ImsgRegSpec ImsgRegSpec;

typedef struct _ImsgBlockExec ImsgBlockExec;
typedef struct _ImsgContext ImsgContext;
typedef struct _ImsgHeader ImsgHeader;
#define GUM_TYPE_STALKER_ITRANSFORMER \
    (gum_default_stalker_transformer_get_type ())

GUM_DECLARE_FINAL_TYPE (GumStalkerItransformer,
                        gum_stalker_itransformer,
                        GUM, STALKER_ITRANSFORMER,
                        GObject)
struct _ImsgBlockCompile {
  guint64 type;
  gboolean done;
  GumAddress address;
  guint size;
  GumAddress compiled_address;
  guint compiled_size;
  // block_data[size];
  // compiled_data[compiled_size];
  // block_spec=[{offset,register_id}]
};
struct _ImsgBlockExec {
  guint64 type;
  gpointer address;
  gsize size;
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
  guint64 type;
  guint32 offset;
  guint32 reg_id;
};
void gum_stalker_itransformer_set_buf(GumStalkerItransformer *tm,
                                         gpointer buf, gsize size);

G_END_DECLS
#endif