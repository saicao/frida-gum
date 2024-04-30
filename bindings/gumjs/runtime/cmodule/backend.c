#line 2
#include "json-glib/json-glib.h"
#include <gum/gummodulemap.h>
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>

#define RED_ZONE_SIZE 128
#define SCRATCH_REG_BOTTOM AArch64_REG_X21
#define SCRATCH_REG_TOP AArch64_REG_X28
#define ABORT()                                                                \
  int *__abort_at_here__ = NULL;                                               \
  *__abort_at_here__ = 1
#define SCRATCH_REG_INDEX(r) ((r)-SCRATCH_REG_BOTTOM)
#define SCRATCH_REG_OFFSET(r) (SCRATCH_REG_INDEX(r) * 8)
#define CS_INS_UINT32(cs_insn) *((gint32 *)(cs_insn->bytes))
typedef enum _ITraceState ITraceState;
typedef struct _ITraceSession ITraceSession;
typedef struct _ITraceBuffer ITraceBuffer;

enum _ITraceState {
  STRACE_STATE_CREATED,
  STRACE_STATE_STARTING,
  STRACE_STATE_STARTED,
  STRACE_STATE_ENDED,
};

struct _ITraceSession {
  ITraceState state;
  guint64 log_buf_size;
  guint64 saved_regs[2];
  // shallow stack use for write_impl
  //  guint64 stack[64];
  guint64 scratch_regs[SCRATCH_REG_TOP - SCRATCH_REG_BOTTOM + 1];
  guint64 log_buf[1024];
  GumModuleMap *modules;
  JsonBuilder *meta;
  aarch64_reg prev_session_reg;
  gboolean block_compile_done;
  guint64 block_size;
  guint64 block_address;
};

extern ITraceSession session;

extern void on_start(const gchar *meta_json, const GumCpuContext *cpu_context,
                     guint length);
extern void on_compile(const gchar *meta_json);
extern void on_js_log(const gchar *message);
static void on_first_block_hit(GumCpuContext *cpu_context, gpointer user_data);
static void add_cpu_system_register_meta(JsonBuilder *meta, const gchar *name,
                                         guint64 value);
static void add_cpu_register_meta(JsonBuilder *meta, const gchar *name,
                                  guint size);
static void add_block_write_meta(JsonBuilder *meta, guint block_offset,
                                 guint cpu_reg_index);
static void add_memory_address(JsonBuilder *builder, GumAddress address);
static gchar *make_json(JsonBuilder **builder);
static aarch64_reg pick_scratch_register(cs_regs regs_read,
                                         uint8_t num_regs_read,
                                         cs_regs regs_written,
                                         uint8_t num_regs_written);
static aarch64_reg register_to_full_size_register(aarch64_reg reg);
static void emit_scratch_register_restore(GumArm64Writer *cw, aarch64_reg reg);
static cs_err atomic_regs_access(const cs_insn *insn, cs_regs regs_read,
                                 uint8_t *regs_read_count, cs_regs regs_write,
                                 uint8_t *regs_write_count);

static void js_log(const char *format, ...);

static void dump_insts(csh cap, guint8 *strat, gsize size);

void dump_insts(csh cap, guint8 *strat, gsize size) {
  cs_insn *insn;
  cs_option(cap, CS_OPT_SKIPDATA, CS_OPT_ON);
  printf("======dump inst base:%p size:%lu=======\n", strat, size);
  gsize count = cs_disasm(cap, strat, size, (guint64)strat, 0, &insn);
  for (gsize i = 0; i < count; i++) {
    printf("%llx:%s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
  }
  cs_free(insn, count);
  cs_option(cap, CS_OPT_SKIPDATA, CS_OPT_OFF);
  printf("======dump inst end=======\n");
}
// 如果所有的都正确的话，我们不需要这些。
// javascript 只支持 48bit
extern void js_on_block_exec(gpointer ctx, guint32 ctx_size, gpointer buf,
                             guint32 buf_size);
static void on_block_exec(GumCpuContext *cpu_context, gpointer user_data);
static void on_block_exec(GumCpuContext *cpu_context, gpointer user_data) {
  printf("pending size %llu\n", session.log_buf_size);
  js_on_block_exec(cpu_context, sizeof(GumCpuContext), session.log_buf,
                   session.log_buf_size);
  printf("on_block_exec done\n");
};
static inline uint32_t extract32(uint32_t value, int start, int length);
void init(void) {
  session.modules = gum_module_map_new();
  // js_log("session %p",&session);
  // js_log("on_block_exec %p",&on_block_exec);
}

void finalize(void) { g_object_unref(session.modules); }

cs_err regs_access(csh ud, const cs_insn *insn, cs_regs regs_read,
                   uint8_t *regs_read_count, cs_regs regs_write,
                   uint8_t *regs_write_count) {
  cs_err err;
  if (insn->id == AArch64_INS_SVC) {
    // js_log("%s","encounter SVC");
    aarch64_reg reg;
    *regs_read_count = 0;
    *regs_write_count = 0;
    for (reg = AArch64_REG_X0; reg <= AArch64_REG_X8; reg++) {
      regs_write[*regs_write_count] = reg;
      *regs_write_count = *regs_write_count + 1;
    }
    regs_write[*regs_write_count++] =AArch64_REG_NZCV;
    return CS_ERR_OK;
  }
  // check and decode atomic
  //   err = atomic_regs_access(insn, regs_read, regs_read_count, regs_write,
  //                            regs_write_count);
  //   if (err == CS_ERR_OK) {
  //     return CS_ERR_OK;
  //   }
  err = cs_regs_access(ud, insn, regs_read, regs_read_count, regs_write,
                       regs_write_count);

  return err;
}

// transform may not give you a whole block;
void transform(GumStalkerIterator *iterator, GumStalkerOutput *output,
               gpointer user_data) {

  printf("%s\n", "transform");
  GumArm64Writer *cw = output->writer.arm64;
  csh capstone = gum_stalker_iterator_get_capstone(iterator);

  guint num_instructions = 0;

  guint log_buf_offset = session.log_buf_size;
  if (log_buf_offset >= sizeof(session.log_buf)) {
    printf("can not hold more reg info\n");
    ABORT();
  }
  GumAddress first_insn_address = 0;

  cs_insn *insn;

  // gboolean block_compile_done = false;
  // init

  while (gum_stalker_iterator_next(iterator, &insn)) {
    // only work after call next
    printf("transform %llx %s %s \n",insn->address,insn->mnemonic,insn->op_str);
    
    gboolean is_first_in_block = num_instructions == 1;
    if (session.state == STRACE_STATE_CREATED) {
      session.state = STRACE_STATE_STARTING;
      gum_stalker_iterator_put_callout(iterator, on_first_block_hit, NULL,
                                       NULL);
      session.prev_session_reg = AArch64_REG_INVALID;
      session.block_compile_done = true;
    }

    num_instructions++;
    if (num_instructions == 1) {
      first_insn_address = insn->address;
      if (session.block_compile_done) {
        // hit new block

        if (gum_stalker_iterator_get_memory_access(iterator) ==
            GUM_MEMORY_ACCESS_OPEN) {
          gum_stalker_iterator_put_callout(iterator, on_block_exec, NULL, NULL);
          // gum_arm64_writer_put_brk_imm(cw,0x1234);
        } else {
          printf("memory close \n");
        }
        log_buf_offset = 16;
        session.meta = json_builder_new_immutable();
        json_builder_begin_object(session.meta);

        printf("start build writes header\n");
        json_builder_set_member_name(session.meta, "writes");
        json_builder_begin_array(session.meta);
        //start new blcok;
        GumAddress block_address = insn->address;
        session.block_address = block_address;
        session.block_size=0;
      }
    }
    session.block_compile_done = cs_insn_group(capstone, insn, CS_GRP_JUMP) ||
                                 cs_insn_group(capstone, insn, CS_GRP_RET)||
                                 cs_insn_group(capstone, insn, CS_GRP_CALL);
    // commit last reg readings
    // 只是简单跳过所exclusive 中的指令，我们只抓最一次exclusvie blcok
    // to do 增加缓存和计数器？保存所有exclusive block 信息？
    cs_regs regs_read, regs_written;
    uint8_t num_regs_read, num_regs_written;

    regs_access(capstone, insn, regs_read, &num_regs_read, regs_written,
                &num_regs_written);
    for (uint8_t i = 0; i != num_regs_read; i++) {
      regs_read[i] = register_to_full_size_register(regs_read[i]);
    }

    for (uint8_t i = 0; i != num_regs_written; i++) {
      regs_written[i] = register_to_full_size_register(regs_written[i]);
    }

    aarch64_reg session_reg =
        session.block_compile_done
            ? SCRATCH_REG_TOP
            : pick_scratch_register(regs_read, num_regs_read, regs_written,
                                    num_regs_written);

    if (session_reg != session.prev_session_reg) {
      if (session.prev_session_reg != AArch64_REG_INVALID) {
        gum_arm64_writer_put_mov_reg_reg(cw, session_reg,
                                         session.prev_session_reg);
        emit_scratch_register_restore(cw, session.prev_session_reg);
      } else {
        gum_arm64_writer_put_ldr_reg_address(cw, session_reg,
                                             GUM_ADDRESS(&session));
      }
    }
    // always save lr
    if (is_first_in_block) {
      gum_arm64_writer_put_str_reg_reg_offset(
          cw, AArch64_REG_LR, session_reg,
          G_STRUCT_OFFSET(ITraceSession, log_buf) + 8);
    }

    if (session.block_compile_done) {
      gum_arm64_writer_put_stp_reg_reg_reg_offset(
          cw, AArch64_REG_X27, AArch64_REG_LR, session_reg,
          G_STRUCT_OFFSET(ITraceSession, saved_regs), GUM_INDEX_SIGNED_OFFSET);
      // 我们知道offset 在runtime之前，但是要保存此值 mov
      // log_buf_offset，将block信息写入指令中。
      gum_arm64_writer_put_ldr_reg_u64(cw, AArch64_REG_X27,
                                       session.block_address);
      gum_arm64_writer_put_str_reg_reg_offset(
          cw, AArch64_REG_X27, session_reg,
          G_STRUCT_OFFSET(ITraceSession, log_buf));
      // 我们知道offset 在runtime之前，但是要保存此值 mov
      // log_buf_offset，将block信息写入指令中。
      gum_arm64_writer_put_ldr_reg_u64(cw, AArch64_REG_X27, log_buf_offset);
      gum_arm64_writer_put_str_reg_reg_offset(
          cw, AArch64_REG_X27, session_reg,
          G_STRUCT_OFFSET(ITraceSession, log_buf_size));
      gum_arm64_writer_put_ldp_reg_reg_reg_offset(
          cw, AArch64_REG_X27, AArch64_REG_LR, session_reg,
          G_STRUCT_OFFSET(ITraceSession, saved_regs), GUM_INDEX_SIGNED_OFFSET);

      emit_scratch_register_restore(cw, session_reg);
      session.prev_session_reg = AArch64_REG_INVALID;
    }
    guint block_offset = (insn->address) - session.block_address;
    
    session.block_size += insn->size;
    //when is insn get freed?
    gum_stalker_iterator_keep(iterator);
  
    // last block 不需要抓寄存器
    if (session.block_compile_done)
      continue;
    //save scratch_reg
    for (uint8_t i = 0; i != num_regs_written; i++) {
      aarch64_reg reg = regs_written[i];
      gboolean is_scratch_reg =
          reg >= SCRATCH_REG_BOTTOM && reg <= SCRATCH_REG_TOP;
      if (is_scratch_reg) {
        gum_arm64_writer_put_str_reg_reg_offset(
            cw, reg, session_reg,
            G_STRUCT_OFFSET(ITraceSession, scratch_regs) +
                SCRATCH_REG_OFFSET(reg));
      }
    }
    for (uint8_t i = 0; i != num_regs_written; i++) {
      aarch64_reg reg = regs_written[i];

      guint cpu_reg_index;
      aarch64_reg source_reg;
      gsize size;
      aarch64_reg temp_reg = AArch64_REG_INVALID;

      if (reg == AArch64_REG_SP) {
        temp_reg = AArch64_REG_X0;

        cpu_reg_index = 1;
        source_reg = temp_reg;
        size = 8;
      } else if (reg >= AArch64_REG_X0 && reg <= AArch64_REG_X28) {
        cpu_reg_index = 3 + (reg - AArch64_REG_X0);
        source_reg = reg;
        size = 8;
      } else if (reg == AArch64_REG_FP) {
        cpu_reg_index = 32;
        source_reg = reg;
        size = 8;
      } else if (reg == AArch64_REG_LR) {
        cpu_reg_index = 33;
        source_reg = reg;
        size = 8;
      } else if (reg >= AArch64_REG_Q0 && reg <= AArch64_REG_Q31) {
        cpu_reg_index = 34 + (reg - AArch64_REG_Q0);
        source_reg = reg;
        size = 16;
      } else if (reg == AArch64_REG_NZCV) {
        temp_reg = AArch64_REG_X0;

        cpu_reg_index = 2;
        source_reg = temp_reg;
        size = 8;
      } else if (reg == AArch64_REG_XZR || reg == AArch64_REG_WZR) {
        continue;
      } else {
        js_log("Unhandled register: %s", cs_reg_name(capstone, reg));
        while (TRUE)
          ;
      }

      if (temp_reg != AArch64_REG_INVALID)
        gum_arm64_writer_put_str_reg_reg_offset(
            cw, temp_reg, session_reg,
            G_STRUCT_OFFSET(ITraceSession, saved_regs));

      if (reg == AArch64_REG_SP)
        gum_arm64_writer_put_mov_reg_reg(cw, temp_reg, AArch64_REG_SP);
      else if (reg == AArch64_REG_NZCV)
        gum_arm64_writer_put_mov_reg_nzcv(cw, temp_reg);

      gsize offset = G_STRUCT_OFFSET(ITraceSession, log_buf) + log_buf_offset;
      gsize alignment_delta = offset % size;
      guint paddings = 0;
      if (alignment_delta != 0) {
        paddings = size - alignment_delta;
        offset += paddings;
      }

      if (offset > 1 << 12) {
        js_log("over max str offset %lu", size);
        while (1)
          ;
      }

      // TODO: Handle large offsets
      gum_arm64_writer_put_str_reg_reg_offset(cw, source_reg, session_reg,
                                              offset);

      add_block_write_meta(session.meta, block_offset, cpu_reg_index);
      log_buf_offset += paddings + size;

      if (temp_reg != AArch64_REG_INVALID)
        gum_arm64_writer_put_ldr_reg_reg_offset(
            cw, temp_reg, session_reg,
            G_STRUCT_OFFSET(ITraceSession, saved_regs));
    }
    

    session.prev_session_reg = session_reg;
  }

  
  printf("%s %d\n", "gum_stalker_iterator_done ",session.block_compile_done);
  
  
  if (session.block_compile_done) {
    printf(" block_compile_done\n");
    // end build write
    json_builder_end_array(session.meta);
    printf("start build block header\n");
    json_builder_set_member_name(session.meta, "address");
    add_memory_address(session.meta, session.block_address);

    json_builder_set_member_name(session.meta, "size");

    json_builder_add_int_value(session.meta, session.block_size);
    printf("start build module header\n");
    const GumModuleDetails *m =
        gum_module_map_find(session.modules, session.block_address);
    if (m != NULL) {
      json_builder_set_member_name(session.meta, "name");
      gchar *name = g_strdup_printf(
          "%s!0x%x", m->name,
          (guint)(session.block_address - m->range->base_address));
      json_builder_add_string_value(session.meta, name);
      g_free(name);

      json_builder_set_member_name(session.meta, "module");
      json_builder_begin_object(session.meta);

      json_builder_set_member_name(session.meta, "path");
      json_builder_add_string_value(session.meta, m->path);

      json_builder_set_member_name(session.meta, "base");
      add_memory_address(session.meta, m->range->base_address);

      json_builder_end_object(session.meta);
    } else {
      json_builder_set_member_name(session.meta, "name");
      add_memory_address(session.meta, session.block_address);
    }
    json_builder_end_object(session.meta);
    gchar *json = make_json(&session.meta);
    printf("%s\n", json);
    guint64 compiled_code_size = gum_arm64_writer_offset(cw);
    guint64 compile_start = (guint64)cw->base;
    dump_insts(capstone, (void *)compile_start, compiled_code_size);
    on_compile(json);
    g_free(json);
  }

  if (num_instructions == 0) {
    printf("transform an empty block\n");
    ABORT();
  }
  printf("%s\n", "transform done");
}

static void on_first_block_hit(GumCpuContext *cpu_context, gpointer user_data) {
  if (session.state != STRACE_STATE_STARTING)
    return;

  session.state = STRACE_STATE_STARTED;
  memcpy(session.scratch_regs,
         cpu_context->x + (SCRATCH_REG_BOTTOM - AArch64_REG_X0),
         sizeof(session.scratch_regs));

  JsonBuilder *meta = json_builder_new_immutable();
  json_builder_begin_object(meta);
  json_builder_set_member_name(meta, "general");
  json_builder_begin_array(meta);
  add_cpu_register_meta(meta, "pc", sizeof(cpu_context->pc));
  add_cpu_register_meta(meta, "sp", sizeof(cpu_context->sp));
  add_cpu_register_meta(meta, "nzcv", sizeof(cpu_context->nzcv));
  for (guint i = 0; i != G_N_ELEMENTS(cpu_context->x); i++) {
    gchar *name = g_strdup_printf("x%u", i);
    add_cpu_register_meta(meta, name, sizeof(cpu_context->x[0]));
    g_free(name);
  }
  add_cpu_register_meta(meta, "fp", sizeof(cpu_context->fp));
  add_cpu_register_meta(meta, "lr", sizeof(cpu_context->lr));
  for (guint i = 0; i != G_N_ELEMENTS(cpu_context->v); i++) {
    gchar *name = g_strdup_printf("v%u", i);
    add_cpu_register_meta(meta, name, sizeof(cpu_context->v[0]));
    g_free(name);
  }
  json_builder_end_array(meta);
  json_builder_set_member_name(meta, "system");
  json_builder_begin_array(meta);
  Arm64SystemRegs regs;
  gum_stalker_get_system_regs(&regs);
  add_cpu_system_register_meta(meta, "fpcr", regs.fpcr);
  // MRS(fpsr, reg_value);
  add_cpu_system_register_meta(meta, "fpsr", regs.fpsr);
  json_builder_end_array(meta);
  json_builder_end_object(meta);
  gchar *json = make_json(&meta);
  on_start(json, cpu_context, sizeof(GumCpuContext));
  printf("send meta %s\n", json);
  g_free(json);
}
static void add_cpu_system_register_meta(JsonBuilder *meta, const gchar *name,
                                         guint64 value) {
  json_builder_begin_object(meta);

  json_builder_set_member_name(meta, "name");
  json_builder_add_string_value(meta, name);

  json_builder_set_member_name(meta, "value");
  char *json_value = g_strdup_printf("%llx", value);
  json_builder_add_string_value(meta, json_value);
  json_builder_end_object(meta);
  g_free(json_value);
}

static void add_cpu_register_meta(JsonBuilder *meta, const gchar *name,
                                  guint size) {
  json_builder_begin_object(meta);

  json_builder_set_member_name(meta, "name");
  json_builder_add_string_value(meta, name);

  json_builder_set_member_name(meta, "size");
  json_builder_add_int_value(meta, size);

  json_builder_end_object(meta);
}

static void add_block_write_meta(JsonBuilder *meta, guint block_offset,
                                 guint cpu_ctx_offset) {
  printf("add_block_write_meta %d %d\n", block_offset, cpu_ctx_offset);
  json_builder_begin_array(meta);
  json_builder_add_int_value(meta, block_offset);
  json_builder_add_int_value(meta, cpu_ctx_offset);
  json_builder_end_array(meta);
}

static void add_memory_address(JsonBuilder *builder, GumAddress address) {
  gchar *str = g_strdup_printf("0x%" G_GINT64_MODIFIER "x", address);
  json_builder_add_string_value(builder, str);
  g_free(str);
}

static gchar *make_json(JsonBuilder **builder) {
  JsonBuilder *b = *builder;
  *builder = NULL;

  JsonNode *node = json_builder_get_root(b);
  gchar *json = json_to_string(node, FALSE);
  json_node_unref(node);

  g_object_unref(b);

  return json;
}

static aarch64_reg pick_scratch_register(cs_regs regs_read,
                                         uint8_t num_regs_read,
                                         cs_regs regs_written,
                                         uint8_t num_regs_written) {
  aarch64_reg candidate;

  for (candidate = SCRATCH_REG_TOP; candidate != SCRATCH_REG_BOTTOM - 1;
       candidate--) {
    gboolean available = TRUE;

    for (uint8_t i = 0; i != num_regs_read; i++) {
      if (regs_read[i] == candidate) {
        available = FALSE;
        break;
      }
    }
    if (!available)
      continue;

    for (uint8_t i = 0; i != num_regs_written; i++) {
      if (regs_written[i] == candidate) {
        available = FALSE;
        break;
      }
    }
    if (!available)
      continue;

    break;
  }

  return candidate;
}

static aarch64_reg register_to_full_size_register(aarch64_reg reg) {

  switch (reg) {
  case AArch64_REG_SP:
  case AArch64_REG_FP:
  case AArch64_REG_LR:
  case AArch64_REG_NZCV:
  case AArch64_REG_XZR:
  case AArch64_REG_WZR:
    return reg;
  }

  if (reg >= AArch64_REG_X0 && reg <= AArch64_REG_X28)
    return reg;
  if (reg >= AArch64_REG_W0 && reg <= AArch64_REG_W28)
    return AArch64_REG_X0 + (reg - AArch64_REG_W0);
  if (reg == AArch64_REG_W29)
    return AArch64_REG_FP;
  if (reg == AArch64_REG_W30)
    return AArch64_REG_LR;

  if (reg >= AArch64_REG_Q0 && reg <= AArch64_REG_Q31)
    return reg;
  //   if (reg >= AArch64_REG_V0 && reg <= AArch64_REG_V31)
  //     return AArch64_REG_Q0 + (reg - AArch64_REG_V0);
  if (reg >= AArch64_REG_D0 && reg <= AArch64_REG_D31)
    return AArch64_REG_Q0 + (reg - AArch64_REG_D0);
  if (reg >= AArch64_REG_S0 && reg <= AArch64_REG_S31)
    return AArch64_REG_Q0 + (reg - AArch64_REG_S0);
  if (reg >= AArch64_REG_H0 && reg <= AArch64_REG_H31)
    return AArch64_REG_Q0 + (reg - AArch64_REG_H0);
  if (reg >= AArch64_REG_B0 && reg <= AArch64_REG_B31)
    return AArch64_REG_Q0 + (reg - AArch64_REG_B0);

  return reg;
}

static void emit_scratch_register_restore(GumArm64Writer *cw, aarch64_reg reg) {
  gum_arm64_writer_put_ldr_reg_reg_offset(
      cw, reg, reg,
      G_STRUCT_OFFSET(ITraceSession, scratch_regs) + SCRATCH_REG_OFFSET(reg));
}

static void js_log(const char *format, ...) {
  va_list args;
  va_start(args, format);
  gchar *message = g_strdup_vprintf(format, args);
  va_end(args);

  on_js_log(message);

  g_free(message);
}
/**
 * extract32:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 32 bit input @value the bit field specified by the
 * @start and @length parameters, and return it. The bit field must
 * lie entirely within the 32 bit word. It is valid to request that
 * all 32 bits are returned (ie @length 32 and @start 0).
 *
 * Returns: the value of the bit field extracted from the input value.
 */
static inline uint32_t extract32(uint32_t value, int start, int length) {
  return (value >> start) & (~0U >> (32 - length));
}

static inline int operand_to_cs_reg_id(guint operand, gboolean v) {
  guint32 ret = AArch64_REG_INVALID;
  guint32 reg_base = v ? AArch64_REG_Q0 : AArch64_REG_X0;
  ret = reg_base + operand;
  return ret;
}

/* Atomic memory operations
 *
 *  31  30      27  26    24    22  21   16   15    12    10    5     0
 * +------+-------+---+-----+-----+---+----+----+-----+-----+----+-----+
 * | size | 1 1 1 | V | 0 0 | A R | 1 | Rs | o3 | opc | 0 0 | Rn |  Rt |
 * +------+-------+---+-----+-----+--------+----+-----+-----+----+-----+
 *
 * Rt: the result register
 * Rn: base address or SP
 * Rs: the source register for the operation
 * V: vector flag (always 0 as of v8.3)
 * A: acquire flag
 * R: release flag
 */
static cs_err atomic_regs_access(const cs_insn *cs_insn, cs_regs regs_read,
                                 uint8_t *regs_read_count, cs_regs regs_write,
                                 uint8_t *regs_write_count) {

  guint32 insn = CS_INS_UINT32(cs_insn);

  // is lse_atmoic_read
  if (!(extract32(insn, 27, 3) == 0x7 && extract32(insn, 24, 2) == 0x0 &&
        extract32(insn, 21, 1) == 0x1 && extract32(insn, 10, 2) == 0)) {
    return CS_ERR_DETAIL;
  }

  int rt = extract32(insn, 0, 5);
  int rs = extract32(insn, 16, 5);
  int rn = extract32(insn, 5, 5);
  int o3_opc = extract32(insn, 12, 4);
  bool r = extract32(insn, 22, 1);
  bool a = extract32(insn, 23, 1);
  bool v = extract32(insn, 26, 1);
  switch (o3_opc) {
  case 000: /* LDADD */
  case 001: /* LDCLR */
  case 002: /* LDEOR */
  case 003: /* LDSET */
  case 004: /* LDSMAX */
  case 005: /* LDSMIN */
  case 006: /* LDUMAX */
  case 007: /* LDUMIN */
  case 010: /* SWP */
    regs_read[0] = operand_to_cs_reg_id(rs, v);
    regs_read[1] = operand_to_cs_reg_id(rn, v);
    regs_write[0] = operand_to_cs_reg_id(rt, v);
    *regs_read_count = 2;
    *regs_write_count = 1;
    break;
  case 014: /* LDAPR, LDAPRH, LDAPRB */
    // ok for capstone
    //  regs_read[0] = operand_to_cs_reg_id(rn, v);

    // regs_write[1] = operand_to_cs_reg_id(rt, v);
    // *regs_read_count = 1;
    // *regs_write_count = 1;
    break;
  default:
    return CS_ERR_DETAIL;
  }
  return CS_ERR_OK;
}
