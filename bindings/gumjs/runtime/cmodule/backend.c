#include "json-glib/json-glib.h"
#include <gum/gummodulemap.h>
#include <gum/gumstalker.h>
#include <string.h>

#define RED_ZONE_SIZE 128
#define MRS(name, reg) __asm__("mrs " #name ",%0\n\t" : "=r"(reg) : :)
#define SCRATCH_REG_BOTTOM ARM64_REG_X21
#define SCRATCH_REG_TOP ARM64_REG_X28

#define SCRATCH_REG_INDEX(r) ((r)-SCRATCH_REG_BOTTOM)
#define SCRATCH_REG_OFFSET(r) (SCRATCH_REG_INDEX(r) * 8)

typedef enum _ITraceState ITraceState;
typedef struct _ITraceSession ITraceSession;
typedef struct _ITraceBuffer ITraceBuffer;

enum _ITraceState {
  ITRACE_STATE_CREATED,
  ITRACE_STATE_STARTING,
  ITRACE_STATE_STARTED,
  ITRACE_STATE_ENDED,
};

struct _ITraceSession {
  ITraceState state;
  guint64 pending_size;
  guint64 saved_regs[2];
  // shallow stack use for write_impl
  //  guint64 stack[64];
  guint64 scratch_regs[SCRATCH_REG_TOP - SCRATCH_REG_BOTTOM + 1];
  guint64 log_buf[1969];
  GumModuleMap *modules;
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
static arm64_reg pick_scratch_register(cs_regs regs_read, uint8_t num_regs_read,
                                       cs_regs regs_written,
                                       uint8_t num_regs_written);
static arm64_reg register_to_full_size_register(arm64_reg reg);
static void emit_scratch_register_restore(GumArm64Writer *cw, arm64_reg reg);

static void js_log(const char *format, ...);
// 如果所有的都正确的话，我们不需要这些。
// javascript 只支持 48bit
extern void js_on_block_exec(gpointer ctx, guint32 ctx_size, gpointer buf,
                             guint32 buf_size);
static void on_block_exec(GumCpuContext *cpu_context, gpointer user_data);
static void on_block_exec(GumCpuContext *cpu_context, gpointer user_data) {
  js_on_block_exec(cpu_context, sizeof(GumCpuContext), session.log_buf,
                   session.pending_size);
};
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
  if (insn->id == ARM64_INS_SVC) {
    // js_log("%s","encounter SVC");
    arm64_reg reg;
    *regs_read_count = 0;
    *regs_write_count = 0;
    for (reg = ARM64_REG_X0; reg <= ARM64_REG_X8; reg++) {
      regs_write[*regs_write_count] = reg;
      *regs_write_count = *regs_write_count + 1;
    }
    err = CS_ERR_OK;
  } else {
    err = cs_regs_access(ud, insn, regs_read, regs_read_count, regs_write,
                         regs_write_count);
  }

  return err;
}

void transform(GumStalkerIterator *iterator, GumStalkerOutput *output,
               gpointer user_data) {
  GumArm64Writer *cw = output->writer.arm64;
  csh capstone = gum_stalker_iterator_get_capstone(iterator);

  guint num_instructions = 0;
  GumAddress block_address = 0;
  guint log_buf_offset = 16;
  arm64_reg prev_session_reg = ARM64_REG_INVALID;

  JsonBuilder *meta = json_builder_new_immutable();
  json_builder_begin_object(meta);

  cs_insn *insn;
  while (gum_stalker_iterator_next(iterator, &insn)) {
    num_instructions++;

    gboolean is_first_in_block = num_instructions == 1;
    gboolean is_last_in_block = cs_insn_group(capstone, insn, CS_GRP_JUMP) ||
                                cs_insn_group(capstone, insn, CS_GRP_RET);
    if (session.state == ITRACE_STATE_CREATED) {
      session.state = ITRACE_STATE_STARTING;
      gum_stalker_iterator_put_callout(iterator, on_first_block_hit, NULL,
                                       NULL);
    }
    if (is_first_in_block) {

      // 只是简单跳过所exclusive 中的指令，我们只抓最一次exclusvie blcok
      // to do 增加缓存和计数器？保存所有exclusive block 信息？
      if (gum_stalker_iterator_get_memory_access(iterator) ==
          GUM_MEMORY_ACCESS_OPEN) {
        gum_stalker_iterator_put_callout(iterator, on_block_exec, NULL, NULL);
      }
      block_address = insn->address;

      json_builder_set_member_name(meta, "writes");
      json_builder_begin_array(meta);
    }

    cs_regs regs_read, regs_written;
    uint8_t num_regs_read, num_regs_written;

    regs_access(capstone, insn, regs_read, &num_regs_read, regs_written,
                &num_regs_written);
    for (uint8_t i = 0; i != num_regs_read; i++)
      regs_read[i] = register_to_full_size_register(regs_read[i]);
    for (uint8_t i = 0; i != num_regs_written; i++)
      regs_written[i] = register_to_full_size_register(regs_written[i]);

    arm64_reg session_reg =
        is_last_in_block
            ? SCRATCH_REG_TOP
            : pick_scratch_register(regs_read, num_regs_read, regs_written,
                                    num_regs_written);

    if (session_reg != prev_session_reg) {
      if (prev_session_reg != ARM64_REG_INVALID)
        gum_arm64_writer_put_mov_reg_reg(cw, session_reg, prev_session_reg);
      else
        gum_arm64_writer_put_ldr_reg_address(cw, session_reg,
                                             GUM_ADDRESS(&session));
    }

    if (prev_session_reg != ARM64_REG_INVALID &&
        session_reg != prev_session_reg)
      emit_scratch_register_restore(cw, prev_session_reg);

    if (is_first_in_block) {

      gum_arm64_writer_put_str_reg_reg_offset(
          cw, ARM64_REG_LR, session_reg,
          G_STRUCT_OFFSET(ITraceSession, log_buf) + 8);
      // add_block_write_meta (meta, insn->address - block_address, 33);
    }
    if (is_last_in_block) {
      gum_arm64_writer_put_stp_reg_reg_reg_offset(
          cw, ARM64_REG_X27, ARM64_REG_LR, session_reg,
          G_STRUCT_OFFSET(ITraceSession, saved_regs), GUM_INDEX_SIGNED_OFFSET);
      // 我们知道offset 在runtime之前，但是要保存此值 mov
      // log_buf_offset，将block信息写入指令中。
      gum_arm64_writer_put_ldr_reg_u64(cw, ARM64_REG_X27, block_address);
      gum_arm64_writer_put_str_reg_reg_offset(
          cw, ARM64_REG_X27, session_reg,
          G_STRUCT_OFFSET(ITraceSession, log_buf));
      // 我们知道offset 在runtime之前，但是要保存此值 mov
      // log_buf_offset，将block信息写入指令中。
      gum_arm64_writer_put_ldr_reg_u64(cw, ARM64_REG_X27, log_buf_offset);

      gum_arm64_writer_put_str_reg_reg_offset(
          cw, ARM64_REG_X27, session_reg,
          G_STRUCT_OFFSET(ITraceSession, pending_size));
      // gum_stalker_iterator_put_callout(iterator,);
      // if (session.write_impl == 0 ||
      //     !gum_arm64_writer_can_branch_directly_between (cw, cw->pc,
      //     session.write_impl))
      // {
      //   gconstpointer after_write_impl = cw->code + 1;
      //   panic("%s\n","backpatch write_impl");
      //   gum_arm64_writer_put_b_label (cw, after_write_impl);

      //   session.write_impl = cw->pc;
      //   emit_buffer_write_impl (cw);

      //   gum_arm64_writer_put_label (cw, after_write_impl);
      // }
      // 返回javascript 引擎，这会很慢很慢，没有buffer缓冲，但是实现简单；
      // gum_arm64_writer_put_bl_imm (cw, session.write_impl);
      // restore regs
      gum_arm64_writer_put_ldp_reg_reg_reg_offset(
          cw, ARM64_REG_X27, ARM64_REG_LR, session_reg,
          G_STRUCT_OFFSET(ITraceSession, saved_regs), GUM_INDEX_SIGNED_OFFSET);

      emit_scratch_register_restore(cw, session_reg);
    }

    gum_stalker_iterator_keep(iterator);
    if( *((guint*) (insn->bytes))==0xfd46ad21){
        gum_arm64_writer_put_brk_imm(cw, 0x14);
    }
    // last block 不需要抓寄存器
    if (is_last_in_block)
      continue;

    guint block_offset = (insn->address) - block_address;

    for (uint8_t i = 0; i != num_regs_written; i++) {
      arm64_reg reg = regs_written[i];
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
      arm64_reg reg = regs_written[i];

      guint cpu_reg_index;
      arm64_reg source_reg;
      gsize size;
      arm64_reg temp_reg = ARM64_REG_INVALID;

      if (reg == ARM64_REG_SP) {
        temp_reg = ARM64_REG_X0;

        cpu_reg_index = 1;
        source_reg = temp_reg;
        size = 8;
      } else if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        cpu_reg_index = 3 + (reg - ARM64_REG_X0);
        source_reg = reg;
        size = 8;
      } else if (reg == ARM64_REG_FP) {
        cpu_reg_index = 32;
        source_reg = reg;
        size = 8;
      } else if (reg == ARM64_REG_LR) {
        cpu_reg_index = 33;
        source_reg = reg;
        size = 8;
      } else if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        cpu_reg_index = 34 + (reg - ARM64_REG_Q0);
        source_reg = reg;
        size = 16;
      } else if (reg == ARM64_REG_NZCV) {
        temp_reg = ARM64_REG_X0;

        cpu_reg_index = 2;
        source_reg = temp_reg;
        size = 8;
      } else if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) {
        continue;
      } else {
        js_log("Unhandled register: %s", cs_reg_name(capstone, reg));
        while (TRUE)
          ;
      }

      if (temp_reg != ARM64_REG_INVALID)
        gum_arm64_writer_put_str_reg_reg_offset(
            cw, temp_reg, session_reg,
            G_STRUCT_OFFSET(ITraceSession, saved_regs));

      if (reg == ARM64_REG_SP)
        gum_arm64_writer_put_mov_reg_reg(cw, temp_reg, ARM64_REG_SP);
      else if (reg == ARM64_REG_NZCV)
        gum_arm64_writer_put_mov_reg_nzcv(cw, temp_reg);

      gsize offset = G_STRUCT_OFFSET(ITraceSession, log_buf) + log_buf_offset;
      //gsize alignment_delta = offset % size;
    //   if (alignment_delta != 0)
    //     offset += size - alignment_delta;
      if (offset > 1<<9){
        js_log("over max str offset %lu",size);
        while (1);
      }
      // TODO: Handle large offsets
      gum_arm64_writer_put_str_reg_reg_offset(cw, source_reg, session_reg,
                                              offset);
      add_block_write_meta(meta, block_offset, cpu_reg_index);
      log_buf_offset += size;

      if (temp_reg != ARM64_REG_INVALID)
        gum_arm64_writer_put_ldr_reg_reg_offset(
            cw, temp_reg, session_reg,
            G_STRUCT_OFFSET(ITraceSession, saved_regs));
    }

    prev_session_reg = session_reg;
  }

  json_builder_end_array(meta);
  json_builder_set_member_name(meta, "address");
  add_memory_address(meta, block_address);

  json_builder_set_member_name(meta, "size");
  json_builder_add_int_value(meta,
                             (insn->address + insn->size) - block_address);

  json_builder_set_member_name(meta, "compiled");
  json_builder_begin_object(meta);
  {
    guint compiled_code_size = gum_arm64_writer_offset(cw);

    json_builder_set_member_name(meta, "address");
    add_memory_address(meta, cw->pc - compiled_code_size);

    json_builder_set_member_name(meta, "size");
    json_builder_add_int_value(meta, compiled_code_size);
  }
  json_builder_end_object(meta);

  const GumModuleDetails *m =
      gum_module_map_find(session.modules, block_address);
  if (m != NULL) {
    json_builder_set_member_name(meta, "name");
    gchar *name = g_strdup_printf(
        "%s!0x%x", m->name, (guint)(block_address - m->range->base_address));
    json_builder_add_string_value(meta, name);
    g_free(name);

    json_builder_set_member_name(meta, "module");
    json_builder_begin_object(meta);

    json_builder_set_member_name(meta, "path");
    json_builder_add_string_value(meta, m->path);

    json_builder_set_member_name(meta, "base");
    add_memory_address(meta, m->range->base_address);

    json_builder_end_object(meta);
  } else {
    json_builder_set_member_name(meta, "name");
    add_memory_address(meta, block_address);
  }

  json_builder_end_object(meta);

  gchar *json = make_json(&meta);
  on_compile(json);
  g_free(json);
}



static void on_first_block_hit(GumCpuContext *cpu_context, gpointer user_data) {
  if (session.state != ITRACE_STATE_STARTING)
    return;
  session.state = ITRACE_STATE_STARTED;

  memcpy(session.scratch_regs,
         cpu_context->x + (SCRATCH_REG_BOTTOM - ARM64_REG_X0),
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

static arm64_reg pick_scratch_register(cs_regs regs_read, uint8_t num_regs_read,
                                       cs_regs regs_written,
                                       uint8_t num_regs_written) {
  arm64_reg candidate;

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

static arm64_reg register_to_full_size_register(arm64_reg reg) {
  switch (reg) {
  case ARM64_REG_SP:
  case ARM64_REG_FP:
  case ARM64_REG_LR:
  case ARM64_REG_NZCV:
  case ARM64_REG_XZR:
  case ARM64_REG_WZR:
    return reg;
  }

  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
    return reg;
  if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28)
    return ARM64_REG_X0 + (reg - ARM64_REG_W0);
  if (reg == ARM64_REG_W29)
    return ARM64_REG_FP;
  if (reg == ARM64_REG_W30)
    return ARM64_REG_LR;

  if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31)
    return reg;
  if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_V0);
  if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_D0);
  if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_S0);
  if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_H0);
  if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_B0);

  return reg;
}

static void emit_scratch_register_restore(GumArm64Writer *cw, arm64_reg reg) {
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
