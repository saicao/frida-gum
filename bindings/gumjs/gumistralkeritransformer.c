
#include "aarch64.h"
#include "capstone.h"
#include "gumarm64writer.h"
#include "gumdefs.h"
#include "gumexceptor.h"
#include "gumisralkeritransformer.h"
#include "gummemory.h"
#include "gumstalker.h"
#include <stdbool.h>
#include <sys/ucred.h>
// #undef g_debug
// #define g_debug(fmt, ...) 
const guint64 GURAD_MAGIC = 0xdeadbeeeeeeeeeef;
static void gum_stalker_itransformer_iface_init(gpointer g_iface,
                                                gpointer iface_data);
static void
gum_stalker_itransformer_transform_block(GumStalkerItransformer *transformer,
                                         GumStalkerIterator *iterator,
                                         GumStalkerOutput *output);
struct _GumStalkerItransformer {
  GObject parent;
  guint64 saved_regs[SCRATCH_REG_MAX];
  // reg [i]=who use the register i
  int reg_used[SCRATCH_REG_MAX];
  aarch64_reg tf_regs[SCRATCH_REG_MAX];
  gpointer buf;
  gpointer buf_offset;
  guint32 reg_val_offset;
  gsize buf_size;
  guint64 dump_counter;
  ITraceState state;
  GumStalkerIterator *iterator;
  GumArm64Writer *cw;
  ImsgBlockCompile current_block;
  gboolean block_done;
  GArray *block_specs;
  
  GumModuleMap *modules;
  gboolean dump_context;
  guint64 context_interval;
  csh capstone;
  GumExceptor *exceptor;
  gpointer guard_page_addr;
  GOutputStream *block_channel;
  GOutputStream *event_channel;
};
G_DEFINE_TYPE_EXTENDED(
    GumStalkerItransformer, gum_stalker_itransformer, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_STALKER_TRANSFORMER,
                          gum_stalker_itransformer_iface_init))
static void dump_imsg_context(const ImsgContext *context);
static void dump_gum_cpu_context(const GumArm64CpuContext *cpu_context);
static inline uint32_t extract32(uint32_t value, int start, int length) {
  return (value >> start) & (~0U >> (32 - length));
}

static void
gum_stalker_itransformer_class_init(GumStalkerItransformerClass *klass) {
  // GObjectClass * object_class = G_OBJECT_CLASS (klass);
  return;
}

static void gum_stalker_itransformer_init(GumStalkerItransformer *self) {
  g_debug("gum_stalker_itransformer_init");
  self->buf = NULL;
  self->buf_offset = NULL;
  self->buf_size = 0;
  self->dump_counter = 0;
  self->block_done = true;
  self->state = ITRACE_STATE_CREATED;
  self->iterator = NULL;
  self->cw = NULL;
  memset(&self->current_block, 0, sizeof(ImsgBlockCompile));
  memset(self->saved_regs, 0, sizeof(self->saved_regs));
  for (int i = 0; i != SCRATCH_REG_MAX; i++) {
    self->reg_used[i] = VREG_FREE;
    self->tf_regs[i] = AArch64_REG_INVALID;
  }
  self->block_specs = g_array_new(FALSE, FALSE, sizeof(ImsgRegSpec));
  self->reg_val_offset = 0;
  self->modules = NULL;
  self->dump_context = TRUE;
  self->context_interval = 1;
  self->exceptor = gum_exceptor_obtain();
}
static void dump_exception_details(const GumExceptionDetails *details) {
  gchar *str_detail = gum_exception_details_to_string(details);
  g_warning("unhandled excpetion at address %p %s", details->address,
            str_detail);
  g_free(str_detail);
}
static gboolean gum_try_do_sink(GumExceptionDetails *details,
                                GumStalkerItransformer *self) {
  // g_debug("gum_try_do_sink at %p %d", details->address, details->type);
  // g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG | G_LOG_FLAG_RECURSION,
  //       "gum_try_do_sink at %p %d");

  if (details->type != GUM_EXCEPTION_ACCESS_VIOLATION) {
    goto end;
  }

  gsize page_size = gum_query_page_size();
  gpointer address = GUM_ALIGN_SIZE(details->memory.address, page_size);
  gsize offset = 0;
  if (address == self->guard_page_addr) {
    offset = address - self->buf;
  }
  if (address == self->guard_page_addr - page_size) {
    offset = address - self->buf;
  }

  if (offset) {
    GumCpuContext *cpu_context = &details->context;
    const guint32 *insn;

    insn = (guint32 *)cpu_context->pc;

    // g_debug("gum_try_do_sink at %p %p", details->address, *insn);
    int reg_idx =
        extract32(*insn, 5, 5); // 0x1F is a mask for the lower 5 bits (0b11111)
    cpu_context->x[reg_idx] = (guint64)self->buf;
    g_debug("gum_try_do_sink at %p %p reg %d", details->address,
            details->memory.address, reg_idx);
    GError *error = NULL;
    g_debug("write to channel %p with buf %p,%lu", self->event_channel,
            self->buf, offset);
    g_output_stream_write(self->event_channel, self->buf, offset, NULL, &error);
    g_output_stream_flush(self->block_channel, NULL, &error);
    if (error) {
      // g_printerr("failed to write to channel %s", error->message);
      g_error("failed to write to channel %s", error->message);
    }
    return TRUE;
  }
end:
  dump_exception_details(details);
  return FALSE;
}
void gum_stalker_itransformer_set_buf(GumStalkerItransformer *self,
                                      gsize size) {
  gsize page_size = gum_query_page_size();
  size = GUM_ALIGN_SIZE(size, page_size);
  gsize n_page = size / page_size;
  void *buf = gum_alloc_n_pages(n_page + 1, GUM_PAGE_RW);
  if (buf == NULL) {
    g_error("failed to allocate memory");
    g_abort();
  }
  guint64 *gurad_page = buf + n_page * page_size;
  self->buf = buf;
  self->buf_offset = buf;
  self->buf_size = size;
  gum_mprotect(gurad_page, page_size, GUM_PAGE_READ);
  self->guard_page_addr = (GumAddress)gurad_page;
  g_debug("set buffer %p %p", buf, gurad_page);
  gum_exceptor_add(self->exceptor, gum_try_do_sink, self);
};
void gum_stalker_itransformer_sink_channel(GumStalkerItransformer *self,
                                           GOutputStream *block_channel,
                                           GOutputStream *event_channel) {
  self->block_channel = block_channel;
  self->event_channel = event_channel;
  g_object_ref(block_channel);
  g_object_ref(event_channel);
};

static void gum_stalker_itransformer_dispose(GumStalkerItransformer *self) {
  g_clear_object(&self->exceptor);
  g_clear_object(&self->block_channel);
  g_clear_object(&self->event_channel);
};
static void gum_stalker_itransformer_finalize(GumStalkerItransformer *self) {
  g_array_free(self->block_specs, TRUE);
};
static void gum_stalker_itransformer_iface_init(gpointer g_iface,
                                                gpointer iface_data) {
  g_debug("gum_stalker_itransformer_iface_init");
  GumStalkerTransformerInterface *iface = g_iface;

  iface->transform_block = gum_stalker_itransformer_transform_block;
}
static inline gboolean is_scartch_register(aarch64_reg reg) {
  return reg >= SCRATCH_REG_BOTTOM && reg <= SCRATCH_REG_TOP;
};
static void gum_stalker_itransformer_starting(GumCpuContext *cpu_context,
                                              GumStalkerItransformer *tm);
static aarch64_reg register_to_full_size_register(aarch64_reg reg);

static void reslove_regs(GumStalkerItransformer *tm, cs_regs regs_read,
                         uint8_t num_regs_read, cs_regs regs_written,
                         uint8_t num_regs_written);
static void on_block_ctx(GumCpuContext *cpu_context,
                         GumStalkerItransformer *tm);
static gboolean itransformer_try_write_context(GumStalkerItransformer *tm,
                                               GumStalkerIterator *iterator,
                                               GumArm64Writer *cw);
void save_register(GumArm64Writer *cw, aarch64_reg tm_reg, aarch64_reg reg) {
  gum_arm64_writer_put_str_reg_reg_offset(
      cw, reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, saved_regs) +
          SCRATCH_REG_OFFSET(reg));
};
static void gum_stalker_itransformer_starting(GumCpuContext *cpu_context,
                                              GumStalkerItransformer *tm) {
  if (tm->state != ITRACE_STATE_STARTING) {
    return;
  };
  memcpy(tm->saved_regs, cpu_context->x + (SCRATCH_REG_BOTTOM - AArch64_REG_X0),
         sizeof(tm->saved_regs));
  tm->current_block.id=1;
  on_block_ctx(cpu_context, tm);
  tm->state = ITRACE_STATE_STARTED;
};

aarch64_reg allocate_tmp_reg(GumStalkerItransformer *tm) {
  // int reg_idx=-1;
  for (int i = SCRATCH_REG_MAX; i > 0; --i) {
    if (tm->reg_used[i] == VREG_FREE) {
      tm->reg_used[i] = VREG_USED;
      aarch64_reg reg = SCRATCH_REG_BOTTOM + i;
      save_register(tm->cw, REG_TRANSFROMER(tm), reg);
      g_debug("allocate tmp register %s", cs_reg_name(tm->capstone, reg));
      return reg;
    }
  };
  return AArch64_REG_INVALID;
}
aarch64_reg allocate_tf_reg(GumStalkerItransformer *tm, int reg_idx) {
  if (tm->tf_regs[reg_idx] != AArch64_REG_INVALID) {
    return AArch64_REG_INVALID;
  }
  aarch64_reg reg = allocate_tmp_reg(tm);
  if (reg == AArch64_REG_INVALID) {
    return AArch64_REG_INVALID;
  }
  tm->reg_used[SCRATCH_REG_INDEX(reg)] = reg_idx;
  tm->tf_regs[reg_idx] = reg;
  return reg;
};

static void aquire_tf_base_reg(GumStalkerItransformer *tm) {
  if (REG_TRANSFROMER(tm) != AArch64_REG_INVALID) {
    g_warning("transformer base register is already aquired");
  }
  REG_TRANSFROMER(tm) = DEFAULT_TRANSFORMER_REG;
  tm->reg_used[SCRATCH_REG_INDEX(DEFAULT_TRANSFORMER_REG)] =
      TRANSFROMER_REG_IDX;
  gum_arm64_writer_put_ldr_reg_address(tm->cw, DEFAULT_TRANSFORMER_REG,
                                       GUM_ADDRESS(tm));
  // offset
  aarch64_reg reg = allocate_tf_reg(tm, BUF_OFFSET_REG_IDX);
  if (reg == AArch64_REG_INVALID) {
    g_warning("failed to allocate offset register");
  }
  g_debug("aquire transformer tm %s buf_offset %s",
          cs_reg_name(tm->capstone, REG_TRANSFROMER(tm)),
          cs_reg_name(tm->capstone, REG_BUF_OFFSET(tm)));
}

static void free_scartch_register(GumStalkerItransformer *self,
                                  aarch64_reg tm_reg, aarch64_reg reg) {
  int idx = SCRATCH_REG_INDEX(reg);
  self->reg_used[idx] = VREG_FREE;
  gum_arm64_writer_put_ldr_reg_reg_offset(
      self->cw, reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, saved_regs) +
          SCRATCH_REG_OFFSET(reg));
  g_debug("free register %s", cs_reg_name(self->capstone, reg));
};
static void free_tmp_reg(GumStalkerItransformer *self, aarch64_reg reg) {
  aarch64_reg tm_reg = REG_TRANSFROMER(self);
  free_scartch_register(self, tm_reg, reg);
}
// void free_virual_register(GumStalkerItransformer *tm, vir_reg tm_vreg,
//                           vir_reg vreg) {
//   aarch64_reg reg = tm->vir_regs[vreg];
//   aarch64_reg tm_reg = tm->vir_regs[tm_reg];
//   free_scartch_register(tm, tm_reg, reg);
// };
static gpointer gum_istraker_make_shmem(size_t size) {
  guint page_size = gum_query_page_size();
  guint page_num = GUM_ALIGN_SIZE(size, page_size) / page_size;
  return gum_alloc_n_pages(page_num, GUM_PAGE_RW);
};

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
    regs_write[*regs_write_count] = AArch64_REG_NZCV;
    *regs_write_count = *regs_write_count + 1;

  } else {
    err = cs_regs_access(ud, insn, regs_read, regs_read_count, regs_write,
                         regs_write_count);
  }

  if (err) {
    return err;
  }
  for (uint8_t i = 0; i != *regs_read_count; i++) {
    regs_read[i] = register_to_full_size_register(regs_read[i]);
  }

  for (uint8_t i = 0; i != *regs_write_count; i++) {
    regs_write[i] = register_to_full_size_register(regs_write[i]);
  }
  return CS_ERR_OK;
}
static inline void align_up_register(GumArm64Writer *writer, aarch64_reg reg,
                                     size_t alignment) {
  // Calculate imms and immr based on the alignment value n
  // size_t n_bits=__builtin_clz(alignment);
  gum_arm64_writer_put_add_reg_reg_imm(writer, reg, reg, alignment - 1);
  // guint8 imms = 0; // No rotation (rotate right amount is 0)
  // Generate the UBFM instruction to align the src_reg to n bytes
  gum_arm64_writer_put_and_reg_reg_imm(writer, reg, reg, ~(alignment - 1));
}
size_t align_up(size_t x, size_t alignment) {
  // Make sure alignment is a power of two
  return (x + alignment - 1) & ~(alignment - 1);
}
static void istalker_save_regs(GumStalkerItransformer *self, cs_regs regs,
                               uint8_t num_regs, aarch64_reg offest_reg,
                               GumAddress address) {

  GumArm64Writer *cw = self->cw;
  for (uint8_t i = 0; i != num_regs; i++) {
    aarch64_reg reg = regs[i];
    guint cpu_reg_index = 0;
    aarch64_reg source_reg;
    guint size;
    aarch64_reg temp_reg = AArch64_REG_INVALID;

    if (reg == AArch64_REG_SP) {
      temp_reg = allocate_tmp_reg(self);
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
      temp_reg = allocate_tmp_reg(self);

      cpu_reg_index = 2;
      source_reg = temp_reg;
      size = 8;
    } else if (reg == AArch64_REG_XZR || reg == AArch64_REG_WZR) {
      continue;
    } else {

      g_abort();
    }

    if (reg == AArch64_REG_SP)
      gum_arm64_writer_put_mov_reg_reg(cw, temp_reg, AArch64_REG_SP);
    else if (reg == AArch64_REG_NZCV)
      gum_arm64_writer_put_mov_reg_nzcv(cw, temp_reg);
    // gum_arm64_writer_put_ldr_reg_reg_offset(cw,istaker_reg, gsize
    ImsgRegSpec spec = {address, cpu_reg_index};

    g_array_append_val(self->block_specs, spec);
    g_debug("save register %s", cs_reg_name(self->capstone, reg));
    if (self->reg_val_offset % size != 0) {
      g_debug("reg_val_offset %u,size %u", self->reg_val_offset, size);
      align_up_register(cw, offest_reg, size);
      self->reg_val_offset = align_up(self->reg_val_offset, size);
    }
    gum_arm64_writer_put_str_reg_reg_offset_mode(cw, source_reg, offest_reg,
                                                 size, GUM_INDEX_POST_ADJUST);
    if (temp_reg != AArch64_REG_INVALID) {
      free_tmp_reg(self, temp_reg);
    }
    self->reg_val_offset += size;
  }
  for (int i = 0; i < SCRATCH_REG_MAX; i++) {
    if (self->reg_used[i] == VREG_USED) {
      self->reg_used[i] = VREG_FREE;
    }
  }
}

// void gum_istaker_destroy(Itransformer *stalker) {
//   g_object_unref(stalker->modules);
//   gum_free_pages(stalker->buf);
// };
inline static gboolean is_control_flow(csh capstone, const cs_insn *insn) {
  return cs_insn_group(capstone, insn, CS_GRP_JUMP) ||
         cs_insn_group(capstone, insn, CS_GRP_RET) ||
         cs_insn_group(capstone, insn, CS_GRP_CALL);
};
// inline void istalker_transform_instr(csh capstone, const cs_insn *insn,
//                                      GumStalkerOutput *output,
//                                      Itransformer *istalker,
//                                      GumStalkerIterator *iterator) {}

// inline static void write_write_bytes(GumStalkerItransformer *self, gchar
// *bytes,
//                                      gsize size) {
//   memcpy(self->buf_offset, bytes, size);
//   self->buf_offset += size;
// };

inline static void istalker_write_bytes(GumStalkerItransformer *self,
                                        gchar *bytes, gsize size) {
  memcpy(self->buf_offset, bytes, size);
}
// write to file
static inline void istalker_write_block_compile(GumStalkerItransformer *self) {
  g_debug("write block compile");
  ImsgBlockCompile *compile_blk = &self->current_block;
  self->current_block.spec_size=sizeof(ImsgRegSpec)*self->block_specs->len;
  g_output_stream_write(self->block_channel, (gchar *)compile_blk,
                        sizeof(ImsgBlockCompile), NULL, NULL);
  g_output_stream_write(self->block_channel, (gchar *)compile_blk->address,
                        compile_blk->size, NULL, NULL);
  g_output_stream_write(self->block_channel,
                        (gchar *)compile_blk->compiled_address,
                        compile_blk->compiled_size, NULL, NULL);
  g_output_stream_write(self->block_channel, self->block_specs->data,
                        sizeof(ImsgRegSpec) * self->block_specs->len, NULL,
                        NULL);
  g_array_set_size(self->block_specs, 0);
  compile_blk->id++;
}
void istalker_write_context(GumStalkerItransformer *istaker, ImsgContext *msg) {
  istalker_write_bytes(istaker, (gchar *)msg, sizeof(ImsgContext));
}

// void itransformer_transform_instr() {};
inline static gboolean
itransformer_try_write_context(GumStalkerItransformer *self,
                               GumStalkerIterator *iterator,
                               GumArm64Writer *cw) {
  // gconstpointer write_label="write";
  gconstpointer not_write_label = "done";
  cw = self->cw;
  aarch64_reg tm_reg = REG_TRANSFROMER(self);
  if (!self->dump_context) {
    return false;
  }

  g_debug("write context");
  aarch64_reg value_reg = allocate_tmp_reg(self);
  // it should always be x28,x27.

  gum_arm64_writer_put_ldr_reg_reg_offset(
      cw, value_reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, dump_counter));

  gum_arm64_writer_put_sub_reg_reg_imm(cw, value_reg, value_reg, 1);

  gum_arm64_writer_put_str_reg_reg_offset(
      cw, value_reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, dump_counter));

  gum_arm64_writer_put_cbnz_reg_label(cw, value_reg, not_write_label);

  gum_stalker_iterator_put_callout(iterator, on_block_ctx, self, NULL);
  gum_arm64_writer_put_label(cw, not_write_label);
  // 可能不太需要free，x27 还是被分配的
  free_tmp_reg(self, value_reg);

  return true;
};
static inline void free_tf_reg(GumStalkerItransformer *self, int idx) {
  aarch64_reg tm_reg = REG_TRANSFROMER(self);
  aarch64_reg reg = self->tf_regs[idx];
  free_scartch_register(self, tm_reg, reg);
  self->tf_regs[idx] = AArch64_REG_INVALID;
};
static inline void end_block_tranform(GumStalkerItransformer *self,
                                      GumArm64Writer *cw) {

  aarch64_reg tm_reg = REG_TRANSFROMER(self);
  // for(int i=0;i<SCRATCH_REG_MAX;i++){
  //   if(transformer->reg_used[i]!=VREG_FREE){
  //     aarch64_reg reg=SCRATCH_REG_BOTTOM+i;
  //     save_scratch_register(cw, tm_reg, reg);
  //   }
  // }
  gum_arm64_writer_put_str_reg_reg_offset(
      cw, REG_BUF_OFFSET(self), tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, buf_offset));
  free_tf_reg(self, BUF_OFFSET_REG_IDX);
  if (tm_reg != SCRATCH_REG_TOP) {
    save_register(cw, tm_reg, SCRATCH_REG_TOP);
  }
  free_tf_reg(self, TRANSFROMER_REG_IDX);
}
static void
gum_stalker_itransformer_transform_block(GumStalkerItransformer *transformer,
                                         GumStalkerIterator *iterator,
                                         GumStalkerOutput *output) {
  g_debug("============transform block=======");
  const cs_insn *insn;
  transformer->iterator = iterator;
  transformer->cw = output->writer.arm64;
  GumArm64Writer *cw = output->writer.arm64;
  transformer->capstone = gum_stalker_iterator_get_capstone(iterator);
  transformer->current_block.compiled_address =
      (GumAddress)gum_arm64_writer_cur(cw);
  GumAddress block_address = 0;
  gsize block_size = 0;
  guint32 instr_count = 0;
  transformer->reg_val_offset = 0;

  // do {
  //   gum_stalker_iterator_next(iterator, &insn);
  //   instr_count++;
  // }while (is_control_flow(transformer->capstone, insn));

  while (gum_stalker_iterator_next(iterator, &insn)) {
    // I think we have to call this function after call the
    // gum_stalker_iterator_next;
    // gum_arm64_writer_put_brk_imm(cw, 0);
    instr_count++;
    g_debug("transform %llx:%s %s", insn->address, insn->mnemonic,
            insn->op_str);
    if (transformer->state == ITRACE_STATE_CREATED) {
      gum_stalker_iterator_put_callout(
          iterator, gum_stalker_itransformer_starting, transformer, NULL);
      transformer->state = ITRACE_STATE_STARTING;
    }
    if (instr_count == 1 && transformer->block_done) {

      transformer->block_done = false;
      block_address = insn->address;
      aquire_tf_base_reg(transformer);
      itransformer_try_write_context(transformer, iterator, cw);
      gum_arm64_writer_put_ldr_reg_reg_offset(
          cw, REG_BUF_OFFSET(transformer), REG_TRANSFROMER(transformer),
          G_STRUCT_OFFSET(GumStalkerItransformer, buf_offset));
      
      aarch64_reg value_reg = allocate_tmp_reg(transformer);
      align_up_register(cw, REG_BUF_OFFSET(transformer), 16);
      gum_arm64_writer_put_add_reg_reg_imm(cw, value_reg, AArch64_REG_XZR,
                                           IMSG_BLOCK_EXEC);
      gum_arm64_writer_put_str_reg_reg_offset_mode(
          cw, value_reg, REG_BUF_OFFSET(transformer), 8, GUM_INDEX_POST_ADJUST);
      gum_arm64_writer_put_ldr_reg_u64(cw, value_reg, transformer->current_block.id);
      gum_arm64_writer_put_str_reg_reg_offset_mode(
          cw, value_reg, REG_BUF_OFFSET(transformer), 8, GUM_INDEX_POST_ADJUST);
      free_tmp_reg(transformer, value_reg);
    }
    if (is_control_flow(transformer->capstone, insn)) { // control flow
      g_debug("get control flow");
      // gum_arm64_writer_put_ldr_reg_value(cw, reg_val_offset_ref, transformer->reg_val_offset);
      end_block_tranform(transformer, cw);
      gum_stalker_iterator_keep(iterator);
      transformer->block_done = true;
      continue;
    }
    cs_regs regs_read, regs_written;
    uint8_t num_regs_read, num_regs_written;

    regs_access(transformer->capstone, insn, regs_read, &num_regs_read,
                regs_written, &num_regs_written);
    reslove_regs(transformer, regs_read, num_regs_read, regs_written,
                 num_regs_written);
    gum_stalker_iterator_keep(iterator);

    istalker_save_regs(transformer, regs_written, num_regs_written,
                       REG_BUF_OFFSET(transformer), insn->address);
  }

  block_size += insn->size;

  transformer->current_block.address = block_address;
  transformer->current_block.size = block_size;
  transformer->current_block.compiled_size = gum_arm64_writer_offset(cw);

  if (transformer->block_done) {
    // send block compile message
    // emit_scratch_register_restore(cw)
    // save_scratch_register(cw, , aarch64_reg reg)
    istalker_write_block_compile(transformer); // send message
  } else {
    // emit_scartch_reg_in_transform(transformer, cw, offest_vreg);
    g_warning("block %llx coutine at %llx", block_address,
              block_address + block_size);
  }
  g_debug("============transform block end===========");
}

static void on_block_ctx(GumCpuContext *cpu_context,
                         GumStalkerItransformer *tm) {
  if (tm->buf_offset + sizeof(ImsgContext) > tm->guard_page_addr) {
    dump_gum_cpu_context(cpu_context);
    return;
  }
  ImsgContext *ctx = (ImsgContext *)(tm->buf_offset);
  ctx->type = IMSG_MSG_CONTEXT;
  // asm volatile("b .");
  memcpy(&ctx->cpu_context, cpu_context, sizeof(GumCpuContext));
  tm->dump_counter = tm->context_interval;
  for (int i = 0; i < SCRATCH_REG_MAX; i++) {
    if (tm->reg_used[i] != VREG_FREE) {
      aarch64_reg reg = SCRATCH_REG_BOTTOM + i;
      ctx->cpu_context.x[reg] = tm->saved_regs[i];
    }
  }
  dump_imsg_context(ctx);
};
static void bind_vreg(GumStalkerItransformer *tm, guint idx,
                      aarch64_reg reg) {
  
  tm->tf_regs[idx] = reg;

  tm->reg_used[SCRATCH_REG_INDEX(reg)] = idx;
};
static void collect_to_be_alloc(GumStalkerItransformer *tm, cs_regs regs,
                                 uint8_t num_regs, gint *to_be_alloc,gsize * count) {

  
  for (uint8_t i = 0; i != num_regs; i++) {

    aarch64_reg reg = regs[i];
    if (!is_scartch_register(reg)) {
      continue;
    }
    if (tm->reg_used[SCRATCH_REG_INDEX(reg)] >= 0) {
      
      int vidx = tm->reg_used[SCRATCH_REG_INDEX(reg)];
      to_be_alloc[(*count)] = vidx;
      (*count)++;
      //g_debug("%s need to be realloc %d", cs_reg_name(tm->capstone, reg), vidx);
    }
    tm->reg_used[SCRATCH_REG_INDEX(reg)] = VREG_USED;
  }
}

static void dump_tf_regs(GumStalkerItransformer *self) {
  g_debug("dump tf regs");
  for (int i = 0; i != SCRATCH_REG_MAX; i++) {
    if (self->reg_used[i] == VREG_FREE) {
      g_debug("reg %s f", cs_reg_name(self->capstone, SCRATCH_REG_BOTTOM + i));
    }
    if (self->reg_used[i] == VREG_USED) {
      g_debug("reg %s u", cs_reg_name(self->capstone, SCRATCH_REG_BOTTOM + i));
    }
    if (self->reg_used[i] >= 0) {
      g_debug("reg %s %d", cs_reg_name(self->capstone, SCRATCH_REG_BOTTOM + i),
              self->reg_used[i]);
    }
  };
  g_debug("end dump tf regs");
};
static void reslove_regs(GumStalkerItransformer *tm, cs_regs regs_read,
                         uint8_t num_regs_read, cs_regs regs_written,
                         uint8_t num_regs_written) {

  // pick_scratch_registers(uint16_t *regs_read, uint8_t num_regs_read,
  // *regs_written, uint8_t num_regs_written)
  // g_debug("reslove regs");

  gint to_be_alloc[SCRATCH_REG_MAX];
  gsize count = 0;

  collect_to_be_alloc(tm, regs_read, num_regs_read, to_be_alloc,&count);
  collect_to_be_alloc(tm, regs_written, num_regs_written, to_be_alloc,&count);
  for (uint8_t i = 0; i < count; i++) {
    gint idx = to_be_alloc[i];
    aarch64_reg old_reg = tm->tf_regs[idx];
    aarch64_reg new_reg = allocate_tmp_reg(tm);
    g_debug("reallocate register idx %d %s -> %s", idx,cs_reg_name(tm->capstone, old_reg),
            cs_reg_name(tm->capstone, new_reg));
    gum_arm64_writer_put_mov_reg_reg(tm->cw, new_reg, old_reg);
    free_scartch_register(tm, REG_TRANSFROMER(tm), old_reg);
    tm->reg_used[SCRATCH_REG_INDEX(old_reg)] = VREG_USED;
    bind_vreg(tm, idx, new_reg);
  }

  // dump_tf_regs(tm);
};

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

static void g_debug_print_uint128(const guint8 bytes[16], GString *output) {
  // 将 128 位数据打印为 16 进制格式

  g_string_append_printf(output, "0x"); // 每个字节两位16进制
  for (int i = 0; i < 16; i++) {
    g_string_append_printf(output, "%02X", bytes[i]); // 每个字节两位16进制
  }
  g_debug("%s", output->str);
}

static void dump_imsg_context(const ImsgContext *context) {
  g_debug("=============cpu_context=============");
  dump_gum_cpu_context(&context->cpu_context);
  g_debug("  fpsr: 0x%016" G_GINT64_MODIFIER "x", context->fpsr);
  g_debug("  fpcr: 0x%016" G_GINT64_MODIFIER "x", context->fpcr);
  g_debug("===========end cpu_context============");
}
static void dump_gum_cpu_context(const GumArm64CpuContext *cpu_context) {

  for (int i = 0; i < 29; i++) {
    g_debug("  x%d: 0x%016" G_GINT64_MODIFIER "x", i, cpu_context->x[i]);
  }
  g_debug("  fp: 0x%016" G_GINT64_MODIFIER "x", cpu_context->fp);
  g_debug("  lr: 0x%016" G_GINT64_MODIFIER "x", cpu_context->lr);
  g_debug("  sp: 0x%016" G_GINT64_MODIFIER "x", cpu_context->sp);
  g_debug("  nzcv: 0x%016" G_GINT64_MODIFIER "x", cpu_context->nzcv);
  g_debug("  pc: 0x%016" G_GINT64_MODIFIER "x", cpu_context->pc);
  GString *output = g_string_new(NULL);
  for (int i = 0; i < 32; i++) {
    g_string_append_printf(output, "  q%d: ", i);
    g_debug_print_uint128(cpu_context->v[i].q, output);
    g_string_truncate(output, 0);
  }
  g_string_free(output, TRUE);
}