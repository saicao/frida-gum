
#include "aarch64.h"
#include "capstone.h"
#include "gumarm64writer.h"
#include "gumdefs.h"
#include "gumexceptor.h"
#include "gumisralkeritransformer.h"
#include "gummemory.h"
#include "gumstalker.h"
#include <stdint.h>
#undef g_debug
#define g_debug(fmt, ...)
const guint64 GURAD_MAGIC = 0xdeadbeeeeeeeeeef;
static void gum_stalker_itransformer_iface_init(gpointer g_iface,
                                                gpointer iface_data);
static void
gum_stalker_itransformer_transform_block(GumStalkerTransformer *transformer,
                                         GumStalkerIterator *iterator,
                                         GumStalkerOutput *output);
static void gum_stalker_itransformer_dispose(GObject *self);
static void gum_stalker_itransformer_finalize(GObject *self);

inline static void write_bytes_to_stream(GOutputStream *stream, gchar *bytes,
                                         gsize size) {
  gsize n_write = 0;
  GError *error = NULL;
  g_output_stream_write_all(stream, bytes, size, &n_write, NULL, &error);
  if (error) {
    g_error("failed to write to stream %s", error->message);
  }
}
struct _GumStalkerItransformer {
  GObject parent;
  guint64 saved_regs[SCRATCH_REG_MAX];
  // reg [i]=who use the register i
  int reg_used[SCRATCH_REG_MAX];
  aarch64_reg tf_regs[SCRATCH_REG_MAX];
  gpointer buf;
  gpointer buf_offset;
  gsize num_buf_pages;
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
  GOutputStream *bstream;
  GOutputStream *estream;
};
G_DEFINE_TYPE_EXTENDED(
    GumStalkerItransformer, gum_stalker_itransformer, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_STALKER_TRANSFORMER,
                          gum_stalker_itransformer_iface_init))
static void dump_imsg_context(const ImsgContext *context);
static void dump_gum_cpu_context(const GumArm64CpuContext *cpu_context);
static aarch64_reg allocate_tmp_reg(GumStalkerItransformer *tm);
static inline uint32_t extract32(uint32_t value, int start, int length) {
  return (value >> start) & (~0U >> (32 - length));
}

static void
gum_stalker_itransformer_class_init(GumStalkerItransformerClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->dispose = gum_stalker_itransformer_dispose;
  object_class->finalize = gum_stalker_itransformer_finalize;
  return;
}

static void gum_stalker_itransformer_init(GumStalkerItransformer *self) {
  g_debug("gum_stalker_itransformer_init");
  self->buf = NULL;
  self->buf_offset = NULL;
  self->num_buf_pages = 0;

  self->block_done = true;
  self->state = ITRACE_STATE_CREATED;
  self->iterator = NULL;
  self->cw = NULL;
  memset(&self->current_block, 0, sizeof(ImsgBlockCompile));
  self->current_block.type = IMSG_BLOCK_COMPILE;
  self->current_block.id = BLOCK_ID_START;
  memset(self->saved_regs, 0, sizeof(self->saved_regs));
  for (int i = 0; i != SCRATCH_REG_MAX; i++) {
    self->reg_used[i] = VREG_FREE;
    self->tf_regs[i] = AArch64_REG_INVALID;
  }
  self->block_specs = g_array_new(FALSE, FALSE, sizeof(ImsgRegSpec));
  self->modules = NULL;

  self->dump_context = TRUE;
  self->context_interval = 1;
  self->dump_counter = self->context_interval;
  self->exceptor = gum_exceptor_obtain();
}
static void dump_exception_details(const GumExceptionDetails *details) {
  gchar *str_detail = gum_exception_details_to_string(details);
  g_warning("unhandled excpetion at address %p %s", details->address,
            str_detail);
  g_free(str_detail);
}
static gsize drain_buffer(GumStalkerItransformer *self) {

  gsize offset = self->buf_offset - self->buf;

  gsize n_write = 0;
  GError *error = NULL;
  g_debug("write to channel %p with buf %p,%lu", self->estream, self->buf,
          offset);
  g_output_stream_flush(self->bstream, NULL, &error);
  g_output_stream_write_all(self->estream, self->buf, offset, &n_write, NULL,
                            &error);
  g_output_stream_flush(self->estream, NULL, &error);
  return n_write;
}
static gboolean gum_try_do_sink(GumExceptionDetails *details,
                                gpointer user_data) {
  
  GumStalkerItransformer *self = GUM_STALKER_ITRANSFORMER(user_data);
  // g_debug("gum_try_do_sink at %p %d", details->address, details->type);
  // g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG | G_LOG_FLAG_RECURSION,
  //       "gum_try_do_sink at %p %d");

  if (details->type != GUM_EXCEPTION_ACCESS_VIOLATION) {
    goto ret;
  }
  // 所有的访问都是对齐的,darwin内核应该不支持不对齐访问
  GumAddress address = (GumAddress)details->memory.address;
  if (address != (GumAddress)self->guard_page_addr) {
    // g_debug("address %p != %p", address, self->guard_page_addr);
    goto ret;
  }

  GumCpuContext *cpu_context = &details->context;
  const guint32 *insn;

  insn = (guint32 *)cpu_context->pc;

  // g_debug("gum_try_do_sink at %p %p", details->address, *insn);
  int reg_idx =
      extract32(*insn, 5, 5); // 0x1F is a mask for the lower 5 bits (0b11111)

  g_debug("gum_try_do_sink at %p %p reg %d", details->address,
          details->memory.address, reg_idx);
  self->buf_offset = (gpointer)address;
  drain_buffer(self);
  cpu_context->x[reg_idx] = (guint64)self->buf;
  return TRUE;
ret:
  dump_exception_details(details);
  return FALSE;
}
void gum_stalker_itransformer_set_up(GumStalkerItransformer *self, gsize n_page,
                                     GOutputStream *bstream,
                                     GOutputStream *estream,
                                     gsize dump_interval) {
  gum_stalker_itransformer_set_buf(self, n_page);
  gum_stalker_itransformer_sink(self, bstream, estream);
  if (dump_interval == 0) {
    self->dump_context = FALSE;
  }
  self->context_interval = dump_interval;
  self->dump_counter = 0;
}
void gum_stalker_itransformer_set_buf(GumStalkerItransformer *self,
                                      gsize n_page) {
  gsize page_size = gum_query_page_size();

  void *buf = gum_alloc_n_pages(n_page + 1, GUM_PAGE_RW);
  if (buf == NULL) {
    g_error("failed to allocate memory");
    g_abort();
  }
  guint64 *gurad_page = buf + n_page * page_size;
  self->buf = buf;
  self->buf_offset = buf;
  self->num_buf_pages = n_page;
  gum_mprotect(gurad_page, page_size, GUM_PAGE_READ);
  self->guard_page_addr = gurad_page;
  g_debug("set buffer %p %p", buf, gurad_page);
  gum_exceptor_add(self->exceptor, gum_try_do_sink, self);
};
void gum_stalker_itransformer_sink(GumStalkerItransformer *self,
                                   GOutputStream *bstream,
                                   GOutputStream *estream) {
  self->bstream = bstream;
  self->estream = estream;
  g_object_ref(bstream);
  g_object_ref(estream);
};

static void gum_stalker_itransformer_dispose(GObject *object) {
  GumStalkerItransformer * self;
  self = GUM_STALKER_ITRANSFORMER (object);
  g_debug("transformer dispose");
  drain_buffer(self);
  g_clear_object(&self->exceptor);
  g_clear_object(&self->bstream);
  g_clear_object(&self->estream);
};
static void gum_stalker_itransformer_finalize(GObject *object) {
  GumStalkerItransformer * self;
  self = GUM_STALKER_ITRANSFORMER (object);
  g_debug("transformer finalize");
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
static void gum_stalker_itransformer_starting(GumCpuContext * cpu_context,
    gpointer user_data);
static aarch64_reg register_to_full_size_register(aarch64_reg reg);

static void reslove_regs(GumStalkerItransformer *tm, cs_regs regs_read,
                         uint8_t num_regs_read, cs_regs regs_written,
                         uint8_t num_regs_written);
static void on_block_ctx(GumCpuContext *cpu_context,
                         gpointer user_data);
static gboolean itransformer_try_write_context(GumStalkerItransformer *tm,
                                               GumStalkerIterator *iterator,
                                               GumArm64Writer *cw);
void save_register(GumArm64Writer *cw, aarch64_reg tm_reg, aarch64_reg reg) {
  gum_arm64_writer_put_str_reg_reg_offset(
      cw, reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, saved_regs) +
          SCRATCH_REG_OFFSET(reg));
};
static void gum_stalker_itransformer_starting(GumCpuContext * cpu_context,
    gpointer user_data) {
  GumStalkerItransformer *self = GUM_STALKER_ITRANSFORMER(user_data);
  if (self->state != ITRACE_STATE_STARTING) {
    return;
  };

  ImsgMeta meta = {IMSG_META_MAGIC, 2, 8};
  write_bytes_to_stream(self->estream, (gchar *)&meta, sizeof(ImsgMeta));
  gchar data[8] = {0};
  write_bytes_to_stream(self->estream, data, 8);
  memcpy(self->saved_regs, cpu_context->x + (SCRATCH_REG_BOTTOM - AArch64_REG_X0),
         sizeof(self->saved_regs));
  self->state = ITRACE_STATE_STARTED;
  ImsgContext ctx = {IMSG_CONTEXT, *cpu_context, 0, 0, 0xFFFFFFFFFFFFFFFF};

  write_bytes_to_stream(self->estream, (gchar *)&ctx, sizeof(ImsgContext));
  g_debug("gum_stalker_itransformer_starting");
  dump_imsg_context(&ctx);
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
    g_warning("failed to allocate offset register,possible already aquired");
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
static inline void adjust_register_alignment(GumArm64Writer *writer,
                                             aarch64_reg reg,
                                             size_t alignment) {
  gum_arm64_writer_put_add_reg_reg_imm(writer, reg, reg, alignment - 1);
  gum_arm64_writer_put_and_reg_reg_imm(writer, reg, reg, ~(alignment - 1));
}
size_t align_up(size_t x, size_t alignment) {
  // Make sure alignment is a power of two
  return (x + alignment - 1) & ~(alignment - 1);
}
static void istalker_save_regs(GumStalkerItransformer *self, cs_regs regs,
                               uint8_t num_regs, aarch64_reg offest_reg,
                               GumAddress address) {
  guint32 *meta_size = &self->current_block.meta_size;
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
    g_debug("save register %s", cs_reg_name(self->capstone, reg));

    if (*meta_size % size != 0) {

      g_debug("reg_val_offset %u,size %u", *meta_size, size);

      adjust_register_alignment(cw, offest_reg, size);
      *meta_size = align_up(*meta_size, size);
    };
    ImsgRegSpec spec = {address, cpu_reg_index, *meta_size};
    g_array_append_val(self->block_specs, spec);
    gum_arm64_writer_put_str_reg_reg_offset_mode(cw, source_reg, offest_reg,
                                                 size, GUM_INDEX_POST_ADJUST);
    if (temp_reg != AArch64_REG_INVALID) {
      free_tmp_reg(self, temp_reg);
    }
    *meta_size = *meta_size + size;
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

// write to file
static inline void istalker_write_block_compile(GumStalkerItransformer *self) {
  g_debug("write block compile");
  ImsgBlockCompile *compile_blk = &self->current_block;
  GOutputStream *os = self->bstream;

  self->current_block.spec_size = sizeof(ImsgRegSpec) * self->block_specs->len;

  write_bytes_to_stream(os, (gchar *)compile_blk, sizeof(ImsgBlockCompile));
  write_bytes_to_stream(os, (gchar *)compile_blk->address, compile_blk->size);
  write_bytes_to_stream(os, (gchar *)self->block_specs->data,
                        sizeof(ImsgRegSpec) * self->block_specs->len);
  g_array_set_size(self->block_specs, 0);
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
    return FALSE;
  }

  g_debug("put code write context");
  aarch64_reg value_reg = allocate_tmp_reg(self);
  // it should always be x28,x27 x26.

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
  // GArray * block_specs = self->block_specs;
  guint32 *meta_size = &self->current_block.meta_size;
  if (*meta_size % 16 != 0) {
    adjust_register_alignment(self->cw, REG_BUF_OFFSET(self), 16);
    *meta_size = align_up(*meta_size, 16);
    g_debug("end meta size %u", *meta_size);
  };

  aarch64_reg tm_reg = REG_TRANSFROMER(self);

  // for(int i=0;i<SCRATCH_REG_MAX;i++){
  //   if(transformer->reg_used[i]!=VREG_FREE){
  //     aarch64_reg reg=SCRATCH_REG_BOTTOM+i;
  //     save_scratch_register(cw, tm_reg, reg);
  //   }
  // }
  // if(self->reg_val_offset%8!=0){
  //   align_up_register(cw, REG_BUF_OFFSET(self), 8);
  //   self->reg_val_offset=align_up(self->reg_val_offset,8);
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
static void gum_stalker_itransformer_keep_writes(GumStalkerItransformer *self,
                                            GumStalkerIterator *iterator,
                                            const cs_insn *insn) {
  cs_regs regs_read, regs_written;
  uint8_t num_regs_read, num_regs_written;

  regs_access(self->capstone, insn, regs_read, &num_regs_read,
              regs_written, &num_regs_written);
  reslove_regs(self, regs_read, num_regs_read, regs_written,
               num_regs_written);
  gum_stalker_iterator_keep(iterator);

  istalker_save_regs(self, regs_written, num_regs_written,
                     REG_BUF_OFFSET(self), insn->address);
};

// static inline gboolean handle_svc(GumStalkerItransformer *transformer,
//                                   GumStalkerIterator *iterator,
//                                   const cs_insn *insn) {

//   const uint32_t *last_insn = insn->address - 4;

//   // // mov x16,0x1
//   // if (*last_insn == 0xd2800030) {
//   //   g_debug("handle exit");
//   //   ImsgTermaintingBlock tb = {0};
//   //   tb.type = IMSG_BLOCK_TERM;
//   //   tb.id = transformer->current_block.id;
//   //   tb.meta_offset = transformer->current_block.meta_size;
//   //   tb.stop_address = insn->address;
//   //   write_bytes_to_stream(transformer->bstream, (char *)&tb, sizeof(tb));
//   //   gum_arm64_writer_put_brk_imm(transformer->cw, 1234);
//   // }
//   // return false;
// }
/**
 * @brief
 * 当 transformer
 * 遇到未完成的block时（拆分一个block，多次编译），因fridaAPI采用迭代器，我们无法提前知道这种block。
 * 在这种block发生的时候我们已经无法再次intrument，所以只能在下一个block进行intrument。
 * 幸运的是下一次调用时连续的，所以我们可以分享transformer state。
 * 在这两次调用之间，所以我们的transformer，寄存器依然是一样的。我们没有必要改变他。
 *
 * @param transformer
 * @param iterator
 * @param output
 */
static void
gum_stalker_itransformer_transform_block(GumStalkerTransformer *transformer,
                                         GumStalkerIterator *iterator,
                                         GumStalkerOutput *output) {
  GumStalkerItransformer *self = GUM_STALKER_ITRANSFORMER(transformer);
  g_debug("============transform block %d=======",
          transformer->current_block.id);
  const cs_insn *insn;
  ImsgBlockCompile *current_block = &self->current_block;
  self->iterator = iterator;
  self->cw = output->writer.arm64;
  GumArm64Writer *cw = output->writer.arm64;
  self->capstone = gum_stalker_iterator_get_capstone(iterator);
  // transformer->current_block.compiled_address =
  //     (GumAddress)gum_arm64_writer_cur(cw);
  guint32 instr_count = 0;

  // do {
  //   gum_stalker_iterator_next(iterator, &insn);
  //   instr_count++;
  // }while (is_control_flow(transformer->capstone, insn));
  while (gum_stalker_iterator_next(iterator, &insn)) {
    instr_count++;
    g_debug("transform %llx:%s %s", insn->address, insn->mnemonic,
            insn->op_str);
    if (self->state == ITRACE_STATE_CREATED) {
      gum_stalker_iterator_put_callout(
          iterator, gum_stalker_itransformer_starting, self, NULL);
      self->state = ITRACE_STATE_STARTING;
    }
    if (instr_count == 1 && self->block_done) {
      // if (current_block->id == 18) {

      //   gum_arm64_writer_put_brk_imm(cw, 1234);
      // }
      self->block_done = FALSE;
      current_block->address = insn->address;
      // 应该永远是x28， ofset x27
      aquire_tf_base_reg(self);
      itransformer_try_write_context(self, iterator, cw);
      gum_arm64_writer_put_ldr_reg_reg_offset(
          cw, REG_BUF_OFFSET(self), REG_TRANSFROMER(self),
          G_STRUCT_OFFSET(GumStalkerItransformer, buf_offset));

      aarch64_reg value_reg = allocate_tmp_reg(self);
      // align_up_register(cw, REG_BUF_OFFSET(transformer), 16);

      gum_arm64_writer_put_mov_imm(cw, value_reg, IMSG_BLOCK_EXEC);
      gum_arm64_writer_put_str_reg_reg_offset_mode(
          cw, value_reg, REG_BUF_OFFSET(self), 8, GUM_INDEX_POST_ADJUST);
      gum_arm64_writer_put_ldr_reg_u64(cw, value_reg, current_block->id);
      gum_arm64_writer_put_str_reg_reg_offset_mode(
          cw, value_reg, REG_BUF_OFFSET(self), 8, GUM_INDEX_POST_ADJUST);
      free_tmp_reg(self, value_reg);
    }
    if (is_control_flow(self->capstone, insn)) { // control flow
      g_debug("get control flow");
      // gum_arm64_writer_put_ldr_reg_value(cw, reg_val_offset_ref,
      // transformer->reg_val_offset);
      current_block->size = insn->address + insn->size - current_block->address;
      end_block_tranform(self, cw);
      gum_stalker_iterator_keep(iterator);
      self->block_done = true;
      continue;
    }
    // if (insn->id == AArch64_INS_SVC) {
    //   g_debug("handle svc");
    //   handle_svc(transformer, iterator, insn);
    // }

    cs_regs regs_read, regs_written;
    uint8_t num_regs_read, num_regs_written;

    regs_access(self->capstone, insn, regs_read, &num_regs_read,
                regs_written, &num_regs_written);
    reslove_regs(self, regs_read, num_regs_read, regs_written,
                 num_regs_written);
    gum_stalker_iterator_keep(iterator);

    istalker_save_regs(self, regs_written, num_regs_written,
                       REG_BUF_OFFSET(self), insn->address);
  }

  // transformer->current_block.compiled_size = gum_arm64_writer_offset(cw);

  if (self->block_done) {
    istalker_write_block_compile(self);
    current_block->type = IMSG_BLOCK_COMPILE;
    current_block->meta_size = 0;
    // current_block->spec_size=0;
    current_block->id++;
  } else {
    // emit_scartch_reg_in_transform(transformer, cw, offest_vreg);
    g_warning("block %llx coutine at %llx", current_block->address,
              current_block->address + current_block->size);
  }

  g_debug("============transform block end===========");
}

static void on_block_ctx(GumCpuContext *cpu_context,
                         gpointer user_data) {
  GumStalkerItransformer *tm = GUM_STALKER_ITRANSFORMER(user_data);
  g_debug("on block ctx");
  // 这里处理的比较低效，破坏了以page为单位的写
  if (tm->buf_offset + sizeof(ImsgContext) > tm->guard_page_addr) {
    drain_buffer(tm);
    tm->buf_offset = tm->buf;
  }

  ImsgContext *ctx = (ImsgContext *)(tm->buf_offset);
  ctx->type = IMSG_CONTEXT;
  // asm volatile("b .");
  memcpy(&ctx->cpu_context, cpu_context, sizeof(GumCpuContext));
  tm->dump_counter = tm->context_interval;
  for (int i = SCRATCH_REG_INDEX(AArch64_REG_X26);
       i <= SCRATCH_REG_INDEX(AArch64_REG_X28); i++) {

    aarch64_reg reg = SCRATCH_REG_BOTTOM + i;
    ctx->cpu_context.x[reg - AArch64_REG_X0] = tm->saved_regs[i];
    g_debug("save register %s %llx", cs_reg_name(tm->capstone, reg),
            tm->saved_regs[i]);
  }
  ctx->paddings = 0xFFFFFFFFFFFFFFFF;

  tm->buf_offset += sizeof(ImsgContext);
  // cpu_context->x[DEFAULT_BUF_OFFSET_REG - AArch64_REG_X0] =
  //     (guint64)tm->buf_offset;
  g_debug("buf offset %p", tm->buf_offset);
  // write_bytes_to_stream(tm->estream, (gchar *)&ctx, sizeof(ImsgContext));
  // dump_imsg_context(ctx);
};
static void bind_vreg(GumStalkerItransformer *tm, guint idx, aarch64_reg reg) {

  tm->tf_regs[idx] = reg;

  tm->reg_used[SCRATCH_REG_INDEX(reg)] = idx;
};
static void collect_to_be_alloc(GumStalkerItransformer *tm, cs_regs regs,
                                uint8_t num_regs, gint *to_be_alloc,
                                gsize *count) {

  for (uint8_t i = 0; i != num_regs; i++) {

    aarch64_reg reg = regs[i];
    if (!is_scartch_register(reg)) {
      continue;
    }
    if (tm->reg_used[SCRATCH_REG_INDEX(reg)] >= 0) {

      int vidx = tm->reg_used[SCRATCH_REG_INDEX(reg)];
      to_be_alloc[(*count)] = vidx;
      (*count)++;
      // g_debug("%s need to be realloc %d", cs_reg_name(tm->capstone, reg),
      // vidx);
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

  collect_to_be_alloc(tm, regs_read, num_regs_read, to_be_alloc, &count);
  collect_to_be_alloc(tm, regs_written, num_regs_written, to_be_alloc, &count);
  for (uint8_t i = 0; i < count; i++) {
    gint idx = to_be_alloc[i];
    aarch64_reg old_reg = tm->tf_regs[idx];
    aarch64_reg new_reg = allocate_tmp_reg(tm);
    g_debug("reallocate register idx %d %s -> %s", idx,
            cs_reg_name(tm->capstone, old_reg),
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