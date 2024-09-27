
#include "aarch64.h"
#include "capstone.h"
#include "gumarm64writer.h"
#include "gumdefs.h"
#include "gumexceptor.h"
#include "gumisralkeritransformer.h"

#include "gummemory.h"
#include "gumstalker.h"
// #define GUM_STALKER_ITRANSFOREMER_DEBUG 1
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
  int reg_used[SCRATCH_REG_MAX];
  aarch64_reg vir_regs[SCRATCH_REG_MAX];
  gpointer buf;
  gpointer buf_offset;
  gsize buf_size;
  guint64 event_id;
  ITraceState state;
  GumStalkerIterator *iterator;
  GumArm64Writer *cw;
  ImsgBlockCompile current_block;
  GArray *block_specs;
  guint32 reg_val_offset;
  GumModuleMap *modules;
  gboolean dump_context;
  guint64 context_interval;
  csh capstone;
  GumExceptor *exceptor;
  gpointer guard_page_addr;
};
G_DEFINE_TYPE_EXTENDED(
    GumStalkerItransformer, gum_stalker_itransformer, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_STALKER_TRANSFORMER,
                          gum_stalker_itransformer_iface_init))
static void dump_imsg_context(const ImsgContext *context);
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
  self->event_id = 0;
  self->state = ITRACE_STATE_CREATED;
  self->iterator = NULL;
  self->cw = NULL;
  memset(&self->current_block, 0, sizeof(ImsgBlockCompile));
  memset(self->saved_regs, 0, sizeof(self->saved_regs));
  for (int i = 0; i != SCRATCH_REG_MAX; i++) {
    self->reg_used[i] = VREG_FREE;
    self->vir_regs[i] = AArch64_REG_INVALID;
  }
  self->block_specs = g_array_new(FALSE, FALSE, sizeof(ImsgRegSpec));
  self->reg_val_offset = 0;
  self->modules = NULL;
  self->dump_context = TRUE;
  self->context_interval = 0;
  self->exceptor = gum_exceptor_obtain();


}

gboolean file_write();
gboolean gum_try_do_sink(GumExceptionDetails *details,
                         GumStalkerItransformer *self) {
  
  if (details->type != GUM_EXCEPTION_ACCESS_VIOLATION) {
    return false;
  }

  gsize page_size = gum_query_page_size();
  gpointer address = GUM_ALIGN_SIZE(details->address, page_size);
  if (address == self->guard_page_addr) {
    GumCpuContext *cpu_context = &details->context;
    const guint32 *insn;
    insn = GSIZE_TO_POINTER(cpu_context->pc);
    int reg_idx = *insn & 0x1F; // 0x1F is a mask for the lower 5 bits (0b11111)
    cpu_context->x[reg_idx]=self->buf;
    

    // gum_mprotect(self->guard_page_addr, page_size, GUM_PAGE_RW);
    // gum_mprotect(self->buf, page_size, GUM_PAGE_READ);

    return true;
  };
  // if (address == self->buf) {
  //   gum_mprotect(self->buf, self->buf_size, GUM_PAGE_RW);
  //   gum_mprotect(self->guard_page_addr, page_size, GUM_PAGE_READ);

  //   return true;
  // }
  return false;
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
  *gurad_page = GURAD_MAGIC;
  self->buf = buf;
  self->buf_offset = buf;
  self->buf_size = size;
  gum_mprotect(gurad_page, page_size, GUM_PAGE_READ);
  self->guard_page_addr = (GumAddress)gurad_page;
  gum_exceptor_add(self->exceptor, gum_try_do_sink, self);
};

static void gum_stalker_itransformer_dispose(GumStalkerItransformer *self) {
  g_clear_object(&self->exceptor);
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
      // gum_arm64_writer_put_str_reg_reg_offset(tm->cw, reg,
      //                                        REG_TRANSFROMER(tm),
      //                                        G_STRUCT_OFFSET(GumStalkerItransformer,
      //                                        saved_regs) +
      //                                            SCRATCH_REG_OFFSET(reg));
      g_debug("allocate tmp register %s", cs_reg_name(tm->capstone, reg));

      return reg;
    }
  };
  return AArch64_REG_INVALID;
}
aarch64_reg *allocate_tf_reg(GumStalkerItransformer *tm) {
  for (int i = 1; i != SCRATCH_REG_MAX; i++) {
    if (tm->vir_regs[i] == AArch64_REG_INVALID) {
      aarch64_reg reg = allocate_tmp_reg(tm);
      if (reg == AArch64_REG_INVALID) {
        return NULL;
      }
      tm->vir_regs[i] = reg;
      tm->reg_used[SCRATCH_REG_INDEX(reg)] = i;
      g_debug("allocate register %s", cs_reg_name(tm->capstone, reg));
      return tm->vir_regs + i;
    }
  }
  return NULL;
};
static aarch64_reg aquire_tf_base_reg(GumStalkerItransformer *tm) {
  if (tm->vir_regs[VREG_TRANSFROM] != AArch64_REG_INVALID) {
    g_error("transformer base register is already aquired");
  }
  tm->vir_regs[0] = SCRATCH_REG_TOP;
  g_debug("indx %d", SCRATCH_REG_INDEX(SCRATCH_REG_TOP));
  tm->reg_used[SCRATCH_REG_INDEX(SCRATCH_REG_TOP)] = 0;
  gum_arm64_writer_put_ldr_reg_address(tm->cw, SCRATCH_REG_TOP,
                                       GUM_ADDRESS(tm));

  return SCRATCH_REG_TOP;
}

static void free_scartch_register(GumStalkerItransformer *tm,
                                  aarch64_reg tm_reg, aarch64_reg reg) {
  int idx = SCRATCH_REG_INDEX(reg);
  tm->reg_used[idx] = VREG_FREE;
  gum_arm64_writer_put_ldr_reg_reg_offset(
      tm->cw, reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, saved_regs) +
          SCRATCH_REG_OFFSET(reg));
  g_debug("free register %s", cs_reg_name(tm->capstone, reg));
};
static void free_tmp_reg(GumStalkerItransformer *self, aarch64_reg reg) {
  aarch64_reg tm_reg = self->vir_regs[VREG_TRANSFROM];
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
    gum_arm64_writer_put_str_reg_reg(cw, source_reg, offest_reg);
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
  // self->buf_offset += size;
}
static inline void istalker_write_block_compile(GumStalkerItransformer *self) {
  g_debug("write block compile");
  ImsgBlockCompile *compile_blk = &self->current_block;
  istalker_write_bytes(self, compile_blk, sizeof(ImsgBlockCompile));
  istalker_write_bytes(self, compile_blk->address, compile_blk->size);
  istalker_write_bytes(self, compile_blk->compiled_address,
                       compile_blk->compiled_size);
  istalker_write_bytes(self, self->block_specs->data,
                       sizeof(ImsgRegSpec) * self->block_specs->len);
  g_array_set_size(self->block_specs, 0);
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
  aarch64_reg tm_reg = self->vir_regs[VREG_TRANSFROM];
  if (!self->dump_context) {
    return false;
  }

  g_debug("write context");
  aarch64_reg value_reg = allocate_tmp_reg(self);
  // it should always be x28,x27.

  gum_arm64_writer_put_ldr_reg_reg_offset(
      cw, value_reg, tm_reg, G_STRUCT_OFFSET(GumStalkerItransformer, event_id));

  gum_arm64_writer_put_sub_reg_reg_imm(cw, value_reg, value_reg, 1);
  gum_arm64_writer_put_str_reg_reg_offset(
      cw, value_reg, tm_reg, G_STRUCT_OFFSET(GumStalkerItransformer, event_id));
  gum_arm64_writer_put_cbnz_reg_label(cw, value_reg, not_write_label);

  gum_stalker_iterator_put_callout(iterator, on_block_ctx, self, NULL);
  gum_arm64_writer_put_label(cw, not_write_label);
  free_tmp_reg(self, value_reg);

  return true;
};
static inline void free_tf_reg(GumStalkerItransformer *tm, aarch64_reg *vreg) {
  aarch64_reg tm_reg = tm->vir_regs[VREG_TRANSFROM];
  free_scartch_register(tm, tm_reg, *vreg);
  *vreg = AArch64_REG_INVALID;
};
static inline void emit_scartch_reg_in_transform(GumStalkerItransformer *self,
                                                 GumArm64Writer *cw,
                                                 aarch64_reg *offset_vreg) {

  aarch64_reg tm_reg = self->vir_regs[VREG_TRANSFROM];
  // for(int i=0;i<SCRATCH_REG_MAX;i++){
  //   if(transformer->reg_used[i]!=VREG_FREE){
  //     aarch64_reg reg=SCRATCH_REG_BOTTOM+i;
  //     save_scratch_register(cw, tm_reg, reg);
  //   }
  // }

  free_tf_reg(self, offset_vreg);
  *offset_vreg = AArch64_REG_INVALID;

  if (tm_reg != SCRATCH_REG_TOP) {
    save_register(cw, tm_reg, SCRATCH_REG_TOP);
  }
  free_scartch_register(self, tm_reg, tm_reg);
  self->vir_regs[VREG_TRANSFROM] = AArch64_REG_INVALID;
}
static void
gum_stalker_itransformer_transform_block(GumStalkerItransformer *transformer,
                                         GumStalkerIterator *iterator,
                                         GumStalkerOutput *output) {
  g_debug("transform block");
  const cs_insn *insn;
  transformer->iterator = iterator;
  transformer->cw = output->writer.arm64;

  GumArm64Writer *cw = output->writer.arm64;
  transformer->capstone = gum_stalker_iterator_get_capstone(iterator);
  transformer->current_block.compiled_address =
      (GumAddress)gum_arm64_writer_cur(cw);
  gboolean block_done = false;
  GumAddress block_address = 0;
  gsize block_size = 0;

  guint32 instr_count = 0;
  aarch64_reg *offest_vreg = NULL;
  transformer->reg_val_offset = 0;
  // guint reg_val_offset_ref = 0;
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
    if (instr_count == 1) {

      block_address = insn->address;
      aquire_tf_base_reg(transformer);
      itransformer_try_write_context(transformer, iterator, cw);

      offest_vreg = allocate_tf_reg(transformer);
      // g_debug("offset register %s", cs_reg_name(cs, *offest_vreg));

      gum_arm64_writer_put_ldr_reg_reg_offset(
          cw, *offest_vreg, REG_TRANSFROMER(transformer),
          G_STRUCT_OFFSET(GumStalkerItransformer, buf_offset));
      align_up_register(cw, *offest_vreg, 16);
      aarch64_reg value_reg = allocate_tmp_reg(transformer);
      // ImsgHeader header = {IMSG_BLOCK_EXEC, 4};

      gum_arm64_writer_put_ldr_reg_u64(cw, value_reg, 0);
      gum_arm64_writer_put_add_reg_reg_imm(cw, value_reg, value_reg,
                                           IMSG_BLOCK_EXEC);
      gum_arm64_writer_put_str_reg_reg(cw, value_reg, *offest_vreg);
      // reg_val_offset_ref = gum_arm64_writer_put_ldr_reg_ref(cw, value_reg);
      //  gum_arm64_writer_put_ldr_reg_u32(cw, value_reg, AArch64_REG_LR);
      // gum_arm64_writer_put_str_reg_reg(cw, value_reg, *offest_vreg);
      gum_arm64_writer_put_ldr_reg_u64(cw, value_reg, block_address);
      gum_arm64_writer_put_str_reg_reg(cw, value_reg, *offest_vreg);
      free_tmp_reg(transformer, value_reg);
    }
    if (is_control_flow(transformer->capstone, insn)) { // control flow
      g_debug("get control flow");
      emit_scartch_reg_in_transform(transformer, cw, offest_vreg);
      gum_stalker_iterator_keep(iterator);
      block_done = true;
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
                       *offest_vreg, insn->address);
  }

  block_size += insn->size;

  transformer->current_block.address = block_address;
  transformer->current_block.size = block_size;
  transformer->current_block.compiled_size = gum_arm64_writer_offset(cw);

  if (block_done) {
    // send block compile message
    // emit_scratch_register_restore(cw)
    // save_scratch_register(cw, , aarch64_reg reg)
    transformer->current_block.done = true;
  } else {
    g_debug("block not done");
    g_abort();
    transformer->current_block.done = false;
  };
  istalker_write_block_compile(transformer); // send message
}

static void on_block_ctx(GumCpuContext *cpu_context,
                         GumStalkerItransformer *tm) {
  ImsgContext *ctx = (ImsgContext *)(tm->buf_offset);
  ctx->type = IMSG_MSG_CONTEXT;
  memcpy(&ctx->cpu_context, cpu_context, sizeof(GumCpuContext));
  tm->event_id = tm->context_interval;
  ctx->cpu_context.x[28] = tm->saved_regs[SCRATCH_REG_INDEX(SCRATCH_REG_TOP)];
  ctx->cpu_context.x[27] =
      tm->saved_regs[SCRATCH_REG_INDEX(SCRATCH_REG_TOP - 1)];
  // memcpy(,
  //        tm->saved_regs, sizeof(tm->saved_regs));
  // tm->buf_offset += sizeof(ImsgContext);
  dump_imsg_context(ctx);
};

// // static void on_first_block_exec(GumCpuContext *cpu_context, gpointer
// // user_data); static void on_first_block_exec(GumCpuContext *cpu_context,
// // gpointer user_data) {
// //   if(session.state!=ITRACE_STATE_STARTED){
// //     return;
// //   }
// //   on_block_exec(cpu_context, user_data);
// // };

static void bind_vreg(GumStalkerItransformer *tm, aarch64_reg *vreg,
                      aarch64_reg reg) {
  *vreg = reg;
  tm->reg_used[SCRATCH_REG_INDEX(reg)] = vreg - tm->vir_regs;
};
static gsize collect_to_be_alloc(GumStalkerItransformer *tm, cs_regs regs,
                                 uint8_t num_regs, aarch64_reg **to_be_alloc) {

  gsize count = 0;
  for (uint8_t i = 0; i != num_regs; i++) {

    aarch64_reg reg = regs[i];
    if (!is_scartch_register(reg)) {
      continue;
    }
    if (tm->reg_used[SCRATCH_REG_INDEX(reg)] >= 0) {
      g_debug("%s need to be alloc", cs_reg_name(tm->capstone, reg));
      int vidx = tm->reg_used[SCRATCH_REG_INDEX(reg)];
      tm->reg_used[SCRATCH_REG_INDEX(reg)] = VREG_USED;
      to_be_alloc[count++] = tm->vir_regs + vidx;
    }
    tm->reg_used[SCRATCH_REG_INDEX(reg)] = VREG_USED;
  }
  return count;
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

  aarch64_reg *to_be_alloc[SCRATCH_REG_MAX];
  gsize count = 0;

  count += collect_to_be_alloc(tm, regs_read, num_regs_read, to_be_alloc);
  count += collect_to_be_alloc(tm, regs_written, num_regs_written, to_be_alloc);

  for (uint8_t i = 0; i < count; i++) {
    aarch64_reg *vreg = to_be_alloc[i];
    aarch64_reg old_reg = *vreg;
    aarch64_reg new_reg = allocate_tmp_reg(tm);
    g_debug("realocate register %s -> %s", cs_reg_name(tm->capstone, old_reg),
            cs_reg_name(tm->capstone, new_reg));
    gum_arm64_writer_put_mov_reg_reg(tm->cw, new_reg, old_reg);
    free_scartch_register(tm, REG_TRANSFROMER(tm), old_reg);
    bind_vreg(tm, vreg, new_reg);
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

static void dump_imsg_context(const ImsgContext *context) {
  g_debug("type: 0x%016" G_GINT64_MODIFIER "x", context->type);
  g_debug("cpu_context: ");
  g_debug("  x0: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[0]);
  g_debug("  x1: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[1]);
  g_debug("  x2: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[2]);
  g_debug("  x3: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[3]);
  g_debug("  x4: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[4]);
  g_debug("  x5: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[5]);
  g_debug("  x6: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[6]);
  g_debug("  x7: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[7]);
  g_debug("  x8: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[8]);
  g_debug("  x9: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[9]);
  g_debug("  x10: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[10]);
  g_debug("  x11: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[11]);
  g_debug("  x12: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[12]);
  g_debug("  x13: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[13]);
  g_debug("  x14: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[14]);
  g_debug("  x15: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[15]);
  g_debug("  x16: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[16]);
  g_debug("  x17: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[17]);
  g_debug("  x18: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[18]);
  g_debug("  x19: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[19]);
  g_debug("  x20: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[20]);
  g_debug("  x21: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[21]);
  g_debug("  x22: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[22]);
  g_debug("  x23: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[23]);
  g_debug("  x24: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[24]);
  g_debug("  x25: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[25]);
  g_debug("  x26: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[26]);
  g_debug("  x27: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[27]);
  g_debug("  x28: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.x[28]);
  g_debug("  x29: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.lr);
  g_debug("  sp: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.sp);
  g_debug("  nzcv: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.nzcv);
  g_debug("  pc: 0x%016" G_GINT64_MODIFIER "x", context->cpu_context.pc);
  g_debug("fpcr: 0x%016" G_GINT64_MODIFIER "x", context->fpcr);
  g_debug("fpsr: 0x%016" G_GINT64_MODIFIER "x", context->fpsr);
}