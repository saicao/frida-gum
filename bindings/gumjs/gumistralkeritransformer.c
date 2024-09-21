
#include "gumisralkeritransformer.h"
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
};
G_DEFINE_TYPE_EXTENDED(
    GumStalkerItransformer, gum_stalker_itransformer, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_STALKER_TRANSFORMER,
                          gum_stalker_itransformer_iface_init))

static void
gum_stalker_itransformer_class_init(GumStalkerItransformerClass *klass) {
  // GObjectClass * object_class = G_OBJECT_CLASS (klass);
  return;
}
static void gum_stalker_itransformer_init(GumStalkerItransformer *self) {
  self->buf = NULL;
  self->buf_offset = NULL;
  self->buf_size = 0;
  self->event_id = 0;
  self->state = ITRACE_STATE_CREATED;
  self->iterator = NULL;
  self->cw = NULL;
  memset(&self->current_block, 0, sizeof(ImsgBlockCompile));
  self->block_specs = g_array_new(FALSE, FALSE, sizeof(ImsgRegSpec));
  self->reg_val_offset = 0;
  self->modules = NULL;
  self->dump_context = FALSE;
  self->context_interval = 0;
}
void gum_stalker_itransformer_set_buf(GumStalkerItransformer *tm,
                                         gpointer buf, gsize size) {
  tm->buf = buf;
  tm->buf_offset = buf;
  tm->buf_size = size;
};
static void gum_stalker_itransformer_iface_init(gpointer g_iface,
                                                gpointer iface_data) {
  GumStalkerTransformerInterface *iface = g_iface;

  iface->transform_block = gum_stalker_itransformer_transform_block;
}
static aarch64_reg register_to_full_size_register(aarch64_reg reg);

static void reslove_regs(GumStalkerItransformer *tm, cs_regs regs_read,
                            uint8_t num_regs_read, cs_regs regs_written,
                            uint8_t num_regs_written);
static void on_block_ctx(GumCpuContext *cpu_context,
                         GumStalkerItransformer *tm);
static gboolean itransformer_try_write_context(GumStalkerItransformer *tm,
                                               GumStalkerIterator *iterator,
                                               GumArm64Writer *cw);
void save_scratch_register(GumArm64Writer *cw, aarch64_reg tm_reg,
                           aarch64_reg reg) {
  gum_arm64_writer_put_str_reg_reg_offset(
      cw, reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, saved_regs) +
          SCRATCH_REG_OFFSET(reg));
};

aarch64_reg allocate_tmp_reg(GumStalkerItransformer *tm) {
  // int reg_idx=-1;
  for (int i = SCRATCH_REG_MAX; i > 0; --i) {
    if (tm->reg_used[i] == VREG_FREE) {
      tm->reg_used[i] = VREG_USED;
      return SCRATCH_REG_BOTTOM + i;
    }
  };
  return AArch64_REG_INVALID;
}
aarch64_reg *allocate_tf_reg(GumStalkerItransformer *tm) {
  for (int i = 0; i != SCRATCH_REG_MAX; i++) {
    if (tm->vir_regs[i] == AArch64_REG_INVALID) {
      aarch64_reg reg = allocate_tmp_reg(tm);
      if (reg == AArch64_REG_INVALID) {
        return NULL;
      }
      tm->vir_regs[i] = reg;
      tm->reg_used[SCRATCH_REG_INDEX(reg)] = i;
      return tm->vir_regs + i;
    }
  }
  return NULL;
};
aarch64_reg aquire_tf_reg(GumStalkerItransformer *tm) {
  tm->vir_regs[0] = SCRATCH_REG_TOP;
  tm->reg_used[SCRATCH_REG_INDEX(SCRATCH_REG_TOP)] = 0;
  gum_arm64_writer_put_ldr_reg_address(tm->cw, SCRATCH_REG_TOP,
                                       GUM_ADDRESS(tm));
  return SCRATCH_REG_TOP;
}

void free_scartch_register(GumStalkerItransformer *tm, aarch64_reg tm_reg,
                           aarch64_reg reg) {
  int idx = SCRATCH_REG_INDEX(reg);
  tm->reg_used[idx] = VREG_FREE;
  gum_arm64_writer_put_ldr_reg_reg_offset(
      tm->cw, reg, tm_reg,
      G_STRUCT_OFFSET(GumStalkerItransformer, saved_regs) +
          SCRATCH_REG_OFFSET(reg));
};
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
void align_up_register(GumArm64Writer *writer, aarch64_reg reg, guint n_bits) {
  // Calculate imms and immr based on the alignment value n
  gum_arm64_writer_put_add_reg_reg_imm(writer, reg, reg, n_bits);
  guint8 immr = 0; // No rotation (rotate right amount is 0)
  guint8 imms = 63 - (n_bits - 1);
  // Generate the UBFM instruction to align the src_reg to n bytes
  gum_arm64_writer_put_ubfm(writer, reg, reg, imms, immr);
}
size_t align_up(size_t x, size_t alignment) {
  // Make sure alignment is a power of two
  return (x + alignment - 1) & ~(alignment - 1);
}
void istalker_save_regs(GumStalkerItransformer *tm, cs_regs regs,
                        uint8_t num_regs, aarch64_reg offest_reg,
                        GumAddress address) {
  GumArm64Writer *cw = tm->cw;
  aarch64_reg tm_reg = tm->vir_regs[VREG_TRANSFROM];
  for (uint8_t i = 0; i != num_regs; i++) {
    aarch64_reg reg = regs[i];
    guint cpu_reg_index = 0;
    aarch64_reg source_reg;
    guint size;
    aarch64_reg temp_reg = AArch64_REG_INVALID;

    if (reg == AArch64_REG_SP) {
      temp_reg = allocate_tmp_reg(tm);
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
      temp_reg = allocate_tmp_reg(tm);

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
    g_array_append_val(tm->block_specs, spec);
    if (tm->reg_val_offset % size != 0) {
      align_up_register(cw, offest_reg, size);
      tm->reg_val_offset = align_up(tm->reg_val_offset, size);
    }
    gum_arm64_writer_put_str_reg_reg(cw, source_reg, offest_reg);
    if (temp_reg != AArch64_REG_INVALID) {
      free_scartch_register(tm, tm_reg, temp_reg);
    }
    tm->reg_val_offset += size;
  }
}

// void gum_istaker_destroy(Itransformer *stalker) {
//   g_object_unref(stalker->modules);
//   gum_free_pages(stalker->buf);
// };
inline gboolean is_control_flow(csh capstone, const cs_insn *insn) {
  return cs_insn_group(capstone, insn, CS_GRP_JUMP) ||
         cs_insn_group(capstone, insn, CS_GRP_RET) ||
         cs_insn_group(capstone, insn, CS_GRP_CALL);
};
// inline void istalker_transform_instr(csh capstone, const cs_insn *insn,
//                                      GumStalkerOutput *output,
//                                      Itransformer *istalker,
//                                      GumStalkerIterator *iterator) {}

inline void istalker_write_bytes(GumStalkerItransformer *istaker, gchar *bytes,
                                 gsize size) {
  memcpy(istaker->buf_offset, bytes, size);
  istaker->buf_offset += size;
}
static void istalker_write_block_compile(GumStalkerItransformer *tm,
                                         ImsgBlockCompile *msg) {
  istalker_write_bytes(tm, (gchar *)msg, sizeof(ImsgBlockCompile));
  istalker_write_bytes(tm, (gchar *)msg->address, msg->size);
  istalker_write_bytes(tm, (gchar *)msg->compiled_address, msg->compiled_size);
  istalker_write_bytes(tm, tm->block_specs->data, tm->block_specs->len);
  g_array_set_size(tm->block_specs, 0);
}
void istalker_write_context(GumStalkerItransformer *istaker, ImsgContext *msg) {
  istalker_write_bytes(istaker, (gchar *)msg, sizeof(ImsgContext));
}

// void itransformer_transform_instr() {};
static gboolean itransformer_try_write_context(GumStalkerItransformer *tm,
                                               GumStalkerIterator *iterator,
                                               GumArm64Writer *cw) {
  // gconstpointer write_label="write";
  gconstpointer not_write_label = "done";
  cw = tm->cw;
  aarch64_reg tm_reg = tm->vir_regs[VREG_TRANSFROM];
  if (tm->dump_context && tm->state == ITRACE_STATE_STARTED) {
    return false;
  }
  aarch64_reg value_reg = allocate_tmp_reg(tm);

  gum_arm64_writer_put_ldr_reg_reg_offset(
      cw, value_reg, tm_reg, G_STRUCT_OFFSET(GumStalkerItransformer, event_id));

  gum_arm64_writer_put_sub_reg_reg_imm(cw, value_reg, value_reg, 1);
  gum_arm64_writer_put_str_reg_reg_offset(
      cw, value_reg, tm_reg, G_STRUCT_OFFSET(GumStalkerItransformer, event_id));
  gum_arm64_writer_put_cbnz_reg_label(cw, value_reg, not_write_label);

  gum_stalker_iterator_put_callout(iterator, on_block_ctx, tm, NULL);
  gum_arm64_writer_put_label(cw, not_write_label);
  free_scartch_register(tm, tm_reg, value_reg);

  return true;
};
static void
gum_stalker_itransformer_transform_block(GumStalkerItransformer *transformer,
                                         GumStalkerIterator *iterator,
                                         GumStalkerOutput *output) {
  const cs_insn *insn;
  transformer->iterator = iterator;
  transformer->cw = output->writer.arm64;

  GumArm64Writer *cw = output->writer.arm64;
  csh cs = gum_stalker_iterator_get_capstone(iterator);
  ImsgBlockCompile msg = {0};
  msg.compiled_address = (GumAddress)gum_arm64_writer_cur(cw);
  gboolean block_done = false;
  GumAddress block_address = 0;
  gsize block_size = 0;

  guint32 instr_count = 1;
  aarch64_reg *offest_vreg = NULL;
  transformer->reg_val_offset = 0;
  guint reg_val_offset_ref = 0;
  while (gum_stalker_iterator_next(iterator, &insn)) {
    if (instr_count == 1) {
      block_address = insn->address;
      aquire_tf_reg(transformer);
      offest_vreg = allocate_tf_reg(transformer);

      aarch64_reg value_reg = allocate_tmp_reg(transformer);
      // TODO
      itransformer_try_write_context(transformer, iterator, cw);
      // ImsgHeader header = {IMSG_BLOCK_EXEC, 4};
      align_up_register(cw, *offest_vreg, 16);
      gum_arm64_writer_put_ldr_reg_u64(cw, value_reg, 0);
      gum_arm64_writer_put_add_reg_reg_imm(cw, value_reg, value_reg,
                                           IMSG_BLOCK_EXEC);
      gum_arm64_writer_put_str_reg_reg(cw, value_reg, *offest_vreg);
      reg_val_offset_ref = gum_arm64_writer_put_ldr_reg_ref(cw, value_reg);
      gum_arm64_writer_put_ldr_reg_u32(cw, value_reg, block_address);
      gum_arm64_writer_put_ldr_reg_u64(cw, value_reg, block_address);
      gum_arm64_writer_put_str_reg_reg(cw, value_reg, *offest_vreg);
      free_scartch_register(transformer, value_reg, value_reg);
    }
    if (is_control_flow(cs, insn)) { // control flow
      aarch64_reg tm_reg = transformer->vir_regs[VREG_TRANSFROM];
      if (tm_reg != SCRATCH_REG_TOP) {
        save_scratch_register(cw, tm_reg, SCRATCH_REG_TOP);
      }
      free_scartch_register(transformer, tm_reg, tm_reg);
      gum_stalker_iterator_keep(iterator);
      block_done = true;
      continue;
    }
    cs_regs regs_read, regs_written;
    uint8_t num_regs_read, num_regs_written;

    regs_access(cs, insn, regs_read, &num_regs_read, regs_written,
                &num_regs_written);
    reslove_regs(transformer, regs_read, num_regs_read, regs_written,
                 num_regs_written);
    gum_stalker_iterator_keep(iterator);
    istalker_save_regs(transformer, regs_written, num_regs_written,
                       *offest_vreg, block_address);
  }
  gum_arm64_writer_put_ldr_reg_value(cw, reg_val_offset_ref,
                                     transformer->reg_val_offset);
  block_size += insn->size;

  msg.address = block_address;
  msg.size = block_size;
  msg.compiled_size = gum_arm64_writer_offset(cw);
  if (block_done) {
    // send block compile message
    // emit_scratch_register_restore(cw)
    // save_scratch_register(cw, , aarch64_reg reg)
    msg.done = true;
  } else {
    msg.done = false;
  };
  istalker_write_block_compile(transformer, &msg); // send message
}

static void on_block_ctx(GumCpuContext *cpu_context,
                         GumStalkerItransformer *tm) {
  ImsgContext *ctx = (ImsgContext *)(tm->buf);
  ctx->type = IMSG_MSG_CONTEXT;
  memcpy(&ctx->cpu_context, cpu_context, sizeof(GumCpuContext));
  tm->event_id = tm->context_interval;
  for (int i = 0; i != SCRATCH_REG_MAX; i++) {
    if (tm->reg_used[i] >= 0) {
      guint idx = i + SCRATCH_REG_BOTTOM - AArch64_REG_X0;
      ctx->cpu_context.x[idx] = tm->saved_regs[i];
    }
  }
  tm->buf_offset += sizeof(ImsgContext);
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
    if (tm->reg_used[SCRATCH_REG_INDEX(reg)] != VREG_FREE) {
      aarch64_reg vreg = tm->reg_used[SCRATCH_REG_INDEX(reg)];
      tm->reg_used[SCRATCH_REG_INDEX(reg)] = VREG_USED;
      to_be_alloc[count++] = vreg;
    }
  }
  return count;
}

// /**
//  * @brief
//  *
//  * @param scratch_regs
//  * @param count scratch registers to picked (less than 8)
//  * @param num_scratch
//  * @param regs_read
//  * @param num_regs_read
//  * @param regs_written
//  * @param num_regs_written
//  * @return uint8_t
//  */
static void reslove_regs(GumStalkerItransformer *tm, cs_regs regs_read,
                            uint8_t num_regs_read, cs_regs regs_written,
                            uint8_t num_regs_written) {

  // pick_scratch_registers(uint16_t *regs_read, uint8_t num_regs_read,
  // *regs_written, uint8_t num_regs_written)
  aarch64_reg *to_be_alloc[SCRATCH_REG_MAX];
  gsize count = 0;
  count += collect_to_be_alloc(tm, regs_read, num_regs_read, to_be_alloc);
  count += collect_to_be_alloc(tm, regs_written, num_regs_written, to_be_alloc);
  for (uint8_t i = 0; i < count; i++) {
    aarch64_reg *vreg = to_be_alloc[i];
    aarch64_reg old_reg = *vreg;
    aarch64_reg new_reg = allocate_tmp_reg(tm);
    gum_arm64_writer_put_mov_reg_reg(tm->cw, new_reg, old_reg);
    free_scartch_register(tm, REG_TRANSFROMER(tm), old_reg);
    bind_vreg(tm, vreg, new_reg);
  }
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
