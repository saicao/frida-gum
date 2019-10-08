/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwinmodule.h"

#ifdef HAVE_DARWIN
# include "backend-darwin/gumdarwin.h"
#endif
#include "gumleb.h"
#include "gumkernel.h"

#include <gio/gio.h>

#define GUM_FAT_CIGAM_32               0xbebafeca
#define GUM_MH_MAGIC_32                0xfeedface
#define GUM_MH_MAGIC_64                0xfeedfacf
#define GUM_MH_EXECUTE                        0x2
#define GUM_MH_PREBOUND                      0x10

#define GUM_LC_REQ_DYLD                0x80000000

#define GUM_SECTION_TYPE_MASK          0x000000ff

#define GUM_N_EXT                            0x01

#define GUM_REBASE_OPCODE_MASK               0xf0
#define GUM_REBASE_IMMEDIATE_MASK            0x0f

#define GUM_BIND_OPCODE_MASK                 0xf0
#define GUM_BIND_IMMEDIATE_MASK              0x0f

#define GUM_BIND_TYPE_POINTER 1

#define GUM_BIND_SPECIAL_DYLIB_SELF             0
#define GUM_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE -1
#define GUM_BIND_SPECIAL_DYLIB_FLAT_LOOKUP     -2

#define MAX_METADATA_SIZE             (64 * 1024)
#ifdef HAVE_DARWIN
# define GUM_MEM_READ(task, addr, len, out_size) \
    (self->is_kernel ? gum_kernel_read (addr, len, out_size) \
      : gum_darwin_read (task, addr, len, out_size))
#else
# define GUM_MEM_READ(task, addr, len, out_size) NULL
#endif

#define GUM_DARWIN_MODULE_HAS_HEADER_ONLY(self) \
    ((self->flags & GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY) != 0)

typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

typedef struct _GumEmitImportContext GumEmitImportContext;
typedef struct _GumEmitExportFromSymbolContext GumEmitExportFromSymbolContext;
typedef struct _GumEmitInitPointersContext GumEmitInitPointersContext;
typedef struct _GumEmitTermPointersContext GumEmitTermPointersContext;

typedef struct _GumExportsTrieForeachContext GumExportsTrieForeachContext;

typedef struct _GumDyldCacheHeader GumDyldCacheHeader;
typedef struct _GumDyldCacheMappingInfo GumDyldCacheMappingInfo;
typedef struct _GumDyldCacheImageInfo GumDyldCacheImageInfo;

typedef struct _GumFatHeader GumFatHeader;
typedef struct _GumFatArch32 GumFatArch32;
typedef struct _GumMachHeader32 GumMachHeader32;
typedef struct _GumMachHeader64 GumMachHeader64;
typedef gint GumDarwinCpuType;
typedef gint GumDarwinCpuSubtype;
typedef struct _GumLoadCommand GumLoadCommand;
typedef union _GumLcStr GumLcStr;
typedef struct _GumSegmentCommand32 GumSegmentCommand32;
typedef struct _GumSegmentCommand64 GumSegmentCommand64;
typedef struct _GumDylibCommand GumDylibCommand;
typedef struct _GumDylinkerCommand GumDylinkerCommand;
typedef struct _GumUUIDCommand GumUUIDCommand;
typedef struct _GumDylib GumDylib;
typedef struct _GumSection32 GumSection32;
typedef struct _GumSection64 GumSection64;
typedef struct _GumNList32 GumNList32;
typedef struct _GumNList64 GumNList64;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_UUID,
  PROP_TASK,
  PROP_CPU_TYPE,
  PROP_PAGE_SIZE,
  PROP_BASE_ADDRESS,
  PROP_SOURCE_PATH,
  PROP_SOURCE_BLOB,
  PROP_CACHE_FILE,
  PROP_FLAGS,
};

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

struct _GumEmitImportContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GumDarwinModule * module;
  gboolean carry_on;
};

struct _GumEmitExportFromSymbolContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;
};

struct _GumEmitInitPointersContext
{
  GumFoundDarwinInitPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumEmitTermPointersContext
{
  GumFoundDarwinTermPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumExportsTrieForeachContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;

  GString * prefix;
  const guint8 * exports;
  const guint8 * exports_end;
};

struct _GumDyldCacheHeader
{
  gchar magic[16];
  guint32 mapping_offset;
  guint32 mapping_count;
  guint32 images_offset;
  guint32 images_count;
};

struct _GumDyldCacheMappingInfo
{
  GumAddress address;
  guint64 size;
  guint64 offset;
  guint32 max_protection;
  guint32 initial_protection;
};

struct _GumDyldCacheImageInfo
{
  GumAddress address;
  guint64 mtime;
  guint64 inode;
  guint32 name_offset;
  guint32 padding;
};

struct _GumFatHeader
{
  guint32 magic;
  guint32 nfat_arch;
};

struct _GumFatArch32
{
  GumDarwinCpuType cputype;
  GumDarwinCpuSubtype cpusubtype;
  guint32 offset;
  guint32 size;
  guint32 align;
};

struct _GumMachHeader32
{
  guint32 magic;
  GumDarwinCpuType cputype;
  GumDarwinCpuSubtype cpusubtype;
  guint32 filetype;
  guint32 ncmds;
  guint32 sizeofcmds;
  guint32 flags;
};

struct _GumMachHeader64
{
  guint32 magic;
  GumDarwinCpuType cputype;
  GumDarwinCpuSubtype cpusubtype;
  guint32 filetype;
  guint32 ncmds;
  guint32 sizeofcmds;
  guint32 flags;
  guint32 reserved;
};

enum _GumDarwinCpuArchType
{
  GUM_DARWIN_CPU_ARCH_ABI64    = 0x01000000,
  GUM_DARWIN_CPU_ARCH_ABI64_32 = 0x02000000,
};

enum _GumDarwinCpuType
{
  GUM_DARWIN_CPU_X86      =  7,
  GUM_DARWIN_CPU_X86_64   =  7 | GUM_DARWIN_CPU_ARCH_ABI64,
  GUM_DARWIN_CPU_ARM      = 12,
  GUM_DARWIN_CPU_ARM64    = 12 | GUM_DARWIN_CPU_ARCH_ABI64,
  GUM_DARWIN_CPU_ARM64_32 = 12 | GUM_DARWIN_CPU_ARCH_ABI64_32,
};

enum _GumLoadCommandType
{
  GUM_LC_SEGMENT_32        = 0x01,
  GUM_LC_SYMTAB            = 0x02,
  GUM_LC_DYSYMTAB          = 0x0b,
  GUM_LC_LOAD_DYLIB        = 0x0c,
  GUM_LC_ID_DYLIB          = 0x0d,
  GUM_LC_ID_DYLINKER       = 0x0f,
  GUM_LC_LOAD_WEAK_DYLIB   = (0x18 | GUM_LC_REQ_DYLD),
  GUM_LC_SEGMENT_64        = 0x19,
  GUM_LC_UUID              = 0x1b,
  GUM_LC_REEXPORT_DYLIB    = (0x1f | GUM_LC_REQ_DYLD),
  GUM_LC_DYLD_INFO_ONLY    = (0x22 | GUM_LC_REQ_DYLD),
  GUM_LC_LOAD_UPWARD_DYLIB = (0x23 | GUM_LC_REQ_DYLD),
};

struct _GumLoadCommand
{
  guint32 cmd;
  guint32 cmdsize;
};

union _GumLcStr
{
  guint32 offset;
};

struct _GumSegmentCommand32
{
  guint32 cmd;
  guint32 cmdsize;

  gchar segname[16];

  guint32 vmaddr;
  guint32 vmsize;

  guint32 fileoff;
  guint32 filesize;

  GumDarwinPageProtection maxprot;
  GumDarwinPageProtection initprot;

  guint32 nsects;

  guint32 flags;
};

struct _GumSegmentCommand64
{
  guint32 cmd;
  guint32 cmdsize;

  gchar segname[16];

  guint64 vmaddr;
  guint64 vmsize;

  guint64 fileoff;
  guint64 filesize;

  GumDarwinPageProtection maxprot;
  GumDarwinPageProtection initprot;

  guint32 nsects;

  guint32 flags;
};

struct _GumDylib
{
  GumLcStr name;
  guint32 timestamp;
  guint32 current_version;
  guint32 compatibility_version;
};

struct _GumDylibCommand
{
  guint32 cmd;
  guint32 cmdsize;

  GumDylib dylib;
};

struct _GumDylinkerCommand
{
  guint32 cmd;
  guint32 cmdsize;

  GumLcStr name;
};

struct _GumUUIDCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint8 uuid[16];
};

struct _GumDyldInfoCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint32 rebase_off;
  guint32 rebase_size;

  guint32 bind_off;
  guint32 bind_size;

  guint32 weak_bind_off;
  guint32 weak_bind_size;

  guint32 lazy_bind_off;
  guint32 lazy_bind_size;

  guint32 export_off;
  guint32 export_size;
};

struct _GumSymtabCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint32 symoff;
  guint32 nsyms;

  guint32 stroff;
  guint32 strsize;
};

struct _GumDysymtabCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint32 ilocalsym;
  guint32 nlocalsym;

  guint32 iextdefsym;
  guint32 nextdefsym;

  guint32 iundefsym;
  guint32 nundefsym;

  guint32 tocoff;
  guint32 ntoc;

  guint32 modtaboff;
  guint32 nmodtab;

  guint32 extrefsymoff;
  guint32 nextrefsyms;

  guint32 indirectsymoff;
  guint32 nindirectsyms;

  guint32 extreloff;
  guint32 nextrel;

  guint32 locreloff;
  guint32 nlocrel;
};

enum _GumSectionType
{
  GUM_S_MOD_INIT_FUNC_POINTERS = 0x9,
  GUM_S_MOD_TERM_FUNC_POINTERS = 0xa,
};

enum _GumSectionAttributes
{
  GUM_S_ATTR_SOME_INSTRUCTIONS = 0x00000400,
  GUM_S_ATTR_PURE_INSTRUCTIONS = 0x80000000,
};

struct _GumSection32
{
  gchar sectname[16];
  gchar segname[16];
  guint32 addr;
  guint32 size;
  guint32 offset;
  guint32 align;
  guint32 reloff;
  guint32 nreloc;
  guint32 flags;
  guint32 reserved1;
  guint32 reserved2;
};

struct _GumSection64
{
  gchar sectname[16];
  gchar segname[16];
  guint64 addr;
  guint64 size;
  guint32 offset;
  guint32 align;
  guint32 reloff;
  guint32 nreloc;
  guint32 flags;
  guint32 reserved1;
  guint32 reserved2;
  guint32 reserved3;
};

struct _GumNList32
{
  guint32 n_strx;
  guint8 n_type;
  guint8 n_sect;
  gint16 n_desc;
  guint32 n_value;
};

struct _GumNList64
{
  guint32 n_strx;
  guint8 n_type;
  guint8 n_sect;
  guint16 n_desc;
  guint64 n_value;
};

enum _GumRebaseOpcode
{
  GUM_REBASE_OPCODE_DONE                               = 0x00,
  GUM_REBASE_OPCODE_SET_TYPE_IMM                       = 0x10,
  GUM_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = 0x20,
  GUM_REBASE_OPCODE_ADD_ADDR_ULEB                      = 0x30,
  GUM_REBASE_OPCODE_ADD_ADDR_IMM_SCALED                = 0x40,
  GUM_REBASE_OPCODE_DO_REBASE_IMM_TIMES                = 0x50,
  GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES               = 0x60,
  GUM_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            = 0x70,
  GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80,
};

enum _GumBindOpcode
{
  GUM_BIND_OPCODE_DONE                                 = 0x00,
  GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM                = 0x10,
  GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB               = 0x20,
  GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM                = 0x30,
  GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM        = 0x40,
  GUM_BIND_OPCODE_SET_TYPE_IMM                         = 0x50,
  GUM_BIND_OPCODE_SET_ADDEND_SLEB                      = 0x60,
  GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB          = 0x70,
  GUM_BIND_OPCODE_ADD_ADDR_ULEB                        = 0x80,
  GUM_BIND_OPCODE_DO_BIND                              = 0x90,
  GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB                = 0xa0,
  GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED          = 0xb0,
  GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB     = 0xc0,
};

enum _GumExportSymbolFlags
{
  GUM_EXPORT_SYMBOL_FLAGS_REEXPORT                     = 0x08,
  GUM_EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER            = 0x10,
};

static void gum_darwin_module_initable_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_darwin_module_constructed (GObject * object);
static gboolean gum_darwin_module_initable_init (GInitable * initable,
    GCancellable * cancellable, GError ** error);
static void gum_darwin_module_finalize (GObject * object);
static void gum_darwin_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_store_address_if_name_matches (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_emit_import (const GumDarwinBindDetails * details,
    gpointer user_data);
static gboolean gum_emit_export_from_symbol (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_emit_section_init_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_term_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_darwin_module_ensure_image_loaded (GumDarwinModule * self,
    GError ** error);
static gboolean gum_darwin_module_try_load_image_from_cache (
    GumDarwinModule * self, const gchar * name, GumCpuType cpu_type,
    GMappedFile * cache_file);
static gboolean gum_darwin_module_load_image_from_filesystem (
    GumDarwinModule * self, const gchar * path, GumCpuType cpu_type,
    GError ** error);
static gboolean gum_darwin_module_load_image_header_from_filesystem (
    GumDarwinModule * self, const gchar * path, GumCpuType cpu_type,
    GError ** error);
static gboolean gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
    GBytes * blob, GError ** error);
static gboolean gum_darwin_module_load_image_from_memory (
    GumDarwinModule * self, GError ** error);
static gboolean gum_darwin_module_take_image (GumDarwinModule * self,
    GumDarwinModuleImage * image, GError ** error);
static gboolean gum_darwin_module_get_header_offset_size (
    GumDarwinModule * self, gpointer data, gsize data_size, gsize * out_offset,
    gsize * out_size, GError ** error);
static void gum_darwin_module_read_and_assign (GumDarwinModule * self,
    GumAddress address, gsize size, const guint8 ** start, const guint8 ** end,
    gpointer * malloc_data);
static gboolean gum_find_linkedit (const guint8 * module, gsize module_size,
    GumAddress * linkedit);
static gboolean gum_add_text_range_if_text_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_section_flags_indicate_text_section (guint32 flags);

static gboolean gum_exports_trie_find (const guint8 * exports,
    const guint8 * exports_end, const gchar * name,
    GumDarwinExportDetails * details);
static gboolean gum_exports_trie_foreach (const guint8 * exports,
    const guint8 * exports_end, GumFoundDarwinExportFunc func,
    gpointer user_data);
static gboolean gum_exports_trie_traverse (const guint8 * p,
    GumExportsTrieForeachContext * ctx);

static void gum_darwin_export_details_init_from_node (
    GumDarwinExportDetails * details, const gchar * name, const guint8 * node,
    const guint8 * exports_end);

static const GumDyldCacheImageInfo * gum_dyld_cache_find_image_by_name (
    const gchar * name, const GumDyldCacheImageInfo * images, gsize image_count,
    gconstpointer cache);
static guint64 gum_dyld_cache_compute_image_size (
    const GumDyldCacheImageInfo * image, const GumDyldCacheImageInfo * images,
    gsize image_count);
static guint64 gum_dyld_cache_offset_from_address (GumAddress address,
    const GumDyldCacheMappingInfo * mappings, gsize mapping_count);

G_DEFINE_TYPE_EXTENDED (GumDarwinModule,
                        gum_darwin_module,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                            gum_darwin_module_initable_iface_init))

static void
gum_darwin_module_class_init (GumDarwinModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_module_constructed;
  object_class->finalize = gum_darwin_module_finalize;
  object_class->get_property = gum_darwin_module_get_property;
  object_class->set_property = gum_darwin_module_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_UUID,
      g_param_spec_string ("uuid", "UUID", "UUID", NULL,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "Task", "Mach task", 0, G_MAXUINT,
      GUM_DARWIN_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CPU_TYPE,
      g_param_spec_uint ("cpu-type", "CpuType", "CPU type", 0, G_MAXUINT,
      GUM_CPU_INVALID, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PAGE_SIZE,
      g_param_spec_uint ("page-size", "PageSize", "Page size", 0, G_MAXUINT,
      0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "BaseAddress", "Base address", 0,
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_PATH,
      g_param_spec_string ("source-path", "SourcePath", "Source path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_BLOB,
      g_param_spec_boxed ("source-blob", "SourceBlob", "Source blob",
      G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CACHE_FILE,
      g_param_spec_boxed ("cache-file", "CacheFile", "Cache file used by dyld",
      G_TYPE_MAPPED_FILE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FLAGS,
      g_param_spec_flags ("flags", "Flags", "Optional flags",
      GUM_TYPE_DARWIN_MODULE_FLAGS, GUM_DARWIN_MODULE_FLAGS_NONE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_module_initable_iface_init (gpointer g_iface,
                                       gpointer iface_data)
{
  GInitableIface * iface = g_iface;

  iface->init = gum_darwin_module_initable_init;
}

static void
gum_darwin_module_init (GumDarwinModule * self)
{
  self->segments = g_array_new (FALSE, FALSE, sizeof (GumDarwinSegment));
  self->text_ranges = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->dependencies = g_ptr_array_sized_new (5);
  self->reexports = g_ptr_array_sized_new (5);
}

static void
gum_darwin_module_constructed (GObject * object)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

#ifdef HAVE_DARWIN
  if (self->task != GUM_DARWIN_PORT_NULL)
  {
    self->is_local = self->task == mach_task_self ();
    self->is_kernel = self->task == gum_kernel_get_task ();
  }

  if (self->cpu_type == GUM_CPU_INVALID)
  {
    int pid;

    if (self->task == GUM_DARWIN_PORT_NULL ||
        pid_for_task (self->task, &pid) != KERN_SUCCESS ||
        !gum_darwin_cpu_type_from_pid (pid, &self->cpu_type))
    {
      self->cpu_type = GUM_NATIVE_CPU;
    }
  }
#else
  if (self->cpu_type == GUM_CPU_INVALID)
    self->cpu_type = GUM_NATIVE_CPU;
#endif

  switch (self->cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_ARM:
      self->pointer_size = 4;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      self->pointer_size = 8;
      break;
    default:
      g_assert_not_reached ();
  }

  if (self->page_size == 0)
  {
#ifdef HAVE_DARWIN
    if (self->is_local)
    {
      self->page_size = gum_query_page_size ();
    }
    else
    {
      guint page_size = 4096;

      gum_darwin_query_page_size (self->task, &page_size);

      self->page_size = page_size;
    }
#else
    self->page_size = 4096;
#endif
  }
}

static gboolean
gum_darwin_module_initable_init (GInitable * initable,
                                 GCancellable * cancellable,
                                 GError ** error)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (initable);

  if (self->source_path != NULL)
  {
    if (self->cache_file == NULL ||
        !gum_darwin_module_try_load_image_from_cache (self, self->source_path,
        self->cpu_type, self->cache_file))
    {
      if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self))
      {
        if (!gum_darwin_module_load_image_header_from_filesystem (self,
            self->source_path, self->cpu_type, error))
        {
          return FALSE;
        }
      }
      else
      {
        if (!gum_darwin_module_load_image_from_filesystem (self,
            self->source_path, self->cpu_type, error))
        {
          return FALSE;
        }
      }
    }
  }
  else if (self->source_blob != NULL)
  {
    if (!gum_darwin_module_load_image_from_blob (self, self->source_blob,
        error))
    {
      return FALSE;
    }
  }

  if (self->name == NULL)
    return gum_darwin_module_ensure_image_loaded (self, error);

  return TRUE;
}

static void
gum_darwin_module_finalize (GObject * object)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  g_ptr_array_unref (self->dependencies);
  g_ptr_array_unref (self->reexports);

  g_free (self->rebases_malloc_data);
  g_free (self->binds_malloc_data);
  g_free (self->lazy_binds_malloc_data);
  g_free (self->exports_malloc_data);

  g_array_unref (self->segments);
  g_array_unref (self->text_ranges);

  if (self->image != NULL)
    gum_darwin_module_image_free (self->image);

  g_free (self->source_path);
  g_bytes_unref (self->source_blob);
  if (self->cache_file != NULL)
    g_mapped_file_unref (self->cache_file);

  g_free (self->name);
  g_free (self->uuid);

  G_OBJECT_CLASS (gum_darwin_module_parent_class)->finalize (object);
}

static void
gum_darwin_module_get_property (GObject * object,
                                guint property_id,
                                GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_UUID:
      if (self->uuid == NULL)
        gum_darwin_module_ensure_image_loaded (self, NULL);
      g_value_set_string (value, self->uuid);
      break;
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    case PROP_CPU_TYPE:
      g_value_set_uint (value, self->cpu_type);
      break;
    case PROP_PAGE_SIZE:
      g_value_set_uint (value, self->page_size);
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, self->base_address);
      break;
    case PROP_SOURCE_PATH:
      g_value_set_string (value, self->source_path);
      break;
    case PROP_SOURCE_BLOB:
      g_value_set_boxed (value, self->source_blob);
      break;
    case PROP_CACHE_FILE:
      g_value_set_boxed (value, self->cache_file);
      break;
    case PROP_FLAGS:
      g_value_set_flags (value, self->flags);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_module_set_property (GObject * object,
                                guint property_id,
                                const GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    case PROP_CPU_TYPE:
      self->cpu_type = g_value_get_uint (value);
      break;
    case PROP_PAGE_SIZE:
      self->page_size = g_value_get_uint (value);
      break;
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    case PROP_SOURCE_PATH:
      g_free (self->source_path);
      self->source_path = g_value_dup_string (value);
      break;
    case PROP_SOURCE_BLOB:
      g_clear_pointer (&self->source_blob, g_bytes_unref);
      self->source_blob = g_value_dup_boxed (value);
      break;
    case PROP_CACHE_FILE:
      g_clear_pointer (&self->cache_file, g_mapped_file_unref);
      self->cache_file = g_value_dup_boxed (value);
      break;
    case PROP_FLAGS:
      self->flags = g_value_get_flags (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinModule *
gum_darwin_module_new_from_file (const gchar * path,
                                 GumDarwinPort task,
                                 GumCpuType cpu_type,
                                 guint page_size,
                                 GMappedFile * cache_file,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  return g_initable_new (GUM_TYPE_DARWIN_MODULE, NULL, error,
      "task", task,
      "cpu-type", cpu_type,
      "page-size", page_size,
      "source-path", path,
      "cache-file", cache_file,
      "flags", flags,
      NULL);
}

GumDarwinModule *
gum_darwin_module_new_from_blob (GBytes * blob,
                                 GumDarwinPort task,
                                 GumCpuType cpu_type,
                                 guint page_size,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  return g_initable_new (GUM_TYPE_DARWIN_MODULE, NULL, error,
      "task", task,
      "cpu-type", cpu_type,
      "page-size", page_size,
      "source-blob", blob,
      "flags", flags,
      NULL);
}

GumDarwinModule *
gum_darwin_module_new_from_memory (const gchar * name,
                                   GumDarwinPort task,
                                   GumCpuType cpu_type,
                                   guint page_size,
                                   GumAddress base_address,
                                   GumDarwinModuleFlags flags,
                                   GError ** error)
{
  return g_initable_new (GUM_TYPE_DARWIN_MODULE, NULL, error,
      "name", name,
      "task", task,
      "cpu-type", cpu_type,
      "page-size", page_size,
      "base-address", base_address,
      "flags", flags,
      NULL);
}

gboolean
gum_darwin_module_resolve_export (GumDarwinModule * self,
                                  const gchar * name,
                                  GumDarwinExportDetails * details)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  if (self->exports != NULL)
  {
    return gum_exports_trie_find (self->exports, self->exports_end, name,
        details);
  }
  else
  {
    GumAddress address;

    address = gum_darwin_module_resolve_symbol_address (self, name);
    if (address == 0)
      return FALSE;

    details->name = name;
    details->flags = GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE;
    details->offset = address;

    return TRUE;
  }
}

GumAddress
gum_darwin_module_resolve_symbol_address (GumDarwinModule * self,
                                          const gchar * name)
{
  GumResolveSymbolContext ctx;

  ctx.name = name;
  ctx.result = 0;

  gum_darwin_module_enumerate_symbols (self, gum_store_address_if_name_matches,
      &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumDarwinSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}

gboolean
gum_darwin_module_get_lacks_exports_for_reexports (GumDarwinModule * self)
{
  guint32 flags;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  /*
   * FIXME: There must be a better way to detect this behavioral change
   *        introduced in macOS 10.11 and iOS 9.0, but this will have to
   *        do for now.
   */
  flags = ((GumMachHeader32 *) self->image->data)->flags;

  return (flags & GUM_MH_PREBOUND) == 0;
}

void
gum_darwin_module_enumerate_imports (GumDarwinModule * self,
                                     GumFoundImportFunc func,
                                     gpointer user_data)
{
  GumEmitImportContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.module = self;
  ctx.carry_on = TRUE;
  gum_darwin_module_enumerate_binds (self, gum_emit_import, &ctx);
  if (ctx.carry_on)
    gum_darwin_module_enumerate_lazy_binds (self, gum_emit_import, &ctx);
}

static gboolean
gum_emit_import (const GumDarwinBindDetails * details,
                 gpointer user_data)
{
  GumEmitImportContext * ctx = user_data;
  GumImportDetails d;

  d.type = GUM_IMPORT_UNKNOWN;
  d.name = details->symbol_name;
  switch (details->library_ordinal)
  {
    case GUM_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
    case GUM_BIND_SPECIAL_DYLIB_SELF:
      return TRUE;
    case GUM_BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
    {
      d.module = NULL;
      break;
    }
    default:
      d.module = gum_darwin_module_get_dependency_by_ordinal (ctx->module,
          details->library_ordinal);
      break;
  }
  d.address = 0;

  if (details->segment != NULL)
  {
    d.slot = details->offset + details->segment->vm_address +
        gum_darwin_module_get_slide (ctx->module);
  }
  else
  {
    d.slot = 0;
  }

  ctx->carry_on = ctx->func (&d, ctx->user_data);

  return ctx->carry_on;
}

void
gum_darwin_module_enumerate_exports (GumDarwinModule * self,
                                     GumFoundDarwinExportFunc func,
                                     gpointer user_data)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  if (self->exports != NULL)
  {
    gum_exports_trie_foreach (self->exports, self->exports_end, func,
        user_data);
  }
  else
  {
    GumEmitExportFromSymbolContext ctx;

    ctx.func = func;
    ctx.user_data = user_data;

    gum_darwin_module_enumerate_symbols (self, gum_emit_export_from_symbol,
        &ctx);
  }
}

static gboolean
gum_emit_export_from_symbol (const GumDarwinSymbolDetails * details,
                             gpointer user_data)
{
  GumEmitExportFromSymbolContext * ctx = user_data;
  GumDarwinExportDetails d;

  if ((details->type & GUM_N_EXT) == 0)
    return TRUE;

  d.name = details->name;
  d.flags = GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE;
  d.offset = details->address;

  return ctx->func (&d, ctx->user_data);
}

void
gum_darwin_module_enumerate_symbols (GumDarwinModule * self,
                                     GumFoundDarwinSymbolFunc func,
                                     gpointer user_data)
{
  GumDarwinModuleImage * image;
  const GumSymtabCommand * symtab;
  gsize symbol_size;
  GumAddress slide;
  guint8 * symbols = NULL;
  gchar * strings = NULL;
  gsize symbol_index;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    goto beach;
  }

  image = self->image;

  symtab = self->symtab;
  if (symtab == NULL)
    goto beach;

  symbol_size = (self->pointer_size == 8)
      ? sizeof (GumNList64)
      : sizeof (GumNList32);

  slide = gum_darwin_module_get_slide (self);

  if (self->task != GUM_DARWIN_PORT_NULL)
  {
    GumAddress linkedit;

    if (!gum_find_linkedit (image->data, image->size, &linkedit))
      goto beach;
    linkedit += slide;

    symbols = GUM_MEM_READ (self->task, linkedit + symtab->symoff,
        symtab->nsyms * symbol_size, NULL);
    strings = (gchar *) GUM_MEM_READ (self->task, linkedit + symtab->stroff,
        symtab->strsize, NULL);
    if (symbols == NULL || strings == NULL)
      goto beach;
  }
  else
  {
    symbols = (guint8 *) image->linkedit + symtab->symoff;
    strings = (gchar *) image->linkedit + symtab->stroff;
  }

  for (symbol_index = 0; symbol_index != symtab->nsyms; symbol_index++)
  {
    GumDarwinSymbolDetails details;
    gboolean carry_on;

    if (self->pointer_size == 8)
    {
      GumNList64 * symbol;

      symbol = (GumNList64 *) (symbols + (symbol_index * sizeof (GumNList64)));

      details.name = strings + symbol->n_strx;
      details.address = (symbol->n_value != 0) ? symbol->n_value + slide : 0;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }
    else
    {
      GumNList32 * symbol;

      symbol = (GumNList32 *) (symbols + (symbol_index * sizeof (GumNList32)));

      details.name = strings + symbol->n_strx;
      details.address = (symbol->n_value != 0) ? symbol->n_value + slide : 0;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }

    carry_on = func (&details, user_data);
    if (!carry_on)
      goto beach;
  }

beach:
  if (self->task != GUM_DARWIN_PORT_NULL)
  {
    g_free (strings);
    g_free (symbols);
  }
}

GumAddress
gum_darwin_module_get_slide (GumDarwinModule * self)
{
  return self->base_address - self->preferred_address;
}

const GumDarwinSegment *
gum_darwin_module_get_nth_segment (GumDarwinModule * self,
                                   gsize index)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return NULL;

  return &g_array_index (self->segments, GumDarwinSegment, index);
}

void
gum_darwin_module_enumerate_sections (GumDarwinModule * self,
                                      GumFoundDarwinSectionFunc func,
                                      gpointer user_data)
{
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;
  GumAddress slide;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  header = (GumMachHeader32 *) self->image->data;
  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) self->image->data + 1;
  else
    command = (GumMachHeader64 *) self->image->data + 1;
  slide = gum_darwin_module_get_slide (self);
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = command;

    if (lc->cmd == GUM_LC_SEGMENT_32 || lc->cmd == GUM_LC_SEGMENT_64)
    {
      GumDarwinSectionDetails details;
      const guint8 * sections;
      gsize section_count, section_index;

      if (lc->cmd == GUM_LC_SEGMENT_32)
      {
        const GumSegmentCommand32 * sc = command;

        details.protection = sc->initprot;

        sections = (const guint8 *) (sc + 1);
        section_count = sc->nsects;
      }
      else
      {
        const GumSegmentCommand64 * sc = command;

        details.protection = sc->initprot;

        sections = (const guint8 *) (sc + 1);
        section_count = sc->nsects;
      }

      for (section_index = 0; section_index != section_count; section_index++)
      {
        if (lc->cmd == GUM_LC_SEGMENT_32)
        {
          const GumSection32 * s =
              (const GumSection32 *) sections + section_index;

          g_strlcpy (details.segment_name, s->segname,
              sizeof (details.segment_name));
          g_strlcpy (details.section_name, s->sectname,
              sizeof (details.section_name));

          details.vm_address = s->addr + (guint32) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }
        else
        {
          const GumSection64 * s =
              (const GumSection64 *) sections + section_index;

          g_strlcpy (details.segment_name, s->segname,
              sizeof (details.segment_name));
          g_strlcpy (details.section_name, s->sectname,
              sizeof (details.section_name));

          details.vm_address = s->addr + (guint64) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }

        if (!func (&details, user_data))
          return;
      }
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

gboolean
gum_darwin_module_is_address_in_text_section (GumDarwinModule * self,
                                              GumAddress address)
{
  guint i;

  for (i = 0; i != self->text_ranges->len; i++)
  {
    GumMemoryRange * r = &g_array_index (self->text_ranges, GumMemoryRange, i);
    if (GUM_MEMORY_RANGE_INCLUDES (r, address))
      return TRUE;
  }

  return FALSE;
}

void
gum_darwin_module_enumerate_rebases (GumDarwinModule * self,
                                     GumFoundDarwinRebaseFunc func,
                                     gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinRebaseDetails details;
  guint64 max_offset;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->rebases;
  end = self->rebases_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.slide = gum_darwin_module_get_slide (self);

  max_offset = details.segment->file_size;

  while (!done && p != end)
  {
    guint8 opcode = *p & GUM_REBASE_OPCODE_MASK;
    guint8 immediate = *p & GUM_REBASE_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_REBASE_OPCODE_DONE:
        done = TRUE;
        break;
      case GUM_REBASE_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        details.offset = gum_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case GUM_REBASE_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        details.offset += immediate * self->pointer_size;
        break;
      case GUM_REBASE_OPCODE_DO_REBASE_IMM_TIMES:
      {
        guint8 i;

        for (i = 0; i != immediate; i++)
        {
          g_assert (details.offset < max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
      {
        guint64 count, i;

        count = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; i++)
        {
          g_assert (details.offset < max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case GUM_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        g_assert (details.offset < max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
      {
        gsize count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert (details.offset < max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      default:
        g_assert_not_reached ();
        break;
    }
  }
}

void
gum_darwin_module_enumerate_binds (GumDarwinModule * self,
                                   GumFoundDarwinBindFunc func,
                                   gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinBindDetails details;
  guint64 max_offset;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->binds;
  end = self->binds_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  max_offset = details.segment->file_size;

  while (!done && p != end)
  {
    guint8 opcode = *p & GUM_BIND_OPCODE_MASK;
    guint8 immediate = *p & GUM_BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_BIND_OPCODE_DONE:
        done = TRUE;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        details.offset = gum_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        g_assert (details.offset < max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        g_assert (details.offset < max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        g_assert (details.offset < max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + (immediate * self->pointer_size);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        guint64 count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert (details.offset < max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      default:
        g_assert_not_reached ();
        break;
    }
  }
}

void
gum_darwin_module_enumerate_lazy_binds (GumDarwinModule * self,
                                        GumFoundDarwinBindFunc func,
                                        gpointer user_data)
{
  const guint8 * start, * end, * p;
  GumDarwinBindDetails details;
  guint64 max_offset;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->lazy_binds;
  end = self->lazy_binds_end;
  p = start;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = GUM_DARWIN_BIND_POINTER;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  max_offset = details.segment->file_size;

  while (p != end)
  {
    guint8 opcode = *p & GUM_BIND_OPCODE_MASK;
    guint8 immediate = *p & GUM_BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_BIND_OPCODE_DONE:
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        details.offset = gum_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        g_assert (details.offset < max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      default:
        g_assert_not_reached ();
        break;
    }
  }
}

void
gum_darwin_module_enumerate_init_pointers (GumDarwinModule * self,
                                           GumFoundDarwinInitPointersFunc func,
                                           gpointer user_data)
{
  GumEmitInitPointersContext ctx;
  ctx.func = func;
  ctx.user_data = user_data;
  ctx.pointer_size = self->pointer_size;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_init_pointers,
      &ctx);
}

void
gum_darwin_module_enumerate_term_pointers (GumDarwinModule * self,
                                           GumFoundDarwinTermPointersFunc func,
                                           gpointer user_data)
{
  GumEmitTermPointersContext ctx;
  ctx.func = func;
  ctx.user_data = user_data;
  ctx.pointer_size = self->pointer_size;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_term_pointers,
      &ctx);
}

static gboolean
gum_emit_section_init_pointers (const GumDarwinSectionDetails * details,
                                gpointer user_data)
{
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_MOD_INIT_FUNC_POINTERS)
  {
    GumEmitInitPointersContext * ctx = user_data;
    GumDarwinInitPointersDetails d;
    d.address = details->vm_address;
    d.count = details->size / ctx->pointer_size;
    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

static gboolean
gum_emit_section_term_pointers (const GumDarwinSectionDetails * details,
                                gpointer user_data)
{
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_MOD_TERM_FUNC_POINTERS)
  {
    GumEmitTermPointersContext * ctx = user_data;
    GumDarwinTermPointersDetails d;
    d.address = details->vm_address;
    d.count = details->size / ctx->pointer_size;
    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

void
gum_darwin_module_enumerate_dependencies (GumDarwinModule * self,
                                          GumFoundDarwinDependencyFunc func,
                                          gpointer user_data)
{
  guint i;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  for (i = 0; i < self->dependencies->len; i++)
  {
    const gchar * path;

    path = g_ptr_array_index (self->dependencies, i);
    if (path == NULL)
      continue;

    if (!func (path, user_data))
      return;
  }
}

const gchar *
gum_darwin_module_get_dependency_by_ordinal (GumDarwinModule * self,
                                             gint ordinal)
{
  gint i = ordinal - 1;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return NULL;

  if (i < 0 || i >= (gint) self->dependencies->len)
    return NULL;

  return g_ptr_array_index (self->dependencies, i);
}

static gboolean
gum_darwin_module_ensure_image_loaded (GumDarwinModule * self,
                                       GError ** error)
{
  if (self->image != NULL)
    return TRUE;

  return gum_darwin_module_load_image_from_memory (self, error);
}

static gboolean
gum_darwin_module_try_load_image_from_cache (GumDarwinModule * self,
                                             const gchar * name,
                                             GumCpuType cpu_type,
                                             GMappedFile * cache_file)
{
  guint8 * cache;
  const GumDyldCacheHeader * header;
  const GumDyldCacheImageInfo * images, * image;
  const GumDyldCacheMappingInfo * mappings, * first_mapping, * second_mapping,
      * last_mapping, * mapping;
  guint64 image_offset, image_size;
  GumDarwinModuleImage * module_image;
  gboolean success;

  cache = (guint8 *) g_mapped_file_get_contents (cache_file);
  g_assert (cache != NULL);

  header = (GumDyldCacheHeader *) cache;
  images = (GumDyldCacheImageInfo *) (cache + header->images_offset);
  mappings = (GumDyldCacheMappingInfo *) (cache + header->mapping_offset);
  first_mapping = &mappings[0];
  second_mapping = &mappings[1];
  last_mapping = &mappings[header->mapping_count - 1];

  image = gum_dyld_cache_find_image_by_name (name, images,
      header->images_count, cache);
  if (image == NULL)
    return FALSE;

  image_offset = gum_dyld_cache_offset_from_address (image->address, mappings,
      header->mapping_count);
  image_size = gum_dyld_cache_compute_image_size (image, images,
      header->images_count);

  g_assert (image_offset >= first_mapping->offset);
  g_assert (image_offset < first_mapping->offset + first_mapping->size);

  module_image = gum_darwin_module_image_new ();

  module_image->source_offset = image_offset;
  module_image->source_size = image_size;
  module_image->shared_offset = second_mapping->offset - image_offset;
  module_image->shared_size = (last_mapping->offset + last_mapping->size) -
      second_mapping->offset;
  for (mapping = second_mapping; mapping != last_mapping + 1; mapping++)
  {
    GumDarwinModuleImageSegment segment;
    segment.offset = module_image->shared_offset + (mapping->offset -
        second_mapping->offset);
    segment.size = mapping->size;
    segment.protection = mapping->initial_protection;
    g_array_append_val (module_image->shared_segments, segment);
  }

  module_image->data = cache + image_offset;
  module_image->size = module_image->shared_offset +
      module_image->shared_size;
  module_image->linkedit = cache;

  module_image->bytes = g_mapped_file_get_bytes (cache_file);

  success = gum_darwin_module_take_image (self, module_image, NULL);
  g_assert (success);

  return TRUE;
}

static gboolean
gum_darwin_module_load_image_from_filesystem (GumDarwinModule * self,
                                              const gchar * path,
                                              GumCpuType cpu_type,
                                              GError ** error)
{
  gboolean success;
  GMappedFile * file;
  gsize size, size_in_pages, page_size;
  gpointer data;
  GBytes * blob;

  file = g_mapped_file_new (path, FALSE, error);
  if (file == NULL)
    return FALSE;

  size = g_mapped_file_get_length (file);
  page_size = gum_query_page_size ();
  size_in_pages = size / page_size;
  if (size % page_size != 0)
    size_in_pages++;

  data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  memcpy (data, g_mapped_file_get_contents (file), size);

  g_clear_pointer (&file, g_mapped_file_unref);

  blob = g_bytes_new_with_free_func (data, size, gum_free_pages, data);

  success = gum_darwin_module_load_image_from_blob (self, blob, error);

  g_bytes_unref (blob);

  return success;
}

static gboolean
gum_darwin_module_load_image_header_from_filesystem (GumDarwinModule * self,
                                                     const gchar * path,
                                                     GumCpuType cpu_type,
                                                     GError ** error)
{
  gboolean success;
  GMappedFile * file;
  gsize page_size, size, size_in_pages;
  gpointer data;
  GBytes * blob;
  gsize header_size, cursor;
  gboolean is_fat;

  file = g_mapped_file_new (path, FALSE, error);
  if (file == NULL)
    return FALSE;

  page_size = gum_query_page_size ();
  data = gum_alloc_n_pages (1, GUM_PAGE_RW);
  size = page_size;

  cursor = 0;
  do
  {
    gsize header_offset;

    memcpy (data, g_mapped_file_get_contents (file) + cursor, size);
    if (!gum_darwin_module_get_header_offset_size (self, data, size,
        &header_offset, &header_size, error))
    {
      gum_free_pages (data);
      g_clear_pointer (&file, g_mapped_file_unref);
      return FALSE;
    }

    cursor += header_offset;
    is_fat = header_offset > 0;
  }
  while (is_fat);

  size_in_pages = header_size / page_size;
  if (header_size % page_size != 0)
    size_in_pages++;

  if (size_in_pages != 1)
  {
    gum_free_pages (data);
    data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  }

  memcpy (data, g_mapped_file_get_contents (file) + cursor, header_size);

  g_clear_pointer (&file, g_mapped_file_unref);

  blob = g_bytes_new_with_free_func (data, header_size, gum_free_pages, data);

  success = gum_darwin_module_load_image_from_blob (self, blob, error);

  g_bytes_unref (blob);

  return success;
}

static gboolean
gum_darwin_module_get_header_offset_size (GumDarwinModule * self,
                                          gpointer data,
                                          gsize data_size,
                                          gsize * out_offset,
                                          gsize * out_size,
                                          GError ** error)
{
  GumFatHeader * fat_header;
  GumMachHeader32 * header_32 = NULL;
  GumMachHeader64 * header_64 = NULL;
  gboolean found = FALSE;
  gpointer data_end;

  data_end = (guint8 *) data + data_size;
  fat_header = data;

  switch (fat_header->magic)
  {
    case GUM_FAT_CIGAM_32:
    {
      guint32 count, i;

      count = GUINT32_FROM_BE (fat_header->nfat_arch);
      for (i = 0; i != count && !found; i++)
      {
        guint32 offset, cpu_type;

        GumFatArch32 * fat_arch = ((GumFatArch32 *) (fat_header + 1)) + i;
        if ((gpointer) (fat_arch + 1) > data_end)
          goto invalid_blob;

        offset = GUINT32_FROM_BE (fat_arch->offset);
        cpu_type = GUINT32_FROM_BE (fat_arch->cputype);

        *out_offset = offset;
        switch (cpu_type)
        {
          case GUM_DARWIN_CPU_ARM:
          case GUM_DARWIN_CPU_X86:
            *out_size = sizeof (GumMachHeader32);
            found = self->cpu_type == GUM_CPU_ARM ||
                self->cpu_type == GUM_CPU_IA32;
            break;
          case GUM_DARWIN_CPU_ARM64:
          case GUM_DARWIN_CPU_X86_64:
            *out_size = sizeof (GumMachHeader64);
            found = self->cpu_type == GUM_CPU_ARM64 ||
                self->cpu_type == GUM_CPU_AMD64;
            break;
          default:
            goto invalid_blob;
        }
      }

      break;
    }
    case GUM_MH_MAGIC_32:
      header_32 = data;
      if ((gpointer) (header_32 + 1) > data_end)
        goto invalid_blob;

      *out_offset = 0;
      *out_size = sizeof (GumMachHeader32) + header_32->sizeofcmds;

      found = self->cpu_type == GUM_CPU_ARM ||
          self->cpu_type == GUM_CPU_IA32;

      break;
    case GUM_MH_MAGIC_64:
      header_64 = data;
      if ((gpointer) (header_64 + 1) > data_end)
        goto invalid_blob;

      *out_offset = 0;
      *out_size = sizeof (GumMachHeader64) + header_64->sizeofcmds;

      found = self->cpu_type == GUM_CPU_ARM64 ||
          self->cpu_type == GUM_CPU_AMD64;

      break;
    default:
      goto invalid_blob;
  }

  if (!found)
    goto invalid_blob;

  return TRUE;

invalid_blob:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
                                        GBytes * blob,
                                        GError ** error)
{
  GumDarwinModuleImage * image;
  gpointer blob_data;
  gsize blob_size;
  GumFatHeader * fat_header;
  GumMachHeader32 * header_32 = NULL;
  GumMachHeader64 * header_64 = NULL;
  gsize size_32 = 0;
  gsize size_64 = 0;

  image = gum_darwin_module_image_new ();
  image->bytes = g_bytes_ref (blob);

  blob_data = (gpointer) g_bytes_get_data (blob, &blob_size);

  fat_header = blob_data;
  switch (fat_header->magic)
  {
    case GUM_FAT_CIGAM_32:
    {
      guint32 count, i;

      count = GUINT32_FROM_BE (fat_header->nfat_arch);
      for (i = 0; i != count; i++)
      {
        GumFatArch32 * fat_arch = ((GumFatArch32 *) (fat_header + 1)) + i;
        gpointer mach_header = (guint8 *) blob_data +
            GUINT32_FROM_BE (fat_arch->offset);
        switch (((GumMachHeader32 *) mach_header)->magic)
        {
          case GUM_MH_MAGIC_32:
            header_32 = mach_header;
            size_32 = GUINT32_FROM_BE (fat_arch->size);
            break;
          case GUM_MH_MAGIC_64:
            header_64 = mach_header;
            size_64 = GUINT32_FROM_BE (fat_arch->size);
            break;
          default:
            goto invalid_blob;
        }
      }

      break;
    }
    case GUM_MH_MAGIC_32:
      header_32 = blob_data;
      size_32 = blob_size;
      break;
    case GUM_MH_MAGIC_64:
      header_64 = blob_data;
      size_64 = blob_size;
      break;
    default:
      goto invalid_blob;
  }

  switch (self->cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_ARM:
      g_assert (header_32 != NULL);
      image->data = header_32;
      image->size = size_32;
      image->linkedit = header_32;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      g_assert (header_64 != NULL);
      image->data = header_64;
      image->size = size_64;
      image->linkedit = header_64;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  return gum_darwin_module_take_image (self, image, error);

invalid_blob:
  {
    gum_darwin_module_image_free (image);

    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_load_image_from_memory (GumDarwinModule * self,
                                          GError ** error)
{
  gpointer data, malloc_data;
  gsize data_size;
  GumDarwinModuleImage * image;

  g_assert (self->base_address != 0);

  if (self->is_local)
  {
    data = GSIZE_TO_POINTER (self->base_address);
    data_size = MAX_METADATA_SIZE;
    malloc_data = NULL;
  }
  else
  {
    data_size = 0;
    data = GUM_MEM_READ (self->task, self->base_address,
        MAX_METADATA_SIZE, &data_size);
    if (data == NULL)
      return FALSE;
    malloc_data = data;
  }

  image = gum_darwin_module_image_new ();

  image->data = data;
  image->size = data_size;

  image->malloc_data = malloc_data;

  return gum_darwin_module_take_image (self, image, error);
}

static gboolean
gum_darwin_module_take_image (GumDarwinModule * self,
                              GumDarwinModuleImage * image,
                              GError ** error)
{
  gboolean success = FALSE;
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;

  g_assert (self->image == NULL);
  self->image = image;

  header = (GumMachHeader32 *) image->data;
  if (header->filetype == GUM_MH_EXECUTE)
    self->name = g_strdup ("Executable");
  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) image->data + 1;
  else
    command = (GumMachHeader64 *) image->data + 1;
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = (GumLoadCommand *) command;

    switch (lc->cmd)
    {
      case GUM_LC_ID_DYLIB:
      {
        if (self->name == NULL)
        {
          const GumDylib * dl = &((GumDylibCommand *) lc)->dylib;
          const gchar * raw_path;
          guint raw_path_len;

          raw_path = (const gchar *) command + dl->name.offset;
          raw_path_len = lc->cmdsize - sizeof (GumDylibCommand);

          self->name = g_strndup (raw_path, raw_path_len);
        }

        break;
      }
      case GUM_LC_ID_DYLINKER:
      {
        if (self->name == NULL)
        {
          const GumDylinkerCommand * dl = (const GumDylinkerCommand *) lc;
          const gchar * raw_path;
          guint raw_path_len;

          raw_path = (const gchar *) command + dl->name.offset;
          raw_path_len = lc->cmdsize - sizeof (GumDylinkerCommand);

          self->name = g_strndup (raw_path, raw_path_len);
        }

        break;
      }
      case GUM_LC_UUID:
      {
        if (self->uuid == NULL)
        {
          const GumUUIDCommand * uc = command;
          const uint8_t * u = uc->uuid;

          self->uuid = g_strdup_printf ("%02X%02X%02X%02X-%02X%02X-%02X%02X-"
              "%02X%02X-%02X%02X%02X%02X%02X%02X", u[0], u[1], u[2], u[3],
              u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
              u[14], u[15]);
        }

        break;
      }
      case GUM_LC_SEGMENT_32:
      case GUM_LC_SEGMENT_64:
      {
        GumDarwinSegment segment;

        if (lc->cmd == GUM_LC_SEGMENT_32)
        {
          const GumSegmentCommand32 * sc = command;

          g_strlcpy (segment.name, sc->segname, sizeof (segment.name));
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }
        else
        {
          const GumSegmentCommand64 * sc = command;

          g_strlcpy (segment.name, sc->segname, sizeof (segment.name));
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }

        g_array_append_val (self->segments, segment);

        if (strcmp (segment.name, "__TEXT") == 0)
        {
          self->preferred_address = segment.vm_address;
        }

        break;
      }
      case GUM_LC_LOAD_DYLIB:
      case GUM_LC_LOAD_WEAK_DYLIB:
      case GUM_LC_REEXPORT_DYLIB:
      case GUM_LC_LOAD_UPWARD_DYLIB:
      {
        const GumDylibCommand * dc = command;
        const gchar * name;

        name = (const gchar *) command + dc->dylib.name.offset;
        g_ptr_array_add (self->dependencies, (gpointer) name);

        if (lc->cmd == GUM_LC_REEXPORT_DYLIB)
          g_ptr_array_add (self->reexports, (gpointer) name);

        break;
      }
      case GUM_LC_DYLD_INFO_ONLY:
        self->info = command;
        break;
      case GUM_LC_SYMTAB:
        self->symtab = command;
        break;
      case GUM_LC_DYSYMTAB:
        self->dysymtab = command;
        break;
      default:
        break;
    }

    command = (const guint8 *) command + lc->cmdsize;
  }

  gum_darwin_module_enumerate_sections (self,
      gum_add_text_range_if_text_section, self->text_ranges);

  if (self->info == NULL)
  {
    /* This is the case with dyld */
  }
  else if (image->linkedit != NULL)
  {
    self->rebases = (const guint8 *) image->linkedit + self->info->rebase_off;
    self->rebases_end = self->rebases + self->info->rebase_size;
    self->rebases_malloc_data = NULL;

    self->binds = (const guint8 *) image->linkedit + self->info->bind_off;
    self->binds_end = self->binds + self->info->bind_size;
    self->binds_malloc_data = NULL;

    self->lazy_binds =
        (const guint8 *) image->linkedit + self->info->lazy_bind_off;
    self->lazy_binds_end = self->lazy_binds + self->info->lazy_bind_size;
    self->lazy_binds_malloc_data = NULL;

    self->exports = (const guint8 *) image->linkedit + self->info->export_off;
    self->exports_end = self->exports + self->info->export_size;
    self->exports_malloc_data = NULL;
  }
  else
  {
    GumAddress linkedit;

    if (!gum_find_linkedit (image->data, image->size, &linkedit))
      goto beach;
    linkedit += gum_darwin_module_get_slide (self);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->rebase_off,
        self->info->rebase_size,
        &self->rebases,
        &self->rebases_end,
        &self->rebases_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->bind_off,
        self->info->bind_size,
        &self->binds,
        &self->binds_end,
        &self->binds_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->lazy_bind_off,
        self->info->lazy_bind_size,
        &self->lazy_binds,
        &self->lazy_binds_end,
        &self->lazy_binds_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->export_off,
        self->info->export_size,
        &self->exports,
        &self->exports_end,
        &self->exports_malloc_data);
  }

  success = self->name != NULL;

beach:
  if (!success)
  {
    self->image = NULL;
    gum_darwin_module_image_free (image);

    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
  }

  return success;
}

static void
gum_darwin_module_read_and_assign (GumDarwinModule * self,
                                   GumAddress address,
                                   gsize size,
                                   const guint8 ** start,
                                   const guint8 ** end,
                                   gpointer * malloc_data)
{
  if (self->is_local)
  {
    *start = GSIZE_TO_POINTER (address);
    *end = GSIZE_TO_POINTER (address + size);
    *malloc_data = NULL;
  }
  else
  {
    guint8 * data;
    gsize n_bytes_read;

    n_bytes_read = 0;
    data = GUM_MEM_READ (self->task, address, size, &n_bytes_read);
    *start = data;
    *end = (data != NULL) ? data + n_bytes_read : NULL;
    *malloc_data = data;
  }
}

static gboolean
gum_find_linkedit (const guint8 * module,
                   gsize module_size,
                   GumAddress * linkedit)
{
  GumMachHeader32 * header;
  const guint8 * p;
  guint cmd_index;

  header = (GumMachHeader32 *) module;
  if (header->magic == GUM_MH_MAGIC_32)
    p = module + sizeof (GumMachHeader32);
  else
    p = module + sizeof (GumMachHeader64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    GumLoadCommand * lc = (GumLoadCommand *) p;

    if (lc->cmd == GUM_LC_SEGMENT_32 || lc->cmd == GUM_LC_SEGMENT_64)
    {
      GumSegmentCommand32 * sc32 = (GumSegmentCommand32 *) lc;
      GumSegmentCommand64 * sc64 = (GumSegmentCommand64 *) lc;
      if (strncmp (sc32->segname, "__LINKEDIT", 10) == 0)
      {
        if (header->magic == GUM_MH_MAGIC_32)
          *linkedit = sc32->vmaddr - sc32->fileoff;
        else
          *linkedit = sc64->vmaddr - sc64->fileoff;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
gum_add_text_range_if_text_section (const GumDarwinSectionDetails * details,
                                    gpointer user_data)
{
  GArray * ranges = user_data;

  if (gum_section_flags_indicate_text_section (details->flags))
  {
    GumMemoryRange r;
    r.base_address = details->vm_address;
    r.size = details->size;
    g_array_append_val (ranges, r);
  }

  return TRUE;
}

static gboolean
gum_section_flags_indicate_text_section (guint32 flags)
{
  return (flags & (GUM_S_ATTR_PURE_INSTRUCTIONS | GUM_S_ATTR_SOME_INSTRUCTIONS))
      != 0;
}

GumDarwinModuleImage *
gum_darwin_module_image_new (void)
{
  GumDarwinModuleImage * image;

  image = g_slice_new0 (GumDarwinModuleImage);
  image->shared_segments = g_array_new (FALSE, FALSE,
      sizeof (GumDarwinModuleImageSegment));

  return image;
}

GumDarwinModuleImage *
gum_darwin_module_image_dup (const GumDarwinModuleImage * other)
{
  GumDarwinModuleImage * image;

  image = g_slice_new0 (GumDarwinModuleImage);

  image->size = other->size;

  image->source_offset = other->source_offset;
  image->source_size = other->source_size;
  image->shared_offset = other->shared_offset;
  image->shared_size = other->shared_size;
  image->shared_segments = g_array_ref (other->shared_segments);

  if (other->bytes != NULL)
    image->bytes = g_bytes_ref (other->bytes);

  if (other->shared_segments->len > 0)
  {
    guint i;

    image->malloc_data = g_malloc (other->size);
    image->data = image->malloc_data;

    g_assert (other->source_size != 0);
    memcpy (image->data, other->data, other->source_size);

    for (i = 0; i != other->shared_segments->len; i++)
    {
      GumDarwinModuleImageSegment * s = &g_array_index (other->shared_segments,
          GumDarwinModuleImageSegment, i);
      memcpy ((guint8 *) image->data + s->offset,
          (const guint8 *) other->data + s->offset, s->size);
    }
  }
  else
  {
    image->malloc_data = g_memdup (other->data, other->size);
    image->data = image->malloc_data;
  }

  if (other->bytes != NULL)
  {
    gconstpointer data;
    gsize size;

    data = g_bytes_get_data (other->bytes, &size);
    if (other->linkedit >= data &&
        other->linkedit < (gconstpointer) ((const guint8 *) data + size))
    {
      image->linkedit = other->linkedit;
    }
  }

  if (image->linkedit == NULL && other->linkedit != NULL)
  {
    g_assert (other->linkedit >= other->data &&
        other->linkedit < other->data + other->size);
    image->linkedit = (guint8 *) image->data +
        ((guint8 *) other->linkedit - (guint8 *) other->data);
  }

  return image;
}

void
gum_darwin_module_image_free (GumDarwinModuleImage * image)
{
  g_free (image->malloc_data);
  g_bytes_unref (image->bytes);

  g_array_unref (image->shared_segments);

  g_slice_free (GumDarwinModuleImage, image);
}

static gboolean
gum_exports_trie_find (const guint8 * exports,
                       const guint8 * exports_end,
                       const gchar * name,
                       GumDarwinExportDetails * details)
{
  const gchar * s;
  const guint8 * p;

  if (exports == exports_end)
    return FALSE;

  s = name;
  p = exports;
  while (p != NULL)
  {
    gint64 terminal_size;
    const guint8 * children;
    guint8 child_count, i;
    guint64 node_offset;

    terminal_size = gum_read_uleb128 (&p, exports_end);

    if (*s == '\0' && terminal_size != 0)
    {
      gum_darwin_export_details_init_from_node (details, name, p, exports_end);
      return TRUE;
    }

    children = p + terminal_size;
    child_count = *children++;
    p = children;
    node_offset = 0;
    for (i = 0; i != child_count; i++)
    {
      const gchar * symbol_cur;
      gboolean matching_edge;

      symbol_cur = s;
      matching_edge = TRUE;
      while (*p != '\0')
      {
        if (matching_edge)
        {
          if (*p != *symbol_cur)
            matching_edge = FALSE;
          symbol_cur++;
        }
        p++;
      }
      p++;

      if (matching_edge)
      {
        node_offset = gum_read_uleb128 (&p, exports_end);
        s = symbol_cur;
        break;
      }
      else
      {
        gum_skip_uleb128 (&p);
      }
    }

    if (node_offset != 0)
      p = exports + node_offset;
    else
      p = NULL;
  }

  return FALSE;
}

static gboolean
gum_exports_trie_foreach (const guint8 * exports,
                          const guint8 * exports_end,
                          GumFoundDarwinExportFunc func,
                          gpointer user_data)
{
  GumExportsTrieForeachContext ctx;
  gboolean carry_on;

  if (exports == exports_end)
    return TRUE;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.prefix = g_string_new ("");
  ctx.exports = exports;
  ctx.exports_end = exports_end;

  carry_on = gum_exports_trie_traverse (exports, &ctx);

  g_string_free (ctx.prefix, TRUE);

  return carry_on;
}

static gboolean
gum_exports_trie_traverse (const guint8 * p,
                           GumExportsTrieForeachContext * ctx)
{
  GString * prefix = ctx->prefix;
  const guint8 * exports = ctx->exports;
  const guint8 * exports_end = ctx->exports_end;
  gboolean carry_on;
  guint64 terminal_size;
  guint8 child_count, i;

  terminal_size = gum_read_uleb128 (&p, exports_end);
  if (terminal_size != 0)
  {
    GumDarwinExportDetails details;

    gum_darwin_export_details_init_from_node (&details, prefix->str, p,
        exports_end);

    carry_on = ctx->func (&details, ctx->user_data);
    if (!carry_on)
      return FALSE;
  }

  p += terminal_size;
  child_count = *p++;
  for (i = 0; i != child_count; i++)
  {
    gsize length = 0;

    while (*p != '\0')
    {
      g_string_append_c (prefix, *p++);
      length++;
    }
    p++;

    carry_on = gum_exports_trie_traverse (
        exports + gum_read_uleb128 (&p, exports_end),
        ctx);
    if (!carry_on)
      return FALSE;

    g_string_truncate (prefix, prefix->len - length);
  }

  return TRUE;
}

static void
gum_darwin_export_details_init_from_node (GumDarwinExportDetails * details,
                                          const gchar * name,
                                          const guint8 * node,
                                          const guint8 * exports_end)
{
  const guint8 * p = node;

  details->name = name;
  details->flags = gum_read_uleb128 (&p, exports_end);
  if ((details->flags & GUM_EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    details->reexport_library_ordinal = gum_read_uleb128 (&p, exports_end);
    details->reexport_symbol = (*p != '\0') ? (gchar *) p : name;
  }
  else if ((details->flags & GUM_EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
  {
    details->stub = gum_read_uleb128 (&p, exports_end);
    details->resolver = gum_read_uleb128 (&p, exports_end);
  }
  else
  {
    details->offset = gum_read_uleb128 (&p, exports_end);
  }
}

static const GumDyldCacheImageInfo *
gum_dyld_cache_find_image_by_name (const gchar * name,
                                   const GumDyldCacheImageInfo * images,
                                   gsize image_count,
                                   gconstpointer cache)
{
  gsize i;

  for (i = 0; i != image_count; i++)
  {
    const GumDyldCacheImageInfo * image = &images[i];
    const gchar * current_name;

    current_name = (const gchar *) cache + image->name_offset;
    if (strcmp (current_name, name) == 0)
      return image;
  }

  return NULL;
}

static guint64
gum_dyld_cache_compute_image_size (const GumDyldCacheImageInfo * image,
                                   const GumDyldCacheImageInfo * images,
                                   gsize image_count)
{
  const GumDyldCacheImageInfo * next_image;
  gsize i;

  next_image = NULL;
  for (i = 0; i != image_count; i++)
  {
    const GumDyldCacheImageInfo * candidate = &images[i];

    if (candidate->address > image->address && (next_image == NULL ||
        candidate->address < next_image->address))
    {
      next_image = candidate;
    }
  }
  g_assert (next_image != NULL);

  return next_image->address - image->address;
}

static guint64
gum_dyld_cache_offset_from_address (GumAddress address,
                                    const GumDyldCacheMappingInfo * mappings,
                                    gsize mapping_count)
{
  gsize i;

  for (i = 0; i != mapping_count; i++)
  {
    const GumDyldCacheMappingInfo * mapping = &mappings[i];

    if (address >= mapping->address &&
        address < mapping->address + mapping->size)
    {
      return address - mapping->address + mapping->offset;
    }
  }

  return 0;
}

GType
gum_darwin_module_flags_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    static const GFlagsValue values[] =
    {
      { GUM_DARWIN_MODULE_FLAGS_NONE, "GUM_DARWIN_MODULE_FLAGS_NONE", "none" },
      { GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY,
        "GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY", "header-only" },
      { 0, NULL, NULL }
    };
    GType ftype;

    ftype = g_flags_register_static ("GumDarwinModuleFlags", values);

    g_once_init_leave (&gonce_value, ftype);
  }

  return (GType) gonce_value;
}
