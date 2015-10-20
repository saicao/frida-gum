/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptmemory.h"

#include "gumjscriptmacros.h"
#include "gumjscriptvalue.h"

typedef guint GumMemoryValueType;

enum _GumMemoryValueType
{
  GUM_MEMORY_VALUE_POINTER,
  GUM_MEMORY_VALUE_S8,
  GUM_MEMORY_VALUE_U8,
  GUM_MEMORY_VALUE_S16,
  GUM_MEMORY_VALUE_U16,
  GUM_MEMORY_VALUE_S32,
  GUM_MEMORY_VALUE_U32,
  GUM_MEMORY_VALUE_S64,
  GUM_MEMORY_VALUE_U64,
  GUM_MEMORY_VALUE_FLOAT,
  GUM_MEMORY_VALUE_DOUBLE,
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_C_STRING,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING,
  GUM_MEMORY_VALUE_ANSI_STRING
};

static JSValueRef gum_script_memory_read (GumScriptMemory * self,
    GumMemoryValueType type, size_t argument_count,
    const JSValueRef arguments[], JSValueRef * exception);
static JSValueRef gum_script_memory_write (GumScriptMemory * self,
    GumMemoryValueType type, size_t argument_count,
    const JSValueRef arguments[], JSValueRef * exception);

#ifdef G_OS_WIN32
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUM_DEFINE_MEMORY_READ(T) \
  GUM_DEFINE_JSC_FUNCTION (gumjs_memory_read_##T) \
  { \
    return gum_script_memory_read (JSObjectGetPrivate (this_object), \
        GUM_MEMORY_VALUE_##T, argument_count, arguments, exception); \
  }
#define GUM_DEFINE_MEMORY_WRITE(T) \
  GUM_DEFINE_JSC_FUNCTION (gumjs_memory_write_##T) \
  { \
    return gum_script_memory_write (JSObjectGetPrivate (this_object), \
        GUM_MEMORY_VALUE_##T, argument_count, arguments, exception); \
  }
#define GUM_DEFINE_MEMORY_READ_WRITE(T) \
  GUM_DEFINE_MEMORY_READ (T); \
  GUM_DEFINE_MEMORY_WRITE (T)

#define GUM_EXPORT_MEMORY_READ(N, T) \
  { "read" N, gumjs_memory_read_##T, gumjs_attrs }
#define GUM_EXPORT_MEMORY_WRITE(N, T) \
  { "write" N, gumjs_memory_write_##T, gumjs_attrs }
#define GUM_EXPORT_MEMORY_READ_WRITE(N, T) \
  GUM_EXPORT_MEMORY_READ (N, T), \
  GUM_EXPORT_MEMORY_WRITE (N, T)

GUM_DEFINE_MEMORY_READ_WRITE (POINTER)
GUM_DEFINE_MEMORY_READ_WRITE (S8)
GUM_DEFINE_MEMORY_READ_WRITE (U8)
GUM_DEFINE_MEMORY_READ_WRITE (S16)
GUM_DEFINE_MEMORY_READ_WRITE (U16)
GUM_DEFINE_MEMORY_READ_WRITE (S32)
GUM_DEFINE_MEMORY_READ_WRITE (U32)
GUM_DEFINE_MEMORY_READ_WRITE (S64)
GUM_DEFINE_MEMORY_READ_WRITE (U64)
GUM_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUM_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUM_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUM_DEFINE_MEMORY_READ (C_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (ANSI_STRING)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_memory_functions[] =
{
  GUM_EXPORT_MEMORY_READ_WRITE ("Pointer", POINTER),
  GUM_EXPORT_MEMORY_READ_WRITE ("S8", S8),
  GUM_EXPORT_MEMORY_READ_WRITE ("U8", U8),
  GUM_EXPORT_MEMORY_READ_WRITE ("S16", S16),
  GUM_EXPORT_MEMORY_READ_WRITE ("U16", U16),
  GUM_EXPORT_MEMORY_READ_WRITE ("S32", S32),
  GUM_EXPORT_MEMORY_READ_WRITE ("U32", U32),
  GUM_EXPORT_MEMORY_READ_WRITE ("S64", S64),
  GUM_EXPORT_MEMORY_READ_WRITE ("U64", U64),
  GUM_EXPORT_MEMORY_READ_WRITE ("Float", FLOAT),
  GUM_EXPORT_MEMORY_READ_WRITE ("Double", DOUBLE),
  GUM_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY),
  GUM_EXPORT_MEMORY_READ ("CString", C_STRING),
  GUM_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING),
  GUM_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING),
  GUM_EXPORT_MEMORY_READ_WRITE ("AnsiString", ANSI_STRING),
  { NULL, NULL, 0 }
};

void
_gum_script_memory_init (GumScriptMemory * self,
                         GumScriptCore * core,
                         JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef memory;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Memory";
  def.staticFunctions = gumjs_memory_functions;
  klass = JSClassCreate (&def);
  memory = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Memory", memory);
}

void
_gum_script_memory_dispose (GumScriptMemory * self)
{
  (void) self;
}

void
_gum_script_memory_finalize (GumScriptMemory * self)
{
  (void) self;
}

static JSValueRef
gum_script_memory_read (GumScriptMemory * self,
                        GumMemoryValueType type,
                        size_t argument_count,
                        const JSValueRef arguments[],
                        JSValueRef * exception)
{
  GumScriptCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  JSContextRef ctx = core->ctx;
  JSValueRef result = NULL;
  gpointer address;
  GumExceptorScope scope;

  if (argument_count < 1)
    goto invalid_argument;

  if (!_gumjs_native_pointer_get (core, arguments[0], &address, exception))
    return NULL;

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gumjs_native_pointer_new (core, *((gpointer *) address));
        break;
      case GUM_MEMORY_VALUE_S8:
        result = JSValueMakeNumber (ctx, *((gint8 *) address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = JSValueMakeNumber (ctx, *((guint8 *) address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = JSValueMakeNumber (ctx, *((gint16 *) address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = JSValueMakeNumber (ctx, *((guint16 *) address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = JSValueMakeNumber (ctx, *((gint32 *) address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = JSValueMakeNumber (ctx, *((guint32 *) address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = JSValueMakeNumber (ctx, *((gint64 *) address));
        break;
      case GUM_MEMORY_VALUE_U64:
        result = JSValueMakeNumber (ctx, *((guint64 *) address));
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = JSValueMakeNumber (ctx, *((gfloat *) address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = JSValueMakeNumber (ctx, *((gdouble *) address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        guint8 * data;
        gint length;

        if (argument_count < 2)
        {
          _gumjs_throw (ctx, exception, "expected address and length");
          break;
        }

        data = address;
        if (data == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        if (!_gumjs_try_int_from_value (ctx, arguments[1], &length, exception))
          break;

        if (length > 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          JSObjectRef array;
          gpointer array_data;

          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

          array = _gumjs_array_buffer_new (core, length);
          array_data = _gumjs_array_buffer_get_data (core, array, NULL);
          memcpy (array_data, data, length);
          result = array;
        }
        else
        {
          result = _gumjs_array_buffer_new (core, 0);
        }

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        gchar * data;
        gint length;
        guint8 dummy_to_trap_bad_pointer_early;

        data = address;
        if (data == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        length = -1;
        if (argument_count >= 2)
        {
          if (!_gumjs_try_int_from_value (ctx, arguments[1], &length,
              exception))
            break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

        if (length < 0)
        {
          result = _gumjs_string_to_value (ctx, data);
        }
        else
        {
          gchar * slice;

          slice = g_strndup (data, length);
          result = _gumjs_string_to_value (ctx, slice);
          g_free (slice);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gchar * data;
        gint length;
        guint8 dummy_to_trap_bad_pointer_early;

        data = address;
        if (data == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        length = -1;
        if (argument_count >= 2)
        {
          if (!_gumjs_try_int_from_value (ctx, arguments[1], &length,
              exception))
            break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

        if (length < 0)
        {
          result = _gumjs_string_to_value (ctx, data);
        }
        else
        {
          gsize size;
          gchar * slice;

          size = g_utf8_offset_to_pointer (data, length) - data;
          slice = g_strndup (data, size);
          result = _gumjs_string_to_value (ctx, slice);
          g_free (slice);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gunichar2 * str_utf16;
        gchar * str_utf8;
        gint length;
        guint8 dummy_to_trap_bad_pointer_early;
        glong size;

        str_utf16 = address;
        if (str_utf16 == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        length = -1;
        if (argument_count >= 2)
        {
          if (!_gumjs_try_int_from_value (ctx, arguments[1], &length,
              exception))
            break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, 1);

        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        result = _gumjs_string_to_value (ctx, str_utf8);
        g_free (str_utf8);

        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef G_OS_WIN32
        gchar * str_ansi;
        gint length;

        str_ansi = address;
        if (str_ansi == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        length = -1;
        if (argument_count >= 2)
        {
          if (!_gumjs_try_int_from_value (ctx, arguments[1], &length,
              exception))
            break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          gchar * str_utf8;

          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          result = _gumjs_string_to_value (ctx, str_utf8);
          g_free (str_utf8);
        }
        else
        {
          result = _gumjs_string_to_value (ctx, "");
        }
#else
        _gumjs_throw (ctx, exception, "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gumjs_throw_native (core, &scope.exception, exception);
  }

  return result;

invalid_argument:
  {
    _gumjs_throw (ctx, exception, "invalid argument");
    return NULL;
  }
}

static JSValueRef
gum_script_memory_write (GumScriptMemory * self,
                         GumMemoryValueType type,
                         size_t argument_count,
                         const JSValueRef arguments[],
                         JSValueRef * exception)
{
  _gumjs_throw (self->core->ctx, exception, "not yet implemented");
  return NULL;
}

#ifdef G_OS_WIN32

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  guint str_utf16_size;
  WCHAR * str_utf16;
  gchar * str_utf8;

  if (length < 0)
    length = (gint) strlen (str_ansi);

  str_utf16_size = (guint) (length + 1) * sizeof (WCHAR);
  str_utf16 = (WCHAR *) g_malloc (str_utf16_size);
  MultiByteToWideChar (CP_ACP, 0, str_ansi, length, str_utf16, str_utf16_size);
  str_utf16[length] = L'\0';
  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);
  g_free (str_utf16);

  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  gunichar2 * str_utf16;
  gchar * str_ansi;
  guint str_ansi_size;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  str_ansi_size = WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1,
      NULL, 0, NULL, NULL);
  str_ansi = (gchar *) g_malloc (str_ansi_size);
  WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);
  g_free (str_utf16);

  return str_ansi;
}

#endif
