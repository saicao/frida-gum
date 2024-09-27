#include "gumdarwinfile.h"
#include "glib/gprintf.h"
#include "glib/gstdio.h"
#include <CoreFoundation/CoreFoundation.h>
static char *VIRTUAL_ROOT_DIR;

GIOChannel *gum_darwin_open_in_cache_io(const char *file_name, char *mode) {
  GIOChannel *file = NULL;
  // 获取用户的Cache目录路径
  // CFURLRef cacheDirURL = CFCopyHomeDirectoryURL();
  // CFURLRef cachesURL = CFURLCreateCopyAppendingPathComponent(
  //     kCFAllocatorDefault, cacheDirURL, CFSTR("Library/Caches"), true);

  // // 创建文件的完整路径
  // CFStringRef fileNameRef = CFStringCreateWithCString(
  //     kCFAllocatorDefault, file_name, kCFStringEncodingUTF8);
  // CFURLRef fileURL = CFURLCreateCopyAppendingPathComponent(
  //     kCFAllocatorDefault, cachesURL, fileNameRef, false);

  // // 转换为C字符串路径
  // UInt8 filePath[PATH_MAX];
  // if (CFURLGetFileSystemRepresentation(fileURL, true, filePath,
  //                                      sizeof(filePath))) {
  //   g_printf("file path %s\n", filePath);
  //   file = g_io_channel_new_file((const char *)filePath, mode, NULL);
  //   if (!file) {
  //     g_io_channel_shutdown(file, TRUE, NULL);
  //     g_io_channel_unref(file);
  //   }
  // }

  // // 释放CoreFoundation对象
  // CFRelease(fileURL);
  // CFRelease(fileNameRef);
  // CFRelease(cachesURL);
  // CFRelease(cacheDirURL);
  return file;
}

GIOChannel *gum_darwin_open_io(const char *fileName, char *mode) {
   GIOChannel *channel=NULL;
  // char *path = g_strconcat(VIRTUAL_ROOT_DIR, "/", fileName, NULL);
  // GError *error = NULL;
  // channel = g_io_channel_new_file(path, mode, &error);
  // if (channel == NULL) {
  //   g_printerr("Error opening file: %s\n", error->message);
  //   g_clear_error(&error);
  // }
  // g_free(path);
  return channel;
}
int gum_darwin_rm(const char *fileName) {
  char *path = g_strconcat(VIRTUAL_ROOT_DIR, "/", fileName, NULL);
  int err = g_remove(fileName);
  g_free(path);
  return err;
}
int gum_darwin_open(const char *fileName, int mode, int flags) {
  char *path = g_strconcat(VIRTUAL_ROOT_DIR, "/", fileName, NULL);
  
  int fd = g_open(path, mode, flags);
  g_free(path);
  return fd;
}

int gum_darwin_mkdir(const char *fileName, int mode) {
  char *path = g_strconcat(VIRTUAL_ROOT_DIR, "/", fileName, NULL);
  int err = g_mkdir(path, mode);
  g_free(path);
  return err;
}