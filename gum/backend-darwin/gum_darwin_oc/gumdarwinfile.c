#include "gumdarwinfile.h"
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
gboolean gum_darwin_sandbox_check(){
    printf("Checking sandbox\n");
    return access("/private/", F_OK) != 0;
}

GIOChannel *  gum_darwin_open_in_cache(const char *file_name,char * mode) {
  GIOChannel *file=NULL;
  // 获取用户的Cache目录路径
  CFURLRef cacheDirURL = CFCopyHomeDirectoryURL();
  CFURLRef cachesURL = CFURLCreateCopyAppendingPathComponent(
      kCFAllocatorDefault, cacheDirURL, CFSTR("Library/Caches"), true);

  // 创建文件的完整路径
  CFStringRef fileNameRef = CFStringCreateWithCString(
      kCFAllocatorDefault, file_name, kCFStringEncodingUTF8);
  CFURLRef fileURL = CFURLCreateCopyAppendingPathComponent(
      kCFAllocatorDefault, cachesURL, fileNameRef, false);

  // 转换为C字符串路径
  UInt8 filePath[PATH_MAX];
  if (CFURLGetFileSystemRepresentation(fileURL, true, filePath,
                                       sizeof(filePath))) {
    // 使用C语言标准库创建并写入文件
     file= g_io_channel_new_file((const char *)filePath, mode, NULL);
    // FILE *file = fopen((const char *)filePath, mode);
    if(!file){
        g_io_channel_shutdown(file, TRUE, NULL);
        g_io_channel_unref(file);
    }
  
  }
  



  // 释放CoreFoundation对象
  CFRelease(fileURL);
  CFRelease(fileNameRef);
  CFRelease(cachesURL);
  CFRelease(cacheDirURL);
  return file;
}

GIOChannel *gum_darwin_open(const char *fileName, char *mode) {
  GError *error = NULL;
  GIOChannel *channel = g_io_channel_new_file(fileName, mode, &error);
  if (channel == NULL) {
    g_printerr("Error opening file: %s\n", error->message);
    g_clear_error(&error);
    g_abort();
  }
  return channel;
}
