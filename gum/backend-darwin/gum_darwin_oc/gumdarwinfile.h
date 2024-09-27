// this io load the core foundation framework, i think the resources it used expose to the target app.
// which let the target app to do anti debug.
//管他呢，先试试看
#include <glib.h>
/**
 * @brief  Check if the current process is sandboxed.
 * 
 * @return gboolean 
 */
gboolean gum_darwin_sandbox_check();
/**
 * @brief open a file in the cache directory
 * 
 * @param fileName 
 * @param mode 
 * @return GIOChannel* 
 */
GIOChannel * gum_darwin_open_in_cache_io(const char *fileName,char * mode);
/**
 * @brief open a file
 * 
 * @param fileName 
 * @param mode 
 * @return GIOChannel* 
 */
GIOChannel * gum_darwin_open_io(const char *fileName,char * mode);
int gum_darwin_open(const char *fileName, int mode, int flags);
gboolean gum_darwin_vfs_init();