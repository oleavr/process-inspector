#include <gum/gumdarwin.h>

gchar *
process_inspector_darwin_session_query_thread_name (mach_port_t thread)
{
  thread_extended_info_data_t info;
  mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
  kern_return_t kr;

  kr = thread_info (thread, THREAD_EXTENDED_INFO, (thread_info_t) &info, &count);
  if (kr != KERN_SUCCESS)
    return NULL;

  if (info.pth_name[0] == '\0')
    return NULL;

  return g_strdup (info.pth_name);
}
