project('process-inspector', 'vala', 'c',
  version: '1.0.0',
  default_options: ['c_std=gnu99'],
)

cc = meson.get_compiler('c')

host_os_family = host_machine.system()
host_os = host_os_family

target_conditionals_prefix = '#include <TargetConditionals.h>'

is_macos_src = target_conditionals_prefix + '''
#if !TARGET_OS_OSX
# error Not macOS
#endif
'''
if cc.compiles(is_macos_src, name: 'compiling for macOS')
  host_os = 'macos'
endif

is_ios_src = target_conditionals_prefix + '''
#if !TARGET_OS_IOS
# error Not iOS
#endif
'''
if cc.compiles(is_ios_src, name: 'compiling for iOS')
  host_os = 'ios'
endif

if cc.has_header('android/api-level.h')
  host_os = 'android'
endif

gio_dep = dependency('gio-2.0')
gmodule_dep = dependency('gmodule-2.0')
gee_dep = dependency('gee-0.8')
gum_dep = dependency('frida-gum-1.0')
libsoup_dep = dependency('libsoup-2.4')
tls_provider_dep = dependency('gioopenssl')

ldid2 = find_program('ldid2', required: host_os == 'ios')

subdir('src')
