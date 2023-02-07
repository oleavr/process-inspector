inspector_sources = [
  'inspector.vala',
  'session.vala',
  'session-' + host_os_family + '.vala',
  'network.vala',
]

inspector_name = 'pinspect'
system_vala_args = ['--pkg=posix']

if host_os_family == 'darwin'
  inspector_sources += [
    'session-darwin-glue.c',
  ]
  inspector_name = 'pinspect-unsigned'
  system_vala_args += '--pkg=frida-gum-darwin-1.0'
endif

inspector = executable(inspector_name, inspector_sources,
  vala_args: system_vala_args,
  dependencies: [gio_dep, gmodule_dep, gee_dep, gum_dep, libsoup_dep, tls_provider_dep],
  install: host_os_family != 'darwin',
)

if host_os_family == 'darwin'
  custom_target('pinspect-signed',
    input: [
      inspector,
      'inspector-' + host_os + '.xml',
    ],
    output: 'pinspect',
    command: [
      files('sign.sh'),
      host_os,
      '@INPUT@',
      '@OUTPUT@',
      '>>>', strip, '<<<',
      get_option('strip').to_string(),
      codesign,
    ],
    build_by_default: true,
    install: true,
    install_dir: get_option('bindir'),
  )
endif
