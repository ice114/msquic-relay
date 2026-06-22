# DPDK CNP relay — build with:
#   PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig meson setup build
#   ninja -C build
project('cnp-relay', 'c',
  version : '0.1',
  default_options : ['c_std=gnu11', 'warning_level=2', 'optimization=2'])

dpdk = dependency('libdpdk', required : true)

executable('relay',
  'relay.c',
  include_directories : include_directories('../include'),
  dependencies : dpdk,
  install : false)
