blake3_args = []
blake3_src = files('blake3.c', 'blake3_dispatch.c', 'blake3_portable.c')

if get_option('simd')
  hcf = host_machine.cpu_family()
  if hcf == 'x86' or hcf == 'x86_64'
    simd_x86 = get_option('simd_x86')
    if hcf == 'x86'
      simd_x86_args = { 'sse2': '-msse2', 'sse41': '-msse4.1',
        'avx2': '-mavx2', 'avx512': ['-mavx512f', '-mavx512vl'] }
      foreach simd : simd_x86
        blake3_args += simd_x86_args[simd]
      endforeach
      simd_f = 'blake3_@0@.c'
    elif host_machine.system() != 'windows'
      simd_f = 'blake3_@0@_x86-64_unix.S'
    elif meson.get_compiler('c').get_id() == 'msvc'
      simd_f = 'blake3_@0@_x86-64_windows_msvc.asm'
    else
      simd_f = 'blake3_@0@_x86-64_windows_gnu.S'
    endif
    foreach simd : simd_x86
      blake3_args += ['-D', 'BLAKE3_USE_@0@'.format(simd).to_upper()]
      blake3_src += files(simd_f.format(simd))
    endforeach
  elif hcf == 'aarch64' and get_option('simd_arm_neon')
    blake3_args += ['-D', 'BLAKE3_USE_NEON']
    blake3_args += '-mfpu=neon'
    blake3_src += files('blake3_neon.c')
  endif
endif

libblake3 = library('blake3', blake3_src,
  c_args : blake3_args,
  install : true,
  version : meson.project_version())

blake3_dep = declare_dependency(
  include_directories : include_directories('.'),
  link_with : libblake3)

if meson.is_subproject()
  subdir_done()
endif

install_headers(files('blake3.h'))

import('pkgconfig').generate(libblake3)

executable('b3sum', files('example.c'),
  dependencies : [blake3_dep])
