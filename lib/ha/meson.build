# Experimental: no NF advertises HA capability until its state adapter and
# transport takeover have independently passed failure-injection tests.
ha_ssl = dependency('openssl', version: '>=3.0')
ha_inc = include_directories('.')
libha = static_library('ogsha', 'ogs-ha.c',
    include_directories: ha_inc, dependencies: ha_ssl)
libha_dep = declare_dependency(link_with: libha,
    include_directories: ha_inc, dependencies: ha_ssl)
