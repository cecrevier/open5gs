ha_test = executable('native-ha-test', 'native-ha-test.c',
    dependencies: libha_dep,
    link_args: ['-Wl,--wrap=fdatasync', '-Wl,--wrap=write'])
test('native-ha-journal', ha_test, suite: 'native-ha')
ha_peer = executable('native-ha-peer', 'native-ha-peer.c', dependencies: libha_dep,
    link_args: ['-Wl,--wrap=fdatasync', '-Wl,--wrap=SSL_write_ex'])
ha_python = find_program('python3')
test('native-ha-mtls', ha_python,
    args: [files('test-mtls.py'), ha_peer.full_path()],
    timeout: 90, suite: 'native-ha')
