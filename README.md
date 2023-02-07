# process-inspector

Tool for inspecting processes, with Frida-aware backtraces. Only
supports iOS for now.

## Building

First build Gum for iOS, and enter the build environment:

```sh
$ cd ~/src/frida
$ make gum-ios
$ . build/frida-env-ios-arm64.rc
```

Then bootstrap the build system:

```sh
$ cd ~/src/process-inspector
$ ~/src/frida/releng/meson/meson.py setup --cross-file ~/src/frida/build/frida-ios-arm64.txt build
```

Build and copy to iOS device:

```sh
$ ~/src/frida/releng/meson/meson.py compile -C build
$ scp build/src/pinspect iphone:/usr/local/bin/pinspect
```
