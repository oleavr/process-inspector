FRIDA ?= ../frida

all: app

build/build.ninja:
	rm -rf build
	( \
		. $(FRIDA)/build/frida_thin-meson-env-macos-x86_64.rc \
		&& $(FRIDA)/releng/meson/meson.py \
			--cross-file $(FRIDA)/build/frida_thin-ios-arm64.txt \
			build \
	)

app: build/build.ninja
	( \
		. $(FRIDA)/build/frida_thin-meson-env-macos-x86_64.rc \
		&& ninja -C build \
	)

test: app
	ssh iphone "rm -f /usr/local/bin/pinspect"
	scp build/src/pinspect iphone:/usr/local/bin/
	ssh iphone /usr/local/bin/pinspect -p $$TEST_TARGET_PID

.PHONY: all app test
.SECONDARY:
