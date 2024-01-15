.PHONY : install load-bpf clean

ANDROID_NDK_ROOT = /home/mufanc/Android/Sdk/ndk/26.1.10909125
MODULE_PATH = /data/adb/modules/bpf-demo

CC     = clang
CFLAGS = -O2 -nostdlib -D __unused=
TARGET = bpfel-unknown-none

install: outputs/ebpf_demo.o outputs/map-reader
	adb push outputs/ebpf_demo.o /data/local/tmp
	adb shell 'su -c "cp /data/local/tmp/ebpf_demo.o $(MODULE_PATH)/system/etc/bpf"'

	adb push outputs/map-reader /data/local/tmp
	adb shell 'su -c "killall map-reader; cp /data/local/tmp/map-reader $(MODULE_PATH)/map-reader"'

run: install
	adb reboot

outputs/map-reader: map-reader/main.cpp
	cmake -Hmap-reader \
	  -B outputs \
	  -D ANDROID_ABI=arm64-v8a \
	  -D ANDROID_PLATFORM=android-28 \
	  -D ANDROID_NDK=$(ANDROID_NDK_ROOT) \
	  -D ANDROID_STL=c++_static \
	  -D CMAKE_TOOLCHAIN_FILE=$(ANDROID_NDK_ROOT)/build/cmake/android.toolchain.cmake \
	  -G Ninja
	  ninja -C outputs

outputs/%.o: bpf/%.c
	mkdir -p outputs
	$(CC) $(CFLAGS) -target $(TARGET) -c -o $@ $<

clean:
	rm -rf outputs
