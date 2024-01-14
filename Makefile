.PHONY : all load-bpf clean

ANDROID_NDK_ROOT = /home/mufanc/Android/Sdk/ndk/26.1.10909125

CC     = clang
CFLAGS = -O2 -nostdlib -D __unused=
TARGET = bpfel-unknown-none

all: outputs/ebpf_demo.o outputs/map-reader

load-bpf: outputs/ebpf_demo.o
	adb push outputs/ebpf_demo.o /data/local/tmp
	adb shell 'su -c "cp /data/local/tmp/ebpf_demo.o /data/adb/modules/bpf-demo/system/etc/bpf"'
	adb reboot

run-map-reader: outputs/map-reader
	adb push outputs/map-reader /data/local/tmp
	adb shell 'chmod +x /data/local/tmp/map-reader && su -c /data/local/tmp/map-reader'

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
