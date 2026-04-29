KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR := build

.PHONY: all module backend gui install uninstall clean

all: module backend gui

module:
	$(MAKE) -C kernel_module KDIR=$(KDIR)

backend:
	cmake -B $(BUILD_DIR)/backend -S backend -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR)/backend --parallel

gui:
	cmake -B $(BUILD_DIR)/gui -S gui -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR)/gui --parallel

install:
	@bash scripts/install.sh

uninstall:
	@bash scripts/uninstall.sh

clean:
	$(MAKE) -C kernel_module clean
	rm -rf $(BUILD_DIR)
