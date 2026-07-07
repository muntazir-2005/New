TARGET := iphone:clang:latest:14.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = bypass

bypass_FILES = main.m
bypass_CFLAGS = -fobjc-arc -I$(THEOS_PROJECT_DIR)
bypass_LDFLAGS = -framework Foundation -framework Security -L$(THEOS_PROJECT_DIR) -lfishhook -lc++

include $(THEOS_MAKE_PATH)/library.mk
