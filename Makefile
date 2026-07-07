TARGET := iphone:clang:14.0:14.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = bypass

bypass_FILES = main.m
bypass_CFLAGS = -fobjc-arc -I.
bypass_LDFLAGS = -framework Foundation -framework Security -L. -lfishhook -lc++
bypass_LIBRARIES = objc

include $(THEOS_MAKE_PATH)/library.mk
