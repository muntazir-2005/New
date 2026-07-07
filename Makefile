# استخدام أحدث SDK متوفر، والنشر الأدنى iOS 14.0
TARGET := iphone:clang:latest:14.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = bypass

bypass_FILES = main.m
bypass_CFLAGS = -fobjc-arc -I.
bypass_LDFLAGS = -framework Foundation -framework Security -L. -lfishhook -lc++
bypass_LIBRARIES = objc

include $(THEOS_MAKE_PATH)/library.mk
