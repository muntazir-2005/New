TARGET := iphone:clang:latest:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = bypass

bypass_FILES = main.m
bypass_FRAMEWORKS = Foundation Security

# المسار إلى جذر المشروع حيث توجد libfishhook.a و fishhook.h
# نستخدم المسار المباشر للمكتبة لضمان نجاح الربط
bypass_LDFLAGS = $(THEOS_PROJECT_DIR)/libfishhook.a

# في حال احتجت إلى ربط مكتبة C++ (غير ضروري عادة مع fishhook) أضف -lc++
# bypass_LDFLAGS = $(THEOS_PROJECT_DIR)/libfishhook.a -lc++

include $(THEOS_MAKE_PATH)/tweak.mk
