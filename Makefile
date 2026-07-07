TARGET := iphone:clang:latest:14.0
ARCHS = arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = bypass

# ملفات السورس
bypass_FILES = main.m

# الأطر البرمجية
bypass_FRAMEWORKS = Foundation Security

# -I. تخبر المترجم بالبحث عن dobby.h في المجلد الحالي (الجذر)
bypass_CFLAGS = -I.

# -L. تخبر الرابط بالبحث عن libdobby.a في المجلد الحالي (الجذر)
bypass_LDFLAGS = -L. -ldobby -lc++

include $(THEOS_MAKE_PATH)/tweak.mk
