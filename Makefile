TARGET := iphone:clang:latest:14.0
ARCHS = arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = bypass

# ملفات السورس الخاصة بالمشروع
bypass_FILES = main.m

# الأطر البرمجية المستخدمة
bypass_FRAMEWORKS = Foundation Security

# توجيه المترجم للبحث عن ملف dobby.h داخل مجلد include
bypass_CFLAGS = -Iinclude

# توجيه الرابط للبحث عن libdobby.a داخل مجلد lib وربطه ديناميكياً مع C++
bypass_LDFLAGS = -Llib -ldobby -lc++

include $(THEOS_MAKE_PATH)/tweak.mk
