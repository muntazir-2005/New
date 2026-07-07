TARGET := iphone:clang:latest:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = bypass

# إضافة fishhook.c هنا تجعل نظام Theos يترجمه ويربطه تلقائياً دون الحاجة لملفات .a خارجية
bypass_FILES = main.m fishhook.c

# الأطر البرمجية الأساسية التي يعتمد عليها المشروع
bypass_FRAMEWORKS = Foundation Security

# تفعيل البحث عن الملفات في المجلد الحالي (الجذر) لقراءة fishhook.h
bypass_CFLAGS = -I.

include $(THEOS_MAKE_PATH)/tweak.mk
