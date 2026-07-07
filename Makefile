# تحديد المعماريات المستهدفة (يدعم الأجهزة الحديثة arm64e و arm64)
TARGET := iphone:clang:latest:14.0
ARCHS = arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = bypass

# تحديد ملف السورس
bypass_FILES = main.m

# إضافة الـ Frameworks المطلوبة من الكود
bypass_FRAMEWORKS = Foundation Security

# ربط مكتبة Dobby (تأكد من وضع ملف libdobby.a داخل مجلد المشروع أو مجلد الـ $THEOS/lib)
bypass_LDFLAGS = -L. -ldobby -lc++

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
