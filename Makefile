XCRUN      = xcrun
SDK        = iphoneos
CLANG      = $(XCRUN) -sdk $(SDK) clang

# تم ترك arm64e ولكن يفضل تحويلها لـ arm64 إذا واجهت مشاكل تشغيل مع Dobby
ARCH       = arm64e
MIN_VER    = 14.0
ARCH_FLAGS = -arch $(ARCH) -miphoneos-version-min=$(MIN_VER)

# إضافة دعم الأكواد المصدريّة لـ Objective-C و C++ (بسبب Dobby)
CFLAGS     = $(ARCH_FLAGS) -O2 -fobjc-arc -I.
# تم إضافة -framework Security هنا لحل مشكلة التجميع
LDFLAGS    = $(ARCH_FLAGS) -dynamiclib -framework Foundation -framework Security -lobjc -L. -ldobby -lc++

SRC        = main.m
OBJ        = $(SRC:.m=.o)
TARGET     = bypass.dylib

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) libdobby.a dobby.h
	$(CLANG) $(LDFLAGS) $(OBJ) -o $@

%.o: %.m
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
