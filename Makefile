# Makefile - بناء bypass.dylib من ملفات في نفس المجلد
XCRUN      = xcrun
SDK        = iphoneos
CLANG      = $(XCRUN) -sdk $(SDK) clang

ARCH       = arm64 arm64e
MIN_VER    = 14.0
ARCH_FLAGS = $(addprefix -arch ,$(ARCH)) -miphoneos-version-min=$(MIN_VER)

# المسارات (كل شيء في الدليل الحالي)
CFLAGS     = $(ARCH_FLAGS) -O2 -fobjc-arc -I.
LDFLAGS    = $(ARCH_FLAGS) -dynamiclib -framework Foundation -lobjc -L. -ldobby

# الملفات
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
