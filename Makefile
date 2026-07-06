# Makefile - بناء bypass.dylib (arm64e) باستخدام Dobby

# الأدوات
XCRUN        = xcrun
SDK          = iphoneos
CLANG        = $(XCRUN) -sdk $(SDK) clang

# المعماريات والإصدار الأدنى
ARCH         = arm64e
MIN_VERSION  = 14.0
ARCH_FLAGS   = -arch $(ARCH) -miphoneos-version-min=$(MIN_VERSION)

# مسارات المكتبات
DOBBY_DIR    = libs/Dobby
INCLUDE_DIRS = -I$(DOBBY_DIR)/include -Isrc
LIB_DIRS     = -F$(DOBBY_DIR)

# خيارات الترجمة
CFLAGS       = $(ARCH_FLAGS) -O2 -fobjc-arc $(INCLUDE_DIRS)
LDFLAGS      = $(ARCH_FLAGS) -dynamiclib -framework Foundation -lobjc $(LIB_DIRS)

# المكتبة الثابتة لـ Dobby
LIBS         = $(DOBBY_DIR)/libdobby.a

# الملفات المصدرية
SRC          = src/main.m
OBJ          = $(SRC:.m=.o)

# الملف الناتج
TARGET       = bypass.dylib

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CLANG) $(LDFLAGS) $^ $(LIBS) -o $@
	@echo "✅ Build successful: $(TARGET)"

%.o: %.m
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
