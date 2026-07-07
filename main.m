// main.m – نسخة كاملة باستخدام fishhook بدلاً من Dobby (تعمل بدون جيلبريك)
// الهيكل كما هو، فقط آلية خطافات C تغيرت إلى rebind_symbols.

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <Security/Security.h>
#include "fishhook.h"

// ============================================================
// MARK: - تعريفات ObjC hooks (بيانات نقية)
// ============================================================
typedef struct {
    const char *className;
    const char *selectorName;
    BOOL isClassMethod;
    IMP replacement;
    const char *description;
} ObjCHookDescriptor;

// تعريف IMPs الصريحة
static id des_httpDns(id self, SEL _cmd, NSString *domain) { return domain; }
static id des_getIPv6(id self, SEL _cmd, NSString *ip) { return ip; }
static void resolver_authChallenge(id self, SEL _cmd, id connection, id challenge) {}
static NSString *login_session(id self, SEL _cmd) { return @"bypass_s"; }
static NSString *login_authCode(id self, SEL _cmd) { return @"bypass_a"; }
static NSString *login_authorizationCode(id self, SEL _cmd) { return @"bypass_z"; }

// جدول الخطافات (مملوء مباشرة)
static ObjCHookDescriptor kObjCHooks[] = {
    {"GSDKDESEncrypt", "httpDnsUrlWithDomain:", YES, (IMP)des_httpDns, "GSDKDESEncrypt httpDnsUrl"},
    {"GSDKDESEncrypt", "getIPv6:", YES, (IMP)des_getIPv6, "GSDKDESEncrypt getIPv6"},
    {"GSDKHttpDnsResolver", "connection:willSendRequestForAuthenticationChallenge:", NO,
     (IMP)resolver_authChallenge, "GSDKHttpDnsResolver authChallenge"},
    {"GSDKLoginSwitch", "session_id", NO, (IMP)login_session, "LoginSwitch.session_id"},
    {"GSDKLoginSwitch", "authCode", NO, (IMP)login_authCode, "LoginSwitch.authCode"},
    {"GSDKLoginSwitch", "_authorizationCode", NO, (IMP)login_authorizationCode, "LoginSwitch._authorizationCode"},
};
static const NSUInteger kObjCHookCount = sizeof(kObjCHooks) / sizeof(ObjCHookDescriptor);

// ============================================================
// MARK: - دوال C البديلة (خارج Objective-C)
// ============================================================
typedef int (*ptrace_t)(int, pid_t, caddr_t, int);
typedef int (*sysctl_t)(int *, u_int, void *, size_t *, void *, size_t);
typedef OSStatus (*sec_copy_t)(CFDictionaryRef, CFTypeRef *);
typedef int (*evp_init_t)(void *, const void *, void *, const unsigned char *, const unsigned char *);
typedef void *(*pkcs7_enc_t)(void *, void *, const void *, int);

static ptrace_t orig_ptrace = NULL;
static sysctl_t orig_sysctl = NULL;
static sec_copy_t orig_SecItemCopyMatching = NULL;
static evp_init_t orig_EVP_EncryptInit_ex = NULL;
static evp_init_t orig_EVP_DecryptInit_ex = NULL;
static pkcs7_enc_t orig_PKCS7_encrypt = NULL;

static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) return 0;
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctl) return -1;
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && oldp && oldlenp && name && namelen >= 4 &&
        name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID &&
        *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        if (kp->kp_proc.p_flag & P_TRACED) kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}
static OSStatus my_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *r) {
    return errSecItemNotFound;
}
static int my_EVP_EncryptInit_ex(void *ctx, const void *cipher, void *impl,
                                const unsigned char *key, const unsigned char *iv) {
    return 1;
}
static int my_EVP_DecryptInit_ex(void *ctx, const void *cipher, void *impl,
                                const unsigned char *key, const unsigned char *iv) {
    return 1;
}
static void *my_PKCS7_encrypt(void *certs, void *in, const void *cipher, int flags) {
    return NULL;
}

// ============================================================
// MARK: - جسر C ↔ ObjC (لتفادي block في dyld)
// ============================================================
static void BypassController_ScheduleInstall(void);

static void bypass_image_added(const struct mach_header *mh, intptr_t slide) {
    BypassController_ScheduleInstall();
}

// ============================================================
// MARK: - مدير الخطافات المركزي (بدون تشخيص خارجي)
// ============================================================
@interface BypassController : NSObject {
    dispatch_queue_t _installQueue;
    BOOL _installScheduled;
    BOOL _needsRescan;
    NSMutableArray<NSNumber *> *_pendingIndices;
    NSMutableDictionary<NSString *, NSNumber *> *_attemptCounts;
    NSMutableDictionary<NSString *, NSValue *> *_originalIMPs;
}
+ (BypassController *)shared;
- (void)startEngine;
- (void)scheduleInstallObjC;
@end

@implementation BypassController

+ (BypassController *)shared {
    static BypassController *ctrl = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        ctrl = [[BypassController alloc] init];
    });
    return ctrl;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _installQueue = dispatch_queue_create("com.bypass.install", DISPATCH_QUEUE_SERIAL);
        _installScheduled = NO;
        _needsRescan = NO;
        _pendingIndices = [NSMutableArray array];
        _attemptCounts = [NSMutableDictionary dictionary];
        _originalIMPs = [NSMutableDictionary dictionary];

        // جميع الـ ObjC hooks تبدأ معلقة
        for (NSUInteger i = 0; i < kObjCHookCount; i++) {
            [_pendingIndices addObject:@(i)];
        }
    }
    return self;
}

// ================ تثبيت خطافات C باستخدام fishhook ================
- (void)installAllCHooks {
    struct rebinding rebindings[] = {
        {"ptrace", my_ptrace, (void **)&orig_ptrace},
        {"sysctl", my_sysctl, (void **)&orig_sysctl},
        {"SecItemCopyMatching", my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"EVP_EncryptInit_ex", my_EVP_EncryptInit_ex, (void **)&orig_EVP_EncryptInit_ex},
        {"EVP_DecryptInit_ex", my_EVP_DecryptInit_ex, (void **)&orig_EVP_DecryptInit_ex},
        {"PKCS7_encrypt", my_PKCS7_encrypt, (void **)&orig_PKCS7_encrypt},
    };
    int rebindCount = sizeof(rebindings) / sizeof(struct rebinding);

    int result = rebind_symbols(rebindings, rebindCount);
    if (result == 0) {
        NSLog(@"[Bypass] Fishhook C hooks installed successfully (%d symbols).", rebindCount);
    } else {
        NSLog(@"[Bypass] Fishhook installation failed with error %d.", result);
    }

    // طباعة حالة كل رمز
    for (int i = 0; i < rebindCount; i++) {
        if (*(rebindings[i].replaced) == NULL) {
            NSLog(@"[Bypass] C hook %s: original pointer is NULL (symbol may not be dynamically linked).", rebindings[i].name);
        } else {
            NSLog(@"[Bypass] C hook %s: original pointer = %p, replacement = %p", rebindings[i].name, *(rebindings[i].replaced), rebindings[i].replacement);
        }
    }
}

// ================ تثبيت ObjC hooks مع إعادة محاولة ================
- (void)installPendingObjCHooks {
    NSMutableArray *stillPending = [NSMutableArray array];
    for (NSNumber *num in _pendingIndices) {
        NSUInteger idx = [num unsignedIntegerValue];
        if (idx >= kObjCHookCount) continue;
        const ObjCHookDescriptor *desc = &kObjCHooks[idx];
        NSString *target = [NSString stringWithUTF8String:desc->description];

        NSUInteger attempts = [_attemptCounts[target] unsignedIntegerValue] + 1;
        _attemptCounts[target] = @(attempts);

        Class cls = objc_getClass(desc->className);
        if (!cls) {
            if (attempts >= 20) {
                NSLog(@"[Bypass] ObjC hook failed after %lu attempts: %s (class not loaded)", (unsigned long)attempts, desc->description);
                continue;
            }
            [stillPending addObject:num];
            continue;
        }

        SEL sel = sel_registerName(desc->selectorName);
        Method m = desc->isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
        if (!m) {
            if (attempts >= 20) {
                NSLog(@"[Bypass] ObjC hook failed after %lu attempts: %s (method not found)", (unsigned long)attempts, desc->description);
                continue;
            }
            [stillPending addObject:num];
            continue;
        }

        IMP original = method_setImplementation(m, desc->replacement);
        IMP current = method_getImplementation(m);
        if (current == desc->replacement) {
            _originalIMPs[target] = [NSValue valueWithPointer:original];
            NSLog(@"[Bypass] ObjC hook installed: %s", desc->description);
        } else {
            if (attempts < 20) {
                [stillPending addObject:num];
            }
            NSLog(@"[Bypass] ObjC hook verification failed: %s (attempt %lu)", desc->description, (unsigned long)attempts);
        }
    }
    _pendingIndices = stillPending;
}

// ================ جدولة المقاومة للفيضان ================
- (void)scheduleInstallObjC {
    BOOL shouldSubmit = NO;
    @synchronized (self) {
        if (!_installScheduled) {
            _installScheduled = YES;
            shouldSubmit = YES;
        } else {
            _needsRescan = YES;
        }
    }
    if (!shouldSubmit) return;

    dispatch_async(_installQueue, ^{
        [self installPendingObjCHooks];

        BOOL rescan = NO;
        @synchronized (self) {
            rescan = self->_needsRescan;
            self->_needsRescan = NO;
            self->_installScheduled = NO;
        }
        if (rescan) {
            [self scheduleInstallObjC];
        }
    });
}

- (void)startEngine {
    [self installAllCHooks];
    [self scheduleInstallObjC]; // محاولة فورية
    _dyld_register_func_for_add_image(bypass_image_added);
}

@end

// دالة C المساعدة التي تستدعي scheduleInstallObjC
static void BypassController_ScheduleInstall(void) {
    [[BypassController shared] scheduleInstallObjC];
}

// ============================================================
// MARK: - نقطة الدخول (تبدأ بعد 10 ثوانٍ)
// ============================================================
__attribute__((constructor)) static void bypass_constructor() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[BypassController shared] startEngine];
        NSLog(@"[Bypass] Engine started after 10 seconds delay.");
    });
}
