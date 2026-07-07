// main.m – نسخة إنتاجية خالية من الأخطاء المذكورة، مع فصل تام للمسؤوليات،
// بنية تشخيص غير متكررة، جدولة مقاومة للفيضان، وإعادة محاولة ذكية.

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <os/log.h>
#import <Security/Security.h>
#include "dobby.h"

// ============================================================
// MARK: - السجلات (os_log)
// ============================================================
static os_log_t bypass_log = NULL;
#define BYPASS_LOG(fmt, ...) if (bypass_log) os_log(bypass_log, "[Bypass] " fmt, ##__VA_ARGS__)

// ============================================================
// MARK: - نماذج التشخيص (immutable value objects)
// ============================================================
typedef NS_ENUM(NSInteger, BypassHookState) {
    BypassHookStatePending = 0,
    BypassHookStateInstalled,
    BypassHookStateFailed,
    BypassHookStateClassNotFound,
    BypassHookStateMethodNotFound,
};

@interface BypassDiagnostic : NSObject <NSCopying>
@property (nonatomic, readonly, copy) NSString *target;
@property (nonatomic, readonly, assign) BypassHookState state;
@property (nonatomic, readonly, copy) NSString *detail;
@property (nonatomic, readonly, assign) NSUInteger attemptCount;
@property (nonatomic, readonly, assign) NSTimeInterval firstAttemptTime;
@property (nonatomic, readonly, assign) NSTimeInterval lastAttemptTime;
@property (nonatomic, readonly, assign) IMP originalIMP;   // لـ ObjC hooks فقط

- (instancetype)initWithTarget:(NSString *)target state:(BypassHookState)state
                        detail:(NSString *)detail originalIMP:(IMP)originalIMP
                  attemptCount:(NSUInteger)attemptCount
              firstAttemptTime:(NSTimeInterval)firstAttemptTime
               lastAttemptTime:(NSTimeInterval)lastAttemptTime;
@end

@implementation BypassDiagnostic
- (instancetype)initWithTarget:(NSString *)target state:(BypassHookState)state
                        detail:(NSString *)detail originalIMP:(IMP)originalIMP
                  attemptCount:(NSUInteger)attemptCount
              firstAttemptTime:(NSTimeInterval)firstAttemptTime
               lastAttemptTime:(NSTimeInterval)lastAttemptTime {
    self = [super init];
    if (self) {
        _target = [target copy];
        _state = state;
        _detail = [detail copy];
        _originalIMP = originalIMP;
        _attemptCount = attemptCount;
        _firstAttemptTime = firstAttemptTime;
        _lastAttemptTime = lastAttemptTime;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    return self; // immutable
}

- (NSString *)description {
    NSString *stateStr;
    switch (self.state) {
        case BypassHookStatePending: stateStr = @"PENDING"; break;
        case BypassHookStateInstalled: stateStr = @"INSTALLED"; break;
        case BypassHookStateFailed: stateStr = @"FAILED"; break;
        case BypassHookStateClassNotFound: stateStr = @"CLASS NOT FOUND"; break;
        case BypassHookStateMethodNotFound: stateStr = @"METHOD NOT FOUND"; break;
    }
    return [NSString stringWithFormat:@"[%@] %@ | %@ | attempts=%lu | original=%p",
            stateStr, self.target, self.detail ?: @"",
            (unsigned long)self.attemptCount, self.originalIMP];
}
@end

// ============================================================
// MARK: - تعريفات ObjC hooks (بيانات نقية خالية من runtime)
// ============================================================
typedef struct {
    const char *className;
    const char *selectorName;   // نستخدم اسم النص بدلاً من SEL
    BOOL isClassMethod;
    IMP replacement;            // يتم تعيينه لاحقًا (بعد تعريف IMP)
    const char *description;
} ObjCHookDescriptor;

// تعريف IMPs الصريحة قبل الجدول
static id des_httpDns(id self, SEL _cmd, NSString *domain) { return domain; }
static id des_getIPv6(id self, SEL _cmd, NSString *ip) { return ip; }
static void resolver_authChallenge(id self, SEL _cmd, id connection, id challenge) {}
static NSString *login_session(id self, SEL _cmd) { return @"bypass_s"; }
static NSString *login_authCode(id self, SEL _cmd) { return @"bypass_a"; }
static NSString *login_authorizationCode(id self, SEL _cmd) { return @"bypass_z"; }

// الآن الجدول (ليس const، لكننا نضمن أنه immutable بعد التهيئة)
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
// MARK: - دالة C لاستدعاء dyld callback (بدلاً من block)
// ============================================================
static void bypass_image_added(const struct mach_header *mh, intptr_t slide) {
    // يتم تعريف هذه الدالة بعد وجود الـ singleton
    extern void BypassController_ScheduleInstall(void);
    BypassController_ScheduleInstall();
}

// ============================================================
// MARK: - مدير الخطافات المركزي (تصميم جديد كلياً)
// ============================================================
@interface BypassController : NSObject {
    // حالة التثبيت
    dispatch_queue_t _installQueue;
    BOOL _installScheduled;
    BOOL _needsRescan;
    NSMutableArray<NSNumber *> *_pendingIndices;      // أرقام الـ hooks المعلقة
    NSMutableDictionary<NSString *, NSNumber *> *_attemptCounts; // لكل مفتاح، عدد المحاولات
    NSMutableDictionary<NSString *, NSNumber *> *_firstAttemptTimes;
    NSMutableDictionary<NSString *, NSValue *> *_originalIMPs;   // IMP الأصلي لكل مفتاح

    // التشخيص
    dispatch_queue_t _diagQueue;
    NSMutableDictionary<NSString *, BypassDiagnostic *> *_diagnostics; // مفتاح = target
    NSMutableArray<NSString *> *_diagOrder;  // لحفظ الترتيب

    NSUInteger _maxDiagnostics;
}

+ (BypassController *)shared;
- (void)startEngine;
- (NSArray<BypassDiagnostic *> *)diagnostics;
- (NSDictionary<NSString *, BypassDiagnostic *> *)currentStates;
@end

// تعريف الدالة المجسرة لاستدعاء من C
void BypassController_ScheduleInstall(void) {
    [[BypassController shared] scheduleInstallObjC];
}

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
        _diagQueue = dispatch_queue_create("com.bypass.diagnostics", DISPATCH_QUEUE_SERIAL);
        _installScheduled = NO;
        _needsRescan = NO;
        _pendingIndices = [NSMutableArray array];
        _attemptCounts = [NSMutableDictionary dictionary];
        _firstAttemptTimes = [NSMutableDictionary dictionary];
        _originalIMPs = [NSMutableDictionary dictionary];
        _diagnostics = [NSMutableDictionary dictionary];
        _diagOrder = [NSMutableArray array];
        _maxDiagnostics = 500;

        // في البداية، جميع الـ ObjC hooks تكون pending
        for (NSUInteger i = 0; i < kObjCHookCount; i++) {
            [_pendingIndices addObject:@(i)];
            NSString *target = [NSString stringWithUTF8String:kObjCHooks[i].description];
            // إضافة أولية للتشخيص
            [self updateDiagnosticForTarget:target state:BypassHookStatePending
                                     detail:@"waiting" originalIMP:NULL];
        }
    }
    return self;
}

// ================ آلية تشخيص غير متكررة ================
- (void)updateDiagnosticForTarget:(NSString *)target state:(BypassHookState)state
                           detail:(NSString *)detail originalIMP:(IMP)originalIMP {
    dispatch_async(_diagQueue, ^{
        // نحسب عدد المحاولات الحالي
        NSUInteger attempts = [self->_attemptCounts[target] unsignedIntegerValue];
        NSTimeInterval firstTime = [self->_firstAttemptTimes[target] doubleValue];
        if (firstTime == 0) firstTime = [NSDate timeIntervalSinceReferenceDate];
        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];

        BypassDiagnostic *newDiag = [[BypassDiagnostic alloc] initWithTarget:target
                                                                       state:state
                                                                      detail:detail
                                                                 originalIMP:originalIMP
                                                                attemptCount:attempts
                                                            firstAttemptTime:firstTime
                                                             lastAttemptTime:now];
        self->_diagnostics[target] = newDiag;

        // إدارة الترتيب والحد الأعلى
        if (![self->_diagOrder containsObject:target]) {
            [self->_diagOrder addObject:target];
        }
        while (self->_diagOrder.count > self->_maxDiagnostics) {
            NSString *old = self->_diagOrder.firstObject;
            [self->_diagOrder removeObjectAtIndex:0];
            [self->_diagnostics removeObjectForKey:old];
        }
    });
}

// ================ C hooks (مرة واحدة) ================
- (void)installAllCHooks {
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

    int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
        if (request == 31) return 0;
        return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
    }
    int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
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
    OSStatus my_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *r) { return errSecItemNotFound; }
    int my_EVP_EncryptInit_ex(void *ctx, const void *cipher, void *impl,
                              const unsigned char *key, const unsigned char *iv) { return 1; }
    int my_EVP_DecryptInit_ex(void *ctx, const void *cipher, void *impl,
                              const unsigned char *key, const unsigned char *iv) { return 1; }
    void *my_PKCS7_encrypt(void *certs, void *in, const void *cipher, int flags) { return NULL; }

    struct { const char *sym; void *hook; void **orig; const char *desc; } hooks[] = {
        {"ptrace", my_ptrace, (void **)&orig_ptrace, "ptrace"},
        {"sysctl", my_sysctl, (void **)&orig_sysctl, "sysctl"},
        {"SecItemCopyMatching", my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching, "Keychain"},
        {"EVP_EncryptInit_ex", my_EVP_EncryptInit_ex, (void **)&orig_EVP_EncryptInit_ex, "EVP_EncInit"},
        {"EVP_DecryptInit_ex", my_EVP_DecryptInit_ex, (void **)&orig_EVP_DecryptInit_ex, "EVP_DecInit"},
        {"PKCS7_encrypt", my_PKCS7_encrypt, (void **)&orig_PKCS7_encrypt, "PKCS7"},
    };

    for (int i = 0; i < sizeof(hooks)/sizeof(hooks[0]); i++) {
        void *addr = dlsym(RTLD_DEFAULT, hooks[i].sym);
        NSString *target = [NSString stringWithUTF8String:hooks[i].desc];
        if (!addr) {
            [self updateDiagnosticForTarget:target state:BypassHookStateFailed
                                     detail:@"symbol not found" originalIMP:NULL];
            continue;
        }
        int ret = DobbyHook(addr, hooks[i].hook, hooks[i].orig);
        if (ret == 0) {
            [self updateDiagnosticForTarget:target state:BypassHookStateInstalled
                                     detail:@"hooked" originalIMP:NULL];
        } else {
            [self updateDiagnosticForTarget:target state:BypassHookStateFailed
                                     detail:[NSString stringWithFormat:@"Dobby error %d", ret] originalIMP:NULL];
        }
    }
}

// ================ إعادة محاولة ذكية لـ ObjC hooks ================
- (void)installPendingObjCHooks {
    // يجب أن نكون داخل _installQueue
    NSMutableArray *stillPending = [NSMutableArray array];
    for (NSNumber *num in _pendingIndices) {
        NSUInteger idx = [num unsignedIntegerValue];
        if (idx >= kObjCHookCount) continue;
        const ObjCHookDescriptor *desc = &kObjCHooks[idx];
        NSString *target = [NSString stringWithUTF8String:desc->description];
        
        // زيادة عداد المحاولات
        NSUInteger attempts = [_attemptCounts[target] unsignedIntegerValue] + 1;
        _attemptCounts[target] = @(attempts);
        if (_firstAttemptTimes[target] == nil) {
            _firstAttemptTimes[target] = @([NSDate timeIntervalSinceReferenceDate]);
        }

        // فحص وجود الفئة
        Class cls = objc_getClass(desc->className);
        if (!cls) {
            [self updateDiagnosticForTarget:target state:BypassHookStateClassNotFound
                                     detail:@"class not loaded" originalIMP:NULL];
            // إذا تجاوزنا الحد الأقصى للمحاولات (20) نحول إلى فشل دائم
            if (attempts >= 20) {
                [self updateDiagnosticForTarget:target state:BypassHookStateFailed
                                         detail:@"class not found after 20 attempts" originalIMP:NULL];
                continue; // لا نضيفه إلى stillPending
            }
            [stillPending addObject:num];
            continue;
        }

        SEL sel = sel_registerName(desc->selectorName);
        Method m = desc->isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
        if (!m) {
            [self updateDiagnosticForTarget:target state:BypassHookStateMethodNotFound
                                     detail:@"method not found" originalIMP:NULL];
            if (attempts >= 20) {
                [self updateDiagnosticForTarget:target state:BypassHookStateFailed
                                         detail:@"method not found after 20 attempts" originalIMP:NULL];
                continue;
            }
            [stillPending addObject:num];
            continue;
        }

        // تثبيت الـ hook
        IMP original = method_setImplementation(m, desc->replacement);
        IMP current = method_getImplementation(m);
        BOOL success = (current == desc->replacement);

        // حفظ original IMP
        _originalIMPs[target] = [NSValue valueWithPointer:original];

        if (success) {
            [self updateDiagnosticForTarget:target state:BypassHookStateInstalled
                                     detail:@"hooked" originalIMP:original];
            // نُخرج هذا العنصر من pending
        } else {
            [self updateDiagnosticForTarget:target state:BypassHookStateFailed
                                     detail:@"IMP mismatch after set" originalIMP:original];
            if (attempts < 20) {
                [stillPending addObject:num];
            }
        }
    }

    _pendingIndices = stillPending;
}

// جدولة مع coalescing حقيقية
- (void)scheduleInstallObjC {
    BOOL shouldSubmit = NO;
    @synchronized (self) {
        if (!_installScheduled) {
            _installScheduled = YES;
            shouldSubmit = YES;
        } else {
            // إذا كان هناك مهمة مجدولة بالفعل، نطلب إعادة فحص بعد انتهائها
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
        // إذا طلب إعادة فحص أثناء التنفيذ، نُعيد الجدولة فورًا
        if (rescan) {
            [self scheduleInstallObjC];
        }
    });
}

// ================ واجهات التشخيص العامة ================
- (NSArray<BypassDiagnostic *> *)diagnostics {
    __block NSArray *snapshot = nil;
    dispatch_sync(_diagQueue, ^{
        snapshot = [self->_diagOrder valueForKey:@"self"];
        snapshot = [snapshot valueForKeyPath:@"self.@unionOfObjects.self"]; // لا، نحتاج لجلب القيم
        // الطريقة الصحيحة:
        NSMutableArray *arr = [NSMutableArray arrayWithCapacity:self->_diagOrder.count];
        for (NSString *target in self->_diagOrder) {
            BypassDiagnostic *d = self->_diagnostics[target];
            if (d) [arr addObject:d];
        }
        snapshot = [arr copy];
    });
    return snapshot;
}

- (NSDictionary<NSString *, BypassDiagnostic *> *)currentStates {
    __block NSDictionary *states = nil;
    dispatch_sync(_diagQueue, ^{
        states = [self->_diagnostics copy];
    });
    return states;
}

// ================ بدء التشغيل ================
- (void)startEngine {
    [self installAllCHooks];
    [self scheduleInstallObjC]; // محاولة فورية
    _dyld_register_func_for_add_image(bypass_image_added);
}

@end

// ============================================================
// MARK: - واجهة API العامة
// ============================================================
NSArray *BypassGetDiagnostics(void) {
    return [[BypassController shared] diagnostics];
}

NSDictionary *BypassGetCurrentStates(void) {
    return [[BypassController shared] currentStates];
}

NSArray *BypassGetPendingTargets(void) {
    NSMutableArray *pending = [NSMutableArray array];
    NSDictionary *states = BypassGetCurrentStates();
    for (NSString *target in states) {
        BypassDiagnostic *d = states[target];
        if (d.state == BypassHookStatePending ||
            d.state == BypassHookStateClassNotFound ||
            d.state == BypassHookStateMethodNotFound) {
            [pending addObject:target];
        }
    }
    return pending;
}

// ============================================================
// MARK: - نقطة الدخول
// ============================================================
__attribute__((constructor)) static void bypass_constructor() {
    bypass_log = os_log_create("com.example.bypass", "hook");
    [[BypassController shared] startEngine];
    BYPASS_LOG("Engine started. Diagnostics: %@", BypassGetDiagnostics());
}
