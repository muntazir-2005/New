// main.m – كود هوك متكامل لاعتراض جميع آليات الحماية المذكورة
// يعمل على arm64e بدون أي إدخال يدوي. يستخدم Dobby + Objective-C Runtime.
// مطلوب: libdobby.a و dobby.h

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#include "dobby.h"

// ========== [1] تعريف مؤشرات الدوال الأصلية ==========
// دوال النظام
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data) = NULL;
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;

// دوال OpenSSL / التشفير (إن وجدت)
static int (*orig_i2d_DSA_PUBKEY)(void *a, unsigned char **out) = NULL;
static int (*orig_i2d_EC_PUBKEY)(void *a, unsigned char **out) = NULL;
static int (*orig_i2d_PrivateKey)(void *a, unsigned char **out) = NULL;
static int (*orig_i2d_PublicKey)(void *a, unsigned char **out) = NULL;
static int (*orig_X509_PUBKEY_set)(void **x, void *pkey) = NULL;
static int (*orig_X509_REQ_check_private_key)(void *req, void *pkey) = NULL;
static void *(*orig_EVP_EncryptInit_ex)(void *ctx, const void *cipher, void *impl, const unsigned char *key, const unsigned char *iv) = NULL;
static void *(*orig_EVP_DecryptInit_ex)(void *ctx, const void *cipher, void *impl, const unsigned char *key, const unsigned char *iv) = NULL;
static int (*orig_PKCS7_encrypt)(void *certs, void *in, void *cipher, int flags) = NULL;
static int (*orig_DH_generate_key)(void *dh) = NULL;

// دوال Keychain
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result) = NULL;

// ========== [2] الدوال البديلة (تزييف النتائج) ==========

// --- اعتراضات النظام (ptrace, sysctl) ---
int hook_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) return 0; // PT_DENY_ATTACH
    return orig_ptrace(request, pid, addr, data);
}

int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (namelen >= 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        if (info && (info->kp_proc.p_flag & P_TRACED)) {
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

// --- اعتراضات OpenSSL: جعل دوال التشفير والتوقيع تُرجع نجاحاً وهمياً ---
int hook_i2d_DSA_PUBKEY(void *a, unsigned char **out) { return 0; }
int hook_i2d_EC_PUBKEY(void *a, unsigned char **out) { return 0; }
int hook_i2d_PrivateKey(void *a, unsigned char **out) { return 0; }
int hook_i2d_PublicKey(void *a, unsigned char **out) { return 0; }
int hook_X509_PUBKEY_set(void **x, void *pkey) { return 1; } // نجاح
int hook_X509_REQ_check_private_key(void *req, void *pkey) { return 1; } // نجاح

void *hook_EVP_EncryptInit_ex(void *ctx, const void *cipher, void *impl,
                              const unsigned char *key, const unsigned char *iv) {
    // نعيد ctx مباشرة دون تشفير فعلي
    return ctx;
}
void *hook_EVP_DecryptInit_ex(void *ctx, const void *cipher, void *impl,
                              const unsigned char *key, const unsigned char *iv) {
    return ctx;
}
int hook_PKCS7_encrypt(void *certs, void *in, void *cipher, int flags) { return 1; }
int hook_DH_generate_key(void *dh) { return 1; }

// --- اعتراض Keychain (مزامنة KeychainSync) ---
OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    // نمنع الوصول لبيانات Keychain الحساسة
    return errSecItemNotFound; // -25300
}

// --- اعتراضات Objective-C (فئات GSDK) ---
// سنُنشئ دوال بديلة باستخدام blocks.

// +[GSDKDESEncrypt httpDnsUrlWithDomain:]
static id replacement_httpDnsUrl(id self, SEL _cmd, NSString *domain) {
    NSLog(@"[Bypass] GSDKDESEncrypt httpDnsUrlWithDomain: bypassed -> %@", domain);
    return domain; // نعيد النطاق بدون تشفير
}

// +[GSDKDESEncrypt getIPv6:]
static id replacement_getIPv6(id self, SEL _cmd, NSString *ipv6) {
    return ipv6;
}

// -[GSDKHttpDnsResolver connection:willSendRequestForAuthenticationChallenge:]
static void replacement_authChallenge(id self, SEL _cmd, id connection, id challenge) {
    NSLog(@"[Bypass] Authentication challenge ignored");
}

// GSDKLoginSwitch (session_id, authCode, authorizationCode)
static NSString *replacement_session_id(id self, SEL _cmd) {
    return @"bypassed_session";
}
static NSString *replacement_authCode(id self, SEL _cmd) {
    return @"bypassed_auth";
}
static NSString *replacement_authorizationCode(id self, SEL _cmd) {
    return @"bypassed_authz";
}

// ========== [3] دوال تركيب الهوكات ==========

// هوك دوال C عبر dlsym (آمنة من الأخطاء)
void safeHook(const char *symbol, void *hook_func, void **orig_ptr, const char *desc) {
    void *addr = dlsym(RTLD_DEFAULT, symbol);
    if (addr) {
        DobbyHook(addr, hook_func, orig_ptr);
        NSLog(@"[Bypass] Hooked %s (%s)", desc, symbol);
    } else {
        NSLog(@"[Bypass] Symbol not found: %s", symbol);
    }
}

// هوك لدوال Objective-C
void hookMethod(Class cls, SEL sel, IMP newImp, const char *desc) {
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) method = class_getClassMethod(cls, sel);
    if (method) {
        method_setImplementation(method, newImp);
        NSLog(@"[Bypass] Hooked %s", desc);
    }
}

void applyObjCHooks() {
    // GSDKDESEncrypt
    Class desClass = objc_getClass("GSDKDESEncrypt");
    if (desClass) {
        hookMethod(desClass, @selector(httpDnsUrlWithDomain:), (IMP)replacement_httpDnsUrl, "+[GSDKDESEncrypt httpDnsUrlWithDomain:]");
        hookMethod(desClass, @selector(getIPv6:), (IMP)replacement_getIPv6, "+[GSDKDESEncrypt getIPv6:]");
    }
    // GSDKHttpDnsResolver
    Class resolverClass = objc_getClass("GSDKHttpDnsResolver");
    if (resolverClass) {
        hookMethod(resolverClass, @selector(connection:willSendRequestForAuthenticationChallenge:),
                   (IMP)replacement_authChallenge, "-[GSDKHttpDnsResolver connection:willSendRequestForAuthenticationChallenge:]");
    }
    // GSDKLoginSwitch (نفترض أن session_id, authCode, _authorizationCode هي خصائص أو أساليب)
    Class loginClass = objc_getClass("GSDKLoginSwitch");
    if (loginClass) {
        // session_id
        SEL selSession = NSSelectorFromString(@"session_id");
        if (class_getInstanceMethod(loginClass, selSession))
            hookMethod(loginClass, selSession, (IMP)replacement_session_id, "GSDKLoginSwitch.session_id");
        // authCode
        SEL selAuth = NSSelectorFromString(@"authCode");
        if (class_getInstanceMethod(loginClass, selAuth))
            hookMethod(loginClass, selAuth, (IMP)replacement_authCode, "GSDKLoginSwitch.authCode");
        // _authorizationCode
        SEL selAuthz = NSSelectorFromString(@"_authorizationCode");
        if (class_getInstanceMethod(loginClass, selAuthz))
            hookMethod(loginClass, selAuthz, (IMP)replacement_authorizationCode, "GSDKLoginSwitch._authorizationCode");
    }
}

void applyCHooks() {
    // دوال النظام
    safeHook("ptrace", (void *)hook_ptrace, (void **)&orig_ptrace, "ptrace");
    safeHook("sysctl", (void *)hook_sysctl, (void **)&orig_sysctl, "sysctl");
    
    // دوال OpenSSL (قد تكون موجودة إذا استخدم التطبيق OpenSSL الديناميكي)
    safeHook("i2d_DSA_PUBKEY", (void *)hook_i2d_DSA_PUBKEY, (void **)&orig_i2d_DSA_PUBKEY, "i2d_DSA_PUBKEY");
    safeHook("i2d_EC_PUBKEY", (void *)hook_i2d_EC_PUBKEY, (void **)&orig_i2d_EC_PUBKEY, "i2d_EC_PUBKEY");
    safeHook("i2d_PrivateKey", (void *)hook_i2d_PrivateKey, (void **)&orig_i2d_PrivateKey, "i2d_PrivateKey");
    safeHook("i2d_PublicKey", (void *)hook_i2d_PublicKey, (void **)&orig_i2d_PublicKey, "i2d_PublicKey");
    safeHook("X509_PUBKEY_set", (void *)hook_X509_PUBKEY_set, (void **)&orig_X509_PUBKEY_set, "X509_PUBKEY_set");
    safeHook("X509_REQ_check_private_key", (void *)hook_X509_REQ_check_private_key, (void **)&orig_X509_REQ_check_private_key, "X509_REQ_check_private_key");
    safeHook("EVP_EncryptInit_ex", (void *)hook_EVP_EncryptInit_ex, (void **)&orig_EVP_EncryptInit_ex, "EVP_EncryptInit_ex");
    safeHook("EVP_DecryptInit_ex", (void *)hook_EVP_DecryptInit_ex, (void **)&orig_EVP_DecryptInit_ex, "EVP_DecryptInit_ex");
    safeHook("PKCS7_encrypt", (void *)hook_PKCS7_encrypt, (void **)&orig_PKCS7_encrypt, "PKCS7_encrypt");
    safeHook("DH_generate_key", (void *)hook_DH_generate_key, (void **)&orig_DH_generate_key, "DH_generate_key");
    
    // Keychain (مزامنة KeychainSync)
    safeHook("SecItemCopyMatching", (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching, "SecItemCopyMatching");
}

// ========== [4] آلية التحميل المبكر ==========
static void image_added_callback(const struct mach_header *mh, intptr_t vmaddr_slide) {
    // نعيد تطبيق Objective-C hooks عند تحميل أي إطار جديد (قد يحتوي على الفئات)
    applyObjCHooks();
}

__attribute__((constructor)) static void init() {
    NSLog(@"[Bypass] Loading complete protection...");
    applyCHooks();            // دوال C متاحة حالاً
    applyObjCHooks();         // الفئات الحالية
    
    // تسجيل المراقبة لتحميل الصور المستقبلية
    _dyld_register_func_for_add_image(image_added_callback);
    
    // محاولة أخيرة بعد قليل (في حال تأخر تحميل بعض الفئات)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        applyObjCHooks();
    });
    NSLog(@"[Bypass] Engine ready.");
}
