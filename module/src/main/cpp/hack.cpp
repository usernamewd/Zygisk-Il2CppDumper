//
// Created by Perfare on 2020/7/4.
// FIXED VERSION - Proper synchronization and thread safety
//

#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>

// Global synchronization primitives
static std::atomic<bool> g_hack_started{false};
static std::atomic<bool> g_dump_completed{false};
static std::mutex g_dump_mutex;
static std::atomic<int> g_init_attempts{0};

// Global storage for game data dir (needed for JNI_OnLoad path)
static char* g_game_data_dir = nullptr;

void hack_start(const char *game_data_dir) {
    int tid = gettid();
    LOGI("hack_start: thread %d starting", tid);
    
    // Prevent multiple concurrent executions
    if (g_hack_started.exchange(true)) {
        LOGI("hack_start: already running in another thread, exiting");
        return;
    }
    
    // CRITICAL FIX: Wait for IL2CPP to be FULLY initialized
    // Not just loaded, but actually ready to accept API calls
    void* handle = nullptr;
    bool ready = false;
    
    for (int i = 0; i < 60; i++) {  // 60 seconds max wait
        handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
        if (handle) {
            // Verify IL2CPP runtime is actually functional
            // Check multiple symbols to ensure complete initialization
            auto il2cpp_domain_get = (void*(*)())xdl_sym(handle, "il2cpp_domain_get", nullptr);
            auto il2cpp_thread_attach = (void*(*)(void*))xdl_sym(handle, "il2cpp_thread_attach", nullptr);
            auto il2cpp_get_corlib = (void*(*)())xdl_sym(handle, "il2cpp_get_corlib", nullptr);
            
            if (il2cpp_domain_get && il2cpp_thread_attach && il2cpp_get_corlib) {
                // Try to get current domain - this only works after full init
                void* domain = il2cpp_domain_get();
                if (domain != nullptr) {
                    // Try to get corlib assembly - another init check
                    void* corlib = il2cpp_get_corlib();
                    if (corlib != nullptr) {
                        LOGI("IL2CPP fully initialized after %d seconds", i);
                        ready = true;
                        break;
                    }
                }
            }
            
            // Not ready yet, close and retry
            xdl_close(handle);
            handle = nullptr;
        }
        
        // Exponential backoff: sleep longer as we wait
        if (i < 10) {
            sleep(1);
        } else if (i < 30) {
            sleep(2);
        } else {
            sleep(3);
        }
    }
    
    if (!handle || !ready) {
        LOGE("hack_start: IL2CPP not initialized after timeout, aborting");
        g_hack_started = false;
        return;
    }
    
    // Double-check we haven't completed in another thread
    {
        std::lock_guard<std::mutex> lock(g_dump_mutex);
        if (g_dump_completed.load()) {
            LOGI("hack_start: dump already completed");
            xdl_close(handle);
            return;
        }
        
        LOGI("hack_start: initializing IL2CPP API and dumping");
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
        g_dump_completed = true;
    }
    
    xdl_close(handle);
    LOGI("hack_start: completed successfully");
}

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    jint attach_result = vms->AttachCurrentThread(&env, nullptr);
    if (attach_result != JNI_OK || !env) {
        LOGE("GetLibDir: Failed to attach thread");
        return {};
    }
    
    std::string result;
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                "currentApplication",
                                                                "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            if (application) {
                jclass application_clazz = env->GetObjectClass(application);
                if (application_clazz) {
                    jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                      "getApplicationInfo",
                                                                      "()Landroid/content/pm/ApplicationInfo;");
                    if (get_application_info) {
                        jobject application_info = env->CallObjectMethod(application,
                                                                         get_application_info);
                        if (application_info) {
                            jclass app_info_clazz = env->GetObjectClass(application_info);
                            if (app_info_clazz) {
                                jfieldID native_library_dir_id = env->GetFieldID(
                                        app_info_clazz, "nativeLibraryDir",
                                        "Ljava/lang/String;");
                                if (native_library_dir_id) {
                                    auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                            application_info, native_library_dir_id);
                                    if (native_library_dir_jstring) {
                                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                                        LOGI("lib dir %s", path);
                                        result = path;
                                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                                    }
                                }
                                env->DeleteLocalRef(app_info_clazz);
                            }
                            env->DeleteLocalRef(application_info);
                        }
                    }
                    env->DeleteLocalRef(application_clazz);
                }
                env->DeleteLocalRef(application);
            }
        }
        env->DeleteLocalRef(activity_thread_clz);
    }
    
    vms->DetachCurrentThread();
    return result;
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;

    void *(*loadLibrary)(const char *libpath, int flag);

    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);

    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;

    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    // Wait for houdini to be ready - longer wait for modern Android
    LOGI("NativeBridgeLoad: waiting for houdini initialization");
    sleep(5);

    auto libart = dlopen("libart.so", RTLD_NOW);
    if (!libart) {
        LOGE("NativeBridgeLoad: failed to open libart.so");
        return false;
    }
    
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart,
                                                                             "JNI_GetCreatedJavaVMs");
    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);
    
    if (!JNI_GetCreatedJavaVMs) {
        LOGE("NativeBridgeLoad: JNI_GetCreatedJavaVMs not found");
        return false;
    }
    
    JavaVM *vms_buf[1];
    JavaVM *vms = nullptr;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status != JNI_OK || num_vms == 0) {
        LOGE("GetCreatedJavaVMs error: status=%d, num_vms=%d", status, num_vms);
        return false;
    }
    vms = vms_buf[0];

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) {
        LOGE("GetLibDir error");
        return false;
    }
    
    // Check if we actually need native bridge
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("x86 native libs detected, no NativeBridge needed");
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        LOGI("native bridge: %s", native_bridge.data());
        if (!native_bridge.empty() && native_bridge != "0") {
            nb = dlopen(native_bridge.data(), RTLD_NOW);
        }
    }
    
    if (!nb) {
        LOGE("NativeBridgeLoad: failed to load native bridge");
        munmap(data, length);
        return false;
    }
    
    LOGI("nb %p", nb);
    auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
    if (!callbacks) {
        LOGE("NativeBridgeItf not found");
        munmap(data, length);
        return false;
    }
    
    LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
    LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
    LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

    int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
    if (fd < 0) {
        LOGE("memfd_create failed");
        munmap(data, length);
        return false;
    }
    
    if (ftruncate(fd, (off_t) length) < 0) {
        LOGE("ftruncate failed");
        close(fd);
        munmap(data, length);
        return false;
    }
    
    void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        LOGE("mmap failed");
        close(fd);
        munmap(data, length);
        return false;
    }
    
    memcpy(mem, data, length);
    munmap(mem, length);
    munmap(data, length);
    
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
    LOGI("arm path %s", path);

    void *arm_handle = nullptr;
    if (api_level >= 26 && callbacks->loadLibraryExt) {
        arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
    } else if (callbacks->loadLibrary) {
        arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
    }
    
    if (!arm_handle) {
        LOGE("NativeBridge loadLibrary failed");
        close(fd);
        return false;
    }
    
    LOGI("arm handle %p", arm_handle);
    
    if (!callbacks->getTrampoline) {
        LOGE("getTrampoline not available");
        close(fd);
        return false;
    }
    
    auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle,
                                                                      "JNI_OnLoad",
                                                                      nullptr, 0);
    LOGI("JNI_OnLoad %p", init);
    
    if (!init) {
        LOGE("Failed to get JNI_OnLoad trampoline");
        close(fd);
        return false;
    }
    
    // Store for JNI_OnLoad use
    if (g_game_data_dir) {
        free(g_game_data_dir);
    }
    g_game_data_dir = strdup(game_data_dir);
    
    // Call JNI_OnLoad - this will spawn the hack thread in ARM context
    init(vms, (void *) g_game_data_dir);
    
    // Don't close fd - ARM library might need it
    return true;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    int tid = gettid();
    LOGI("hack_prepare: thread %d", tid);
    
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

    // CRITICAL FIX: Ensure single entry point
    static std::atomic<bool> prepare_entered{false};
    if (prepare_entered.exchange(true)) {
        LOGI("hack_prepare: already entered, exiting duplicate");
        return;
    }

    // Store game_data_dir globally for potential JNI_OnLoad use
    if (g_game_data_dir) {
        free(g_game_data_dir);
    }
    g_game_data_dir = strdup(game_data_dir);

#if defined(__i386__) || defined(__x86_64__)
    // Try NativeBridge first on x86
    if (NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        LOGI("NativeBridgeLoad succeeded, ARM lib will handle dump");
        return;
    }
    LOGI("NativeBridgeLoad failed or not needed, using direct mode");
#endif

    // Direct execution: spawn thread with proper safeguards
    LOGI("Spawning hack thread directly");
    std::thread(hack_start, g_game_data_dir).detach();
}

#if defined(__arm__) || defined(__aarch64__)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("JNI_OnLoad called in ARM context");
    
    // CRITICAL FIX: Prevent duplicate execution
    static std::atomic<bool> onload_entered{false};
    if (onload_entered.exchange(true)) {
        LOGI("JNI_OnLoad: already called, ignoring duplicate");
        return JNI_VERSION_1_6;
    }
    
    auto game_data_dir = (const char *) reserved;
    if (!game_data_dir) {
        game_data_dir = g_game_data_dir;
    }
    
    if (!game_data_dir) {
        LOGE("JNI_OnLoad: no game_data_dir provided");
        return JNI_VERSION_1_6;
    }
    
    // CRITICAL FIX: Don't spawn new thread - use existing synchronization
    // The hack_start function already has thread-safety guards
    std::thread([game_data_dir]() {
        // Small delay to let JNI_OnLoad return and stabilize
        usleep(100000); // 100ms
        hack_start(game_data_dir);
    }).detach();
    
    return JNI_VERSION_1_6;
}

#endif
