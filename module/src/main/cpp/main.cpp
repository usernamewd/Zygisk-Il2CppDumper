#include <cstring>
#include <thread>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cinttypes>
#include <atomic>
#include "hack.h"
#include "zygisk.hpp"
#include "game.h"
#include "log.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Validate args
        if (!args || !args->nice_name) {
            LOGW("preAppSpecialize: invalid args");
            return;
        }
        
        auto package_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!package_name) {
            LOGW("preAppSpecialize: failed to get package name");
            return;
        }
        
        const char* app_data_dir = nullptr;
        if (args->app_data_dir) {
            app_data_dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        }
        
        preSpecialize(package_name, app_data_dir);
        
        env->ReleaseStringUTFChars(args->nice_name, package_name);
        if (app_data_dir) {
            env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!enable_hack) {
            return;
        }
        
        LOGI("postAppSpecialize: spawning hack for %s", game_data_dir);
        
        // CRITICAL FIX: Ensure single execution
        static std::atomic<bool> post_specialize_called{false};
        if (post_specialize_called.exchange(true)) {
            LOGW("postAppSpecialize: already called, ignoring");
            return;
        }
        
        // Spawn hack thread with detached lifecycle
        // hack_prepare has its own thread-safety guards
        std::thread([this]() {
            hack_prepare(game_data_dir, data, length);
        }).detach();
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool enable_hack = false;
    char *game_data_dir = nullptr;
    void *data = nullptr;
    size_t length = 0;

    void preSpecialize(const char *package_name, const char *app_data_dir) {
        if (!package_name) return;
        
        if (strcmp(package_name, GamePackageName) == 0) {
            LOGI("detect game: %s", package_name);
            enable_hack = true;
            
            if (app_data_dir) {
                game_data_dir = new char[strlen(app_data_dir) + 1];
                strcpy(game_data_dir, app_data_dir);
            } else {
                // Fallback: construct from package name
                game_data_dir = new char[256];
                snprintf(game_data_dir, 256, "/data/data/%s", package_name);
            }

#if defined(__i386__)
            auto path = "zygisk/armeabi-v7a.so";
#elif defined(__x86_64__)
            auto path = "zygisk/arm64-v8a.so";
#else
            const char* path = nullptr;
#endif

#if defined(__i386__) || defined(__x86_64__)
            if (!path) {
                LOGW("Unknown architecture");
                return;
            }
            
            int dirfd = api->getModuleDir();
            if (dirfd < 0) {
                LOGW("getModuleDir failed");
                return;
            }
            
            int fd = openat(dirfd, path, O_RDONLY);
            if (fd < 0) {
                LOGW("Unable to open %s", path);
                return;
            }
            
            struct stat sb{};
            if (fstat(fd, &sb) < 0) {
                LOGW("fstat failed");
                close(fd);
                return;
            }
            
            length = sb.st_size;
            if (length == 0) {
                LOGW("Empty ARM library");
                close(fd);
                return;
            }
            
            data = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
            
            if (data == MAP_FAILED) {
                LOGW("mmap failed");
                data = nullptr;
                length = 0;
            } else {
                LOGI("Loaded ARM library: %zu bytes", length);
            }
#endif
        } else {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
