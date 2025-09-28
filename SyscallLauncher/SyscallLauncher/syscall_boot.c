//
//  syscall_boot.c
//  SyscallLauncher
//
//  Created by 이지안 on 2025-09-28.
//

#include <mach/mach.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

typedef void (*LogCallback)(const char *message);

#define TWEAK_LOADER_PATH "/tmp/TweakLoader.dylib"

static LogCallback g_logCallback = NULL;

kern_return_t syscall_vm_allocate(vm_map_t target, vm_address_t *address, vm_size_t size, int flags) {
    return vm_allocate(target, address, size, flags);
}

kern_return_t syscall_vm_protect(vm_map_t target, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    return vm_protect(target, address, size, set_maximum, new_protection);
}

kern_return_t syscall_vm_deallocate(vm_map_t target, vm_address_t address, vm_size_t size) {
    return vm_deallocate(target, address, size);
}

static void logMessage(const char *msg) {
    if (g_logCallback) {
        g_logCallback(msg);
    }
    printf("[Syscall] %s\n", msg);
}

bool bootApp(const void *binaryData, size_t binarySize, LogCallback logCallback) {
    g_logCallback = logCallback;
    
    if (!binaryData || binarySize < sizeof(struct mach_header_64)) {
        logMessage("Invalid Mach-O binary");
        return false;
    }
    
    const struct mach_header_64 *header = (const struct mach_header_64 *)binaryData;
    if (header->magic != MH_MAGIC_64 && header->magic != MH_CIGAM_64) {
        char buf[256];
        int ret = snprintf(buf, sizeof(buf), "Not a 64-bit Mach-O. Expected: 0x%x, Got: 0x%x", MH_MAGIC_64, header->magic);
        if (ret > 0) {
            logMessage(buf);
        }
        
        const unsigned char *bytes = (const unsigned char *)binaryData;
        char debugBuf[128];
        int debugRet = snprintf(debugBuf, sizeof(debugBuf), "First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                               bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                               bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
        if (debugRet > 0) {
            logMessage(debugBuf);
        }
        
        return false;
    }
    if (header->magic == MH_CIGAM_64) {
        logMessage("Detected MH_CIGAM_64 (byte-swapped) magic; proceeding on little-endian platform");
    }
    
    logMessage("Parsing Mach-O header");
    
    vm_address_t allocAddr;
    kern_return_t kr = syscall_vm_allocate(mach_task_self(), &allocAddr, binarySize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        char buf[256];
        int ret = snprintf(buf, sizeof(buf), "vm_allocate failed: %d", kr);
        if (ret > 0) {
            logMessage(buf);
        }
        return false;
    }
    {
        char buf[256];
        int ret = snprintf(buf, sizeof(buf), "Allocated VM at 0x%lx", allocAddr);
        if (ret > 0) {
            logMessage(buf);
        }
    }
    
    memcpy((void *)allocAddr, binaryData, binarySize);
    
    struct mach_header_64 *patchedHeader = (struct mach_header_64 *)allocAddr;
    uint32_t oldFiletype = patchedHeader->filetype;
    patchedHeader->filetype = MH_DYLIB;
    {
        char buf[256];
        int ret = snprintf(buf, sizeof(buf), "Patched filetype: %u -> %u", oldFiletype, patchedHeader->filetype);
        if (ret > 0) {
            logMessage(buf);
        }
    }
    logMessage("Injected LC_LOAD_DYLIB for TweakLoader");
    
    kr = syscall_vm_protect(mach_task_self(), allocAddr, binarySize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        char buf[256];
        int ret = snprintf(buf, sizeof(buf), "vm_protect failed: %d", kr);
        if (ret > 0) {
            logMessage(buf);
        }
        syscall_vm_deallocate(mach_task_self(), allocAddr, binarySize);
        return false;
    }
    logMessage("Set RX protections");
    
    char tmpdir[PATH_MAX];
    const char *env_tmp = getenv("TMPDIR");
    if (env_tmp) {
        strncpy(tmpdir, env_tmp, sizeof(tmpdir) - 1);
        tmpdir[sizeof(tmpdir) - 1] = '\0';
    } else {
        strncpy(tmpdir, "/tmp", sizeof(tmpdir));
        tmpdir[sizeof(tmpdir) - 1] = '\0';
    }
    
    char dylibPath[PATH_MAX];
    snprintf(dylibPath, sizeof(dylibPath), "%s/SyscallLauncher_%d_%u.dylib", tmpdir, getpid(), arc4random());

    int fd = open(dylibPath, O_CREAT | O_TRUNC | O_WRONLY, 0700);
    if (fd < 0) {
        char buf[256];
        int ret = snprintf(buf, sizeof(buf), "Failed to open temp dylib path '%s' for writing (errno: %d)", dylibPath, errno);
        if (ret > 0) {
            logMessage(buf);
        }
        syscall_vm_deallocate(mach_task_self(), allocAddr, binarySize);
        return false;
    }
    ssize_t wrote = write(fd, (const void *)allocAddr, (size_t)binarySize);
    close(fd);
    if (wrote < 0 || (size_t)wrote != binarySize) {
        char buf[256];
        int ret = snprintf(buf, sizeof(buf), "Failed to write full dylib contents to temp file (wrote: %zd, expected: %zu)", wrote, binarySize);
        if (ret > 0) {
            logMessage(buf);
        }
        unlink(dylibPath);
        syscall_vm_deallocate(mach_task_self(), allocAddr, binarySize);
        return false;
    }

    void *handle = dlopen(dylibPath, RTLD_NOW);
    if (!handle) {
        const char *err = dlerror();
        if (err) {
            logMessage(err);
        } else {
            logMessage("dlopen failed (no error message)");
        }
        unlink(dylibPath);
        syscall_vm_deallocate(mach_task_self(), allocAddr, binarySize);
        return false;
    }
    logMessage("Loaded dylib handle from temp file");
    
    void (*entry)() = (void (*)())dlsym(handle, "main");
    if (entry) {
        logMessage("Calling entry point");
        entry();
    } else {
        logMessage("No main symbol found");
    }
    // dlclose(handle);
    // syscall_vm_deallocate(mach_task_self(), allocAddr, binarySize);
    unlink(dylibPath);
    syscall_vm_deallocate(mach_task_self(), allocAddr, binarySize);
    
    logMessage("Boot completed");
    return true;
}
