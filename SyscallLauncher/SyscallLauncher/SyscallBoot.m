//
//  SyscallBoot.m
//  SyscallLauncher
//
//  Created by 이지안 on 2025-09-28.
//

#import <Foundation/Foundation.h>
#import "SyscallBoot.h"
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <dlfcn.h>

extern bool bootApp(const void *binaryData, size_t binarySize, LogCallback logCallback);

@implementation SyscallBoot

+ (BOOL)bootAppWithPatchedData:(NSData *)data logCallback:(LogCallback)callback {
    return [self bootAppWithPatchedData:data logCallback:callback error:nil];
}

+ (BOOL)bootAppWithPatchedData:(NSData *)data logCallback:(LogCallback)callback error:(NSError **)error {
    if (!data || [data length] == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"SyscallBoot" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Invalid data"}];
        }
        return NO;
    }
    
    const void *bytes = [data bytes];
    size_t size = [data length];
    
    bool success = bootApp(bytes, size, callback);
    
    if (!success && error) {
        *error = [NSError errorWithDomain:@"SyscallBoot" code:2 userInfo:@{NSLocalizedDescriptionKey: @"Boot failed"}];
    }
    
    return success ? YES : NO;
}

@end
