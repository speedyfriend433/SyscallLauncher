//
//  SyscallBoot.h
//  SyscallLauncher
//
//  Created by 이지안 on 2025-09-28.
//

#ifndef SyscallBoot_h
#define SyscallBoot_h

#import <Foundation/Foundation.h>
#include <stddef.h>
#include <stdbool.h>

typedef void (*LogCallback)(const char * _Nonnull message);

extern bool bootApp(const void *binaryData, size_t binarySize, LogCallback logCallback);

@interface SyscallBoot : NSObject

+ (BOOL)bootAppWithPatchedData:(NSData *)data logCallback:(LogCallback)callback;
+ (BOOL)bootAppWithPatchedData:(NSData *)data logCallback:(LogCallback)callback error:(NSError **)error;

@end

#endif 
