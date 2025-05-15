#pragma once
#import "dobby_defines.h"
#import "../Utils/Macros.h"
#include "../Utils/definations.h"
#include <libgen.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach/vm_page_size.h>
#include <Foundation/Foundation.h>
#include <map>
#include <deque>
#include <vector>
#include <array>
#include <substrate.h>


//HOOK BEGIN
#pragma GCC diagnostic ignored "-Warc-performSelector-leaks"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wincomplete-implementation"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-W#warnings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wreorder"
#pragma GCC diagnostic ignored "-Wwritable-strings"
#pragma GCC diagnostic ignored "-Wtrigraphs"

#define STATIC_HOOK_CODEPAGE_SIZE PAGE_SIZE
#define STATIC_HOOK_DATAPAGE_SIZE PAGE_SIZE

uint64_t va2rva(struct mach_header_64* header, uint64_t va);
void* rva2data(struct mach_header_64* header, uint64_t rva);
NSMutableData* load_macho_data(NSString* path);
NSMutableData* add_hook_section(NSMutableData* macho);
bool hex2bytes(char* bytes, unsigned char* buffer);

uint64_t calc_patch_hash(uint64_t vaddr, char* patch);

NSString* StaticInlineHookPatch(char* machoPath, uint64_t vaddr, char* patch);

void* find_module_by_path(char* machoPath);
StaticInlineHookBlock* find_hook_block(void* base, uint64_t vaddr);

void* StaticInlineHookFunction(char* machoPath, uint64_t vaddr, void* replace);

void saveMacho(char* machoPath);

BOOL ActiveCodePatch(char* machoPath, uint64_t vaddr, char* patch);
BOOL DeactiveCodePatch(char* machoPath, uint64_t vaddr, char* patch);

/*JB*/
uint64_t getRealOffset(uint64_t offset);
MemoryPatch patchOffset(uint64_t offset, std::string hexBytes);


#ifdef JAILED
inline NSString* result_string;
#define HOOK(x, y, z) \
result_string = StaticInlineHookPatch(EXCUTABLEPATH, x, nullptr); \
if (result_string) { \
     debug_log(@"Hook result: %s", result_string.UTF8String); \
    void* result = StaticInlineHookFunction(EXCUTABLEPATH, x, (void *) y); \
     debug_log(@"Hook result %p", result); \
    *(void **) (&z) = (void*) result; \
}
#define ONETIMEPATCH(addr, patch)\
result_string = StaticInlineHookPatch(EXCUTABLEPATH, addr, (char*)patch); \
if (result_string){\
     debug_log(result_string);\
    if(ActiveCodePatch(EXCUTABLEPATH, addr,(char*)patch))\
         debug_log(@"OneTime Patch Succeed.");\
}
#define ADDSWITCHPATCH(addr, patch)\
result_string = StaticInlineHookPatch(EXCUTABLEPATH, addr, patch);\
debug_log(result_string);\

#define ACTIVATESWITCHPATCH(addr, patch)\
if (ActiveCodePatch(EXCUTABLEPATH, addr, patch)){\
     debug_log(@"Patch Activated.");\
}
#define DEACTIVATESWITCHPATCH(addr, patch)\
if (DeactiveCodePatch(EXCUTABLEPATH, addr, patch)){\
     debug_log(@"Patch DEActivated.");\
}
#else
#define HOOK(x, y, z) \
     jbHOOK(x,y,z);
#define ONETIMEPATCH(addr, patch)\
patchOffset(addr, patch);
#endif