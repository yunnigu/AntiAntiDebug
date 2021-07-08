#line 1 "/Users/myxa/Desktop/Hook_test/AntiAntiDebug/AntiAntiDebug/AntiAntiDebug.xm"
#import <substrate.h>
#import <sys/sysctl.h>
extern "C" {
#include "hookzz.h"
}
#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>


struct section_64 *zz_macho_get_section_64_via_name(struct mach_header_64 *header, char *sect_name);
zpointer zz_vm_search_data(const zpointer start_addr, zpointer end_addr, zbyte *data, zsize data_len);
zpointer zz_vm_search_data1(const zpointer start_addr, zpointer end_addr, zbyte *data, zbyte *data1, zbyte *data2, zbyte *data3, zsize data_len);
struct segment_command_64 *zz_macho_get_segment_64_via_name(struct mach_header_64 *header, char *segment_name);

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif
#if !defined(SYS_ptrace)
#define SYS_ptrace 26
#endif
#if !defined(SYS_syscall)
#define SYS_syscall 0
#endif
#if !defined(SYS_sysctl)
#define SYS_sysctl 202
#endif


struct section_64 * zz_macho_get_section_64_via_name(struct segment_command_64 *seg_cmd_64,
                                 char *sect_name) {
    struct section_64 *sect_64;
    
    sect_64 = (struct section_64 *)((zaddr)seg_cmd_64 + sizeof(struct segment_command_64));
    for (zsize j = 0; j < seg_cmd_64->nsects; j++, sect_64 = (struct section_64 *)((zaddr)sect_64 + sizeof(struct section_64))) {
        if (!strcmp(sect_64->sectname, sect_name)) {
            return sect_64;
        }
    }
}


zpointer zz_vm_search_data(const zpointer start_addr, zpointer end_addr, zbyte *data,
                           zsize data_len)
{
    zpointer curr_addr;
    if (start_addr <= (zpointer)0)
        printf("search address start_addr(%p) < 0", (zpointer)start_addr);
    if (start_addr > end_addr)
        printf("search start_add(%p) < end_addr(%p)", (zpointer)start_addr, (zpointer)end_addr);
    
    curr_addr = start_addr;
    
    while (end_addr > curr_addr)
    {
        if (!memcmp(curr_addr, data, data_len))
        {
            return curr_addr;
        }
        curr_addr = (zpointer)((zaddr)curr_addr + data_len);
    }
    return 0;
}


zpointer zz_vm_search_data1(const zpointer start_addr, zpointer end_addr, zbyte *data, zbyte *data1, zbyte *data2, zbyte *data3, zsize data_len)
{
    zpointer curr_addr, curr_addr1, curr_addr2, curr_addr3;
    if (start_addr <= (zpointer)0)
        printf("search address start_addr(%p) < 0", (zpointer)start_addr);
    if (start_addr > end_addr)
        printf("search start_add(%p) < end_addr(%p)", (zpointer)start_addr, (zpointer)end_addr);
    
    curr_addr = start_addr;
    
    while (end_addr > curr_addr)
    {
        if (!memcmp(curr_addr, data, data_len))
        {
            curr_addr1 = (zpointer)((zaddr)curr_addr + data_len);
            if (!memcmp(curr_addr1, data1, data_len))
            {
                curr_addr2 = (zpointer)((zaddr)curr_addr1 + data_len);
                if (!memcmp(curr_addr2, data2, data_len))
                {
                    curr_addr3 = (zpointer)((zaddr)curr_addr2 + data_len);
                    if (!memcmp(curr_addr3, data3, data_len))
                    {
                        return curr_addr;
                    }
                }
            }
        }
        curr_addr = (zpointer)((zaddr)curr_addr + data_len);
    }
    return 0;
}




struct segment_command_64 *
zz_macho_get_segment_64_via_name(struct mach_header_64 *header,
                                 char *segment_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    
    load_cmd = (struct load_command *)((zaddr)header + sizeof(struct mach_header_64));
    for (zsize i = 0; i < header->ncmds;
         i++, load_cmd = (struct load_command *)((zaddr)load_cmd + load_cmd->cmdsize)) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            if(!strcmp(seg_cmd_64->segname, segment_name)) {
                return seg_cmd_64;
            }
        }
    }
    return NULL;
}




void hook_svc_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    int num_syscall;
    int request;
    num_syscall = (int)(uint64_t)(rs->general.regs.x16);
    request = (int)(uint64_t)(rs->general.regs.x0);
    
    if (num_syscall == SYS_syscall) {
        int arg1 = (int)(uint64_t)(rs->general.regs.x1);
        if (request == SYS_ptrace && arg1 == PT_DENY_ATTACH) {
            *(unsigned long *)(&rs->general.regs.x1) = 0;
            NSLog(@"[AntiAntiDebug] catch 'SVC #0x80; syscall(ptrace)' and bypass");
        }else if (request == SYS_sysctl) {
            STACK_SET(callstack, (char *)"num_syscall", num_syscall, int);
            STACK_SET(callstack, (char *)"info_ptr", rs->general.regs.x3, zpointer);
        }
    } else if (num_syscall == SYS_ptrace) {
        request = (int)(uint64_t)(rs->general.regs.x0);
        if (request == PT_DENY_ATTACH) {
            *(unsigned long *)(&rs->general.regs.x0) = 0;
            NSLog(@"[AntiAntiDebug] catch 'SVC-0x80; ptrace' and bypass");
        }
    }
    else if(num_syscall == SYS_sysctl) {
        STACK_SET(callstack, (char *)"num_syscall", num_syscall, int);
        STACK_SET(callstack, (char *)"info_ptr", rs->general.regs.x2, zpointer);
    }
}

void hook_svc_half_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    
    if(STACK_CHECK_KEY(callstack, (char *)"num_syscall")) {
        int num_syscall = STACK_GET(callstack, (char *)"num_syscall", int);
        struct kinfo_proc *info = STACK_GET(callstack, (char *)"info_ptr", struct kinfo_proc *);
        if (num_syscall == SYS_sysctl)
        {

            info->kp_proc.p_flag &= ~(P_TRACED);
        }else if (num_syscall == SYS_syscall)
        {

            info->kp_proc.p_flag &= ~(P_TRACED);
        }
    }
}



static int (*orig_ptrace) (int request, pid_t pid, caddr_t addr, int data);
static int my_ptrace (int request, pid_t pid, caddr_t addr, int data){
    if(request == 31){
        NSLog(@"[AntiAntiDebug] - ptrace request is PT_DENY_ATTACH");
        return 0;
    }
    return orig_ptrace(request,pid,addr,data);
}

static void* (*orig_dlsym)(void* handle, const char* symbol);
static void* my_dlsym(void* handle, const char* symbol){
    if(strcmp(symbol, "ptrace") == 0){
        NSLog(@"[AntiAntiDebug] - dlsym get ptrace symbol");
        return (void*)my_ptrace;
    }
       return orig_dlsym(handle, symbol);
}

static int (*orig_sysctl)(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize);
static int my_sysctl(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize){
    int ret = orig_sysctl(name,namelen,info,infosize,newinfo,newinfosize);
    if(namelen == 4 && name[0] == 1 && name[1] == 14 && name[2] == 1){
        struct kinfo_proc *info_ptr = (struct kinfo_proc *)info;
        if(info_ptr && (info_ptr->kp_proc.p_flag & P_TRACED) != 0){
            NSLog(@"[AntiAntiDebug] - sysctl query trace status.");
            info_ptr->kp_proc.p_flag ^= P_TRACED;
            if((info_ptr->kp_proc.p_flag & P_TRACED) == 0){
                NSLog(@"[AntiAntiDebug] trace status reomve success!");
            }
        }
    }
    return ret;
}

static void* (*orig_syscall)(int code, va_list args);
static void* my_syscall(int code, va_list args){
    int request;
    va_list newArgs;
    va_copy(newArgs, args);
    if(code == 26){
        request = (long)args;
        if(request == 31){
            NSLog(@"[AntiAntiDebug] - syscall call ptrace, and request is PT_DENY_ATTACH");
            return nil;
        }
    }
    return (void*)orig_syscall(code, newArgs);
}

void hook_svc_x80() {
    zaddr svc_x80_addr;
    zaddr curr_addr, text_start_addr, text_end_addr;
    uint32_t svc_x80_byte = 0xd4001001;
    
    const struct mach_header *header = _dyld_get_image_header(0);
    
    struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
    zsize slide = (zaddr)header - (zaddr)seg_cmd_64->vmaddr;
    
    struct section_64 *sect_64 = zz_macho_get_section_64_via_name((struct segment_command_64 *)seg_cmd_64, (char *)"__text");
    
    text_start_addr = slide + (zaddr)sect_64->addr;
    text_end_addr = text_start_addr + sect_64->size;
    curr_addr = text_start_addr;
    
    while (curr_addr < text_end_addr) {
        svc_x80_addr = (zaddr)zz_vm_search_data((zpointer)curr_addr, (zpointer)text_end_addr, (zbyte *)&svc_x80_byte, 4);
        if (svc_x80_addr) {
            NSLog(@"-------AntiAntiDebug svc #0x80 adress %p--------", (void *)(svc_x80_addr - slide));
            ZzBuildHookAddress((void *)svc_x80_addr, (void *)(svc_x80_addr + 4), hook_svc_pre_call, hook_svc_half_call, TRUE);
            ZzEnableHook((void *)svc_x80_addr);
            curr_addr = svc_x80_addr + 4;
        } else {
            break;
        }
    }
}


void hook_svc_x0() {
    zaddr svc_x0_addr;
    zaddr curr_addr, text_start_addr, text_end_addr;
    uint32_t svc_x0_byte1 = 0x52800010;
    uint32_t svc_x0_byte2 = 0xd2800340;
    uint32_t svc_x0_byte3 = 0xd28003e1;
    uint32_t svc_x0_byte4 = 0xd4000001;
    uint32_t svc_x0_byte = 0xd4000001;
    const struct mach_header *header = _dyld_get_image_header(0);
    
    struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
    zsize slide = (zaddr)header - (zaddr)seg_cmd_64->vmaddr;
    
    struct section_64 *sect_64 = zz_macho_get_section_64_via_name((struct segment_command_64 *)seg_cmd_64, (char *)"__text");
    
    text_start_addr = slide + (zaddr)sect_64->addr;
    text_end_addr = text_start_addr + sect_64->size;
    curr_addr = text_start_addr;
    
    while (curr_addr < text_end_addr) {
        svc_x0_addr = (zaddr)zz_vm_search_data1((zpointer)curr_addr, (zpointer)text_end_addr, (zbyte *)&svc_x0_byte1, (zbyte *)&svc_x0_byte2, (zbyte *)&svc_x0_byte3, (zbyte *)&svc_x0_byte4, 4);
        if (svc_x0_addr) {
            NSLog(@"-------AntiAntiDebug svc #0x0 adress %p--------", (void *)(svc_x0_addr - slide));
            unsigned long nop_bytes = 0xD503201F;
            ZzRuntimeCodePatch(svc_x0_addr+8, (zpointer)&nop_bytes, 4);
            ZzRuntimeCodePatch(svc_x0_addr+12, (zpointer)&nop_bytes, 4);


            curr_addr = svc_x0_addr + 4;
        } else {
            break;
        }
    }
    
    curr_addr = text_start_addr;
    while (curr_addr < text_end_addr) {
        svc_x0_addr = (zaddr)zz_vm_search_data((zpointer)curr_addr, (zpointer)text_end_addr, (zbyte *)&svc_x0_byte, 4);
        if (svc_x0_addr) {
            NSLog(@"-------AntiAntiDebug svc #0x0 1 adress %p--------", (void *)(svc_x0_addr - slide));
            ZzBuildHookAddress((void *)svc_x0_addr, (void *)(svc_x0_addr + 4), hook_svc_pre_call, hook_svc_half_call, TRUE);
            ZzEnableHook((void *)svc_x0_addr);
            curr_addr = svc_x0_addr + 4;
        } else {
            break;
        }
    }
    
}


static __attribute__((constructor)) void _logosLocalCtor_26e359e8(int __unused argc, char __unused **argv, char __unused **envp)
{
    NSDictionary *pref = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.yunnigu.AntiAntiDebug.plist"];
    NSString *keyPath = [NSString stringWithFormat:@"AntiAntiDebugEnabled-%@", [[NSBundle mainBundle] bundleIdentifier]];
    if ([[pref objectForKey:keyPath] boolValue]) {
        NSLog(@"-------AntiAntiDebug🐲🐲🐲----------Start🐯🐯🐯-------------");
        
        MSHookFunction((void *)MSFindSymbol(NULL,"_ptrace"),(void*)my_ptrace,(void**)&orig_ptrace);
        
        MSHookFunction((void *)dlsym,(void*)my_dlsym,(void**)&orig_dlsym);
        
        MSHookFunction((void *)sysctl,(void*)my_sysctl,(void**)&orig_sysctl);
        
        MSHookFunction((void *)syscall,(void*)my_syscall,(void**)&orig_syscall);
        
        hook_svc_x80();
        
        hook_svc_x0();
        NSLog(@"-------AntiAntiDebug🐲🐲🐲----------End🐯🐯🐯-------------");
    }
    
}
