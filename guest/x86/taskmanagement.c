#include "libcflat.h"
#include "desc.h"
#include "apic-defs.h"
#include "apic.h"
#include "processor.h"
#include "vm.h"
#include "vmalloc.h"
#include "alloc_page.h"

#define MAIN_TSS_SEL (FIRST_SPARE_SEL + 0)
#define VM86_TSS_SEL (FIRST_SPARE_SEL + 8)
#define CONFORM_CS_SEL  (FIRST_SPARE_SEL + 16)
#define TASK_GATE_SEL 0x48 

static volatile int test_count;
static volatile unsigned int test_divider;

#if 0
static char *fault_addr;
static ulong fault_phys;
#endif 

static void irq_tss(void)
{
start:
	printf("IRQ task is running\n");
	//print_current_tss_info();
	test_count++;
	asm volatile ("iret");
	test_count++;
	printf("IRQ task restarts after iret.\n");
	goto start;
}


int do_ring3(void (*fn)(const char *), const char *arg)
{
    static unsigned char user_stack[4096];
    int ret;

    asm volatile ("mov %[user_ds], %%" R "dx\n\t"
            "mov %%dx, %%ds\n\t"
            "mov %%dx, %%es\n\t"
            "mov %%dx, %%fs\n\t"
            "mov %%dx, %%gs\n\t"
            "mov %%" R "sp, %%" R "cx\n\t"
            "push" W " %%" R "dx \n\t"
            "lea %[user_stack_top], %%" R "dx \n\t"
            "push" W " %%" R "dx \n\t"
            "pushf" W "\n\t"
            "push" W " %[user_cs] \n\t"
            "push" W " $1f \n\t"
            "iret" W "\n"
            "1: \n\t"
            "push %%" R "cx\n\t"

#ifndef __x86_64__
            "push %[arg]\n\t"
#endif 
            "call *%[fn]\n\t"
#ifndef __x86_64__
            "pop %%ecx\n\t"
#endif
            "pop %%" R "cx\n\t"
            "mov $1f, %%" R "dx\n\t"
            "int %[kernel_entry_vector]\n\t"
            ".section .text.entry \n\t"
            "kernel_entry: \n\t"
            "mov %%" R "cx, %%" R "sp \n\t"
            "mov %[kernel_ds], %%cx\n\t"
            "mov %%cx, %%ds\n\t"
            "mov %%cx, %%es\n\t"
            "mov %%cx, %%fs\n\t"
            "mov %%cx, %%gs\n\t"
            "jmp *%%" R "dx \n\t"
            ".section .text\n\t"
            "1:\n\t"
            : [ret] "=&a" (ret)
            : [user_ds] "i" (USER_DS),
              [user_cs] "i" (USER_CS),
              [user_stack_top]"m"(user_stack[sizeof user_stack]),
              [fn]"r"(fn),
              [arg]"D"(arg),
              [kernel_ds]"i"(KERNEL_DS),
              [kernel_entry_vector]"i"(0x20)
            : "rcx", "rdx");
    return ret;
}


static int8_t get_CPL(void) 
{
    unsigned int dst = 0;
    asm ("mov %%cs, %0\n\t"
        : "=r" (dst)
        :);
    dst = dst & 0x3;
    return (int8_t)dst;
}

static void test_call_gate(const char *msg)
{
    u16 desc_size = sizeof(tss32_t);
    puts(msg);
    int8_t dst = get_CPL();
    printf("CPL is %d\n", dst);
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x89, 0x0f);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TASK_GATE_SEL) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("excepiton vector is %d\n",exception_vector());    
    return;
}


void test_gdt_task_gate(void)
{
	/* test that calling a task by lcall works */
	test_count = 0;
	tss_intr.eip = (u32)irq_tss;
	printf("*Jump to non-task gate \n");
	/* hlt opcode is 0xf4 I use destination IP 0xf4f4f4f4 to catch
	   incorrect instruction length calculation */
	asm volatile(ASM_TRY("1f")
            "lcall $" xstr(KERNEL_DS) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n",exception_vector());
    report(">lcall to non-task gate \n", test_count == 1);
	//report("lcall", test_count == 1);
    //Jump to valid task gate
    test_count = 0;
    printf("*Jump to valid task gate\n");
    set_gdt_task_gate(TASK_GATE_SEL, TSS_INTR);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TASK_GATE_SEL) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("excepiton vector is %d\n",exception_vector());    
    report(">lcall to valid task gate\n", test_count == 1);
    //Jump to invalid task gate (reserved bit set)
    test_count = 0;
    set_gdt_entry(TASK_GATE_SEL, TSS_INTR, 0xFFFF, 0x85, 0); // task, present
    printf("*Jump to invalid task gate (reserved bit set)\n");
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TASK_GATE_SEL) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("excepiton vector is %d\n",exception_vector());    
    report(">lcall to invalid task gate\n", test_count == 2);
    //Jump to invalid task gate (bit 12 = 1H)
    test_count = 0;
    set_gdt_entry(TASK_GATE_SEL, TSS_INTR, 0, 0x95, 0);
    printf("*Jump to invalid task gate (bit 12 = 1H)\n");
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TASK_GATE_SEL) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to invalid task gate\n", test_count == 2);
    //Jump to non-present task gate
    test_count = 0;
    set_gdt_entry(TASK_GATE_SEL, TSS_INTR, 0, 0x05, 0);
    printf("*Jump to non-present task gate\n");
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TASK_GATE_SEL) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to non-present task gate\n", test_count == 2);
    //Target TSS Segment selector is 1H
    test_count = 0;
    printf("*Target TSS segment selector.TI is 1H\n");
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR_TI) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Target TSS segment selector with TI is 1H\n", test_count == 2);
    //CS.CPL > target TSS descriptor.DPL
    printf("CPL is %d\n", get_CPL()); 
    do_ring3(test_call_gate, "this is calling test call gate\n");
    report(">lcall to CS.CPL > target TSS descriptor.DPL\n", test_count == 2);
    //Target TSS Segment selector.RPL > target TSS descriptor.DPL
    test_count = 0;
    printf("*Target TSS Segment selector.RPL > target TSS descriptor.DPL\n");
    u16 desc_size = sizeof(tss32_t);
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x89, 0x0f);
    asm volatile(ASM_TRY("1f")
            "lcall $0x23, $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Target TSS Segment selector RPL > target TSS descriptor DPL\n", test_count == 2);
    //Target TSS segment descriptor is not a TSS descriptor, make the type to be 0b1010 (reserved) 
    test_count = 0;
    printf("*Target TSS segment descriptor is not a TSS descriptor\n");
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x8A, 0x0f);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Target TSS segment descriptor is not a TSS descriptor\n", test_count == 2);
    //Target TSS segment descriptor is not present
    test_count = 0;
    printf("*Target TSS segment is not present\n");
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x09, 0x0f);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Target TSS segment descriptor is not present\n", test_count == 2);
    //Target TSS segment descriptor is valid 
    test_count = 0;
    printf("*Target TSS segment is valid\n");
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x89, 0x0f);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Traget TSS segment descriptor is valid\n", test_count == 2);
    //Target TSS segment descriptor is invalid (bit 21 = 1H)
    test_count = 0;
    printf("*Target TSS segment is invalid (bit 21 = 1H)\n");
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x89, 0x2f);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Traget TSS segment descriptor is invalid (bit 21 = 1H)\n", test_count == 2);
    //Target TSS segment descriptor is invalid (bit 22 = 1H)
    test_count = 0;
    printf("*Target TSS segment is invalid (bit 22 = 1H)\n");
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x89, 0x4f);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Traget TSS segment descriptor is invalid (bit 22 = 1H)\n", test_count == 2);
    //Target TSS segment descriptor.G = 0H and limit of target TSS segment descriptor less than 67H
    test_count = 0;
    printf("*Target TSS segment descriptor.G = 0H and limit of target TSS segment descriptor less than 67H\n");
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, 0x66, 0x89, 0x00);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Traget TSS segment descriptor.G =0H and limit of target TSS segment descriptor less than 67H ", test_count == 2);
    //Target TSS segment descriptor.B is 1H
    test_count = 0;
    printf("*Target TSS segment decriptor.B is 1H\n");
    set_gdt_entry(TSS_INTR, (u32)&tss_intr, desc_size - 1, 0x8b, 0x0f);
    asm volatile(ASM_TRY("1f")
            "lcall $" xstr(TSS_INTR) ", $0xf4f4f4f4\n\t"
            "1:":::);
    printf("exception vector is %d\n", exception_vector());
    report(">lcall to Traget TSS segment descriptor.B = 1H)\n", test_count == 2);
}

int main()
{
    extern unsigned char kernel_entry;
	setup_vm();
	setup_idt();
    set_idt_entry(0x20, &kernel_entry, 3);
	setup_tss32();

	test_gdt_task_gate();
	//test_kernel_mode_int();
	//test_vm86_switch();
	//test_conforming_switch();

	return report_summary();
}
