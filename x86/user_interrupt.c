#include "libcflat.h"
#include "x86/processor.h"
#include "x86/msr.h"
#include "x86/msr.h"
#include "x86/desc.h"
#include "usermode.h"

#define RESERVED_VECTOR 0xeb
#define UINTR_NOTIFICATION_VECTOR   0xec

#define UINTR_MAX_UITT_NR 256
#define SENDUIPI_ENABLED 1
#define TESTED_UI_VEC 3

#define STUI_OPCODE "0xf3,0x0f,0x01,0xef"
#define CLUI_OPCODE "0xf3,0x0f,0x01,0xee"
#define UIRET_OPCODE "0xf3,0x0f,0x01,0xec"
#define SENDUIPI_RAX_OPCODE "0xf3,0x0f,0xc7,0xf0"

/* User Posted Interrupt Descriptor (UPID) */
struct uintr_upid {
	struct {
		u8 on:1;
		u8 sn:1;
		u8 reserved1:6;
		u8 reserved2;
		u8 nv;		/* Notification vector */
		u8 reserved3;
		u32 ndst;	/* Notification destination */
	} nc __attribute__((__packed__));;		/* Notification control */
	u64 puir;		/* Posted user interrupt requests */
} __attribute__((__aligned__(64)));

/* User Interrupt Target Table Entry (UITTE) */
struct uintr_uitt_entry {
	u8	valid:1;
	u8	reserved1:7;
	u8	user_vec;
	u8	reserved[6];
	u64	target_upid_addr;
} __attribute__((__packed__)) __attribute__((__aligned__(16)));

struct uintr_upid upid_struct;
struct uintr_uitt_entry uitt_struct[UINTR_MAX_UITT_NR];
u64 uintr_received;

extern void set_received_flag(void);
void set_received_flag(void)
{
	uintr_received = 1;
}

extern void uintr_handler(void);
asm (
	"uintr_handler:\n\t"
	"call set_received_flag\n\t"
	/**
	 * User-Interrupt delivery has pushed UIRRV on the stack at last,
	 * so need to adjust RSP before issuing UIRET instruction.
	 */
	"add $0x8,%rsp\n\t"
	".byte " UIRET_OPCODE "\n\t");

static inline void stui(void)
{
	asm volatile(".byte " STUI_OPCODE "\n\t");
}

static inline void clui(void)
{
	asm volatile(".byte " CLUI_OPCODE "\n\t");
}

static int senduipi_checking(u64 uipi_index)
{
	asm volatile(ASM_TRY("1f")
		".byte " SENDUIPI_RAX_OPCODE "\n\t"
		"1:" : : "a" (uipi_index));
	return exception_vector();
}

static int stui_checking(void)
{
	asm volatile(ASM_TRY("1f")
		".byte " STUI_OPCODE "\n\t"
		"1:" :);
	return exception_vector();
}

static void senduipi(u64 uipi_index)
{
	asm volatile(".byte " SENDUIPI_RAX_OPCODE "\n\t" :: "a"(uipi_index));
}

static uint64_t user_func(void)
{
	u64 start = rdtsc();

	do {
		pause();
	} while (rdtsc() - start < 1000000000 && uintr_received == 0);

	return 0;
}

static void enter_user_mode(void)
{
	bool raised_vector;

	run_in_user((usermode_func)user_func, RESERVED_VECTOR,
		0, 0, 0, 0, &raised_vector);
}

static void set_sender_status(void)
{
	struct uintr_uitt_entry *uitt;

	uitt = &uitt_struct[0];
	uitt->valid = 1;
	uitt->reserved1 = 0;
	uitt->reserved[0] = 0;
	uitt->reserved[1] = 0;
	uitt->reserved[2] = 0;
	uitt->reserved[3] = 0;
	uitt->reserved[4] = 0;
	uitt->user_vec = TESTED_UI_VEC;
	uitt->target_upid_addr = (u64)&upid_struct;

	wrmsr(MSR_IA32_UINTR_MISC, rdmsr(MSR_IA32_UINTR_MISC) | (UINTR_MAX_UITT_NR - 1));
	wrmsr(MSR_IA32_UINTR_TT, (u64)uitt | SENDUIPI_ENABLED);
}

static void set_receiver_status(void)
{
	struct uintr_upid *upid;

	irq_enable();
	stui();

	uintr_received = 0;

	upid = &upid_struct;
	upid->nc.on = 0;
	upid->nc.sn = 0;
	upid->nc.reserved1 = 0;
	upid->nc.reserved2 = 0;
	upid->nc.nv = UINTR_NOTIFICATION_VECTOR;
	upid->nc.reserved3 = 0;
	upid->nc.ndst = apic_id();
	upid->puir = 0;

	wrmsr(MSR_IA32_UINTR_RR, 0);
	wrmsr(MSR_IA32_UINTR_STACKADJUST, 0);
	wrmsr(MSR_IA32_UINTR_MISC, (u64)UINTR_NOTIFICATION_VECTOR << 32);
	wrmsr(MSR_IA32_UINTR_PD, (u64)upid);
	wrmsr(MSR_IA32_UINTR_HANDLER, (u64)uintr_handler);
}

int main(void)
{
	struct uintr_upid *upid = &upid_struct;
	struct uintr_uitt_entry *uitt = &uitt_struct[0];

	if (!this_cpu_has(X86_FEATURE_UINTR)) {
		printf("UINTR not enabled\n");
		return report_summary();
	}

	write_cr4(read_cr4() & ~X86_CR4_UINTR);

	report(stui_checking() == UD_VECTOR,
		"If CR4.UINTR is 0, when issuing STUI instruction - expect #UD");

	report(senduipi_checking(0) == UD_VECTOR,
		"If CR4.UINTR is 0, when issuing SENDUIPI instruction - expect #UD");

	write_cr4(read_cr4() | X86_CR4_UINTR);

	set_receiver_status();
	set_sender_status();
	wrmsr(MSR_IA32_UINTR_TT, rdmsr(MSR_IA32_UINTR_TT) & ~SENDUIPI_ENABLED);
	report(senduipi_checking(0) == UD_VECTOR,
		"If IA32_UINT_TT[0] is 0, when issuing SENDUIPI instruction - expect #UD");

	set_receiver_status();
	set_sender_status();
	report(senduipi_checking(UINTR_MAX_UITT_NR) == GP_VECTOR,
		"If the value of the register operand exceeds UITTSZ, when issuing SENDUIPI instruction - expect #GP");

	set_receiver_status();
	set_sender_status();
	uitt->valid = 0;
	report(senduipi_checking(0) == GP_VECTOR,
		"If the selected UITTE is not valid, when issuing SENDUIPI instruction - expect #GP");

	set_receiver_status();
	set_sender_status();
	uitt->reserved[0] = 1;
	report(senduipi_checking(0) == GP_VECTOR,
		"If the selected UITTE  sets any reserved bits, when issuing SENDUIPI instruction - expect #GP");

	set_receiver_status();
	set_sender_status();
	upid->nc.reserved1 = 1;
	report(senduipi_checking(0) == GP_VECTOR,
		"If the selected UPID sets any reserved bits, when issuing SENDUIPI instruction - expect #GP");

	set_receiver_status();
	set_sender_status();
	senduipi(0);
	enter_user_mode();
	report(uintr_received == 1, "After SENDUIPI, User Interrupt handler is invoked successfully.");

	set_receiver_status();
	set_sender_status();
	clui();
	senduipi(0);
	enter_user_mode();
	report(uintr_received == 0 && rdmsr(MSR_IA32_UINTR_RR) == (1 << TESTED_UI_VEC),
		"If UIF = 0, User-Interrupt Delivery won't happen.");

	set_receiver_status();
	irq_disable();
	set_sender_status();
	senduipi(0);
	enter_user_mode();
	report(uintr_received == 0, "If EFLAGS.IF is clear, User-Interrupt Notification Identification won't happen");

	set_receiver_status();
	upid->nc.sn = 1;
	set_sender_status();
	senduipi(0);
	enter_user_mode();
	report(uintr_received == 0 && upid->puir == (1 << TESTED_UI_VEC),
		"When SN=1, After SENDUIPI, the bit for user-interrupt vector"
		"will be set in posted user interrupt requests, but user interrupt handler won't be invoked.");

	set_receiver_status();
	wrmsr(MSR_IA32_UINTR_RR, (1 << TESTED_UI_VEC));
	enter_user_mode();
	report(uintr_received == 1,
		"After WRMSR to the IA32_UINTR_RR, user interrupt handler is invoked successfully.");

	return report_summary();
}
