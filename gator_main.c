/**
 * Copyright (C) ARM Limited 2010. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

static unsigned long gator_protocol_version = 2;

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/dcookies.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

#ifndef CONFIG_GENERIC_TRACER
#ifndef CONFIG_TRACING
#warning gator requires the kernel to have CONFIG_GENERIC_TRACER or CONFIG_TRACING defined
#endif
#endif

#ifndef CONFIG_PROFILING
#warning gator requires the kernel to have CONFIG_PROFILING defined
#endif

#ifndef CONFIG_HIGH_RES_TIMERS
#warning gator requires the kernel to have CONFIG_HIGH_RES_TIMERS defined
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#error kernels prior to 2.6.32 are not supported
#endif

#include "gator.h"

/******************************************************************************
 * DEFINES
 ******************************************************************************/
#define BUFFER_SIZE_DEFAULT		131072

#define NO_COOKIE				0UL
#define INVALID_COOKIE			~0UL

#define PROTOCOL_FRAME				~0
#define PROTOCOL_START_TICK			1
#define PROTOCOL_END_TICK			3
#define PROTOCOL_START_BACKTRACE	5
#define PROTOCOL_END_BACKTRACE		7
#define PROTOCOL_COOKIE				9
#define PROTOCOL_SCHEDULER_TRACE	11
#define PROTOCOL_COUNTERS			13
#define PROTOCOL_ANNOTATE			15

#if defined(__arm__)
#define PC_REG regs->ARM_pc
#else
#define PC_REG regs->ip
#endif

/******************************************************************************
 * PER CPU
 ******************************************************************************/
static unsigned long gator_buffer_size;
static unsigned long gator_backtrace_depth;

static unsigned long gator_started;
static unsigned long gator_buffer_opened;
static unsigned long gator_timer_count;
static unsigned long gator_dump;
static DEFINE_MUTEX(start_mutex);
static DEFINE_MUTEX(gator_buffer_mutex);
static DECLARE_WAIT_QUEUE_HEAD(gator_buffer_wait);
/* atomic_t because wait_event checks it outside of gator_buffer_mutex */
static DEFINE_PER_CPU(atomic_t, gator_buffer_ready);
static DEFINE_PER_CPU(int, gator_tick);
static DEFINE_PER_CPU(int, gator_first_time);

/******************************************************************************
 * Prototypes
 ******************************************************************************/
static void gator_buffer_write_packed_int(int cpu, unsigned int x);
static void gator_buffer_write_string(int cpu, char *x);
static void gator_add_trace(int cpu, unsigned int address);
static uint64_t gator_get_time(void);

/******************************************************************************
 * Application Includes
 ******************************************************************************/
#include "gator_cookies.c"
#include "gator_trace_sched.c"
#include "gator_backtrace.c"
#include "gator_annotate.c"
#include "gator_events.c"
#include "gator_fs.c"

/******************************************************************************
 * Misc
 ******************************************************************************/
#if defined(__arm__)
u32 gator_cpuid(void)
{
	u32 val;
	asm volatile("mrc p15, 0, %0, c0, c0, 0" : "=r" (val));
	return (val >> 4) & 0xfff;
}
#endif
/******************************************************************************
 * Buffer management
 ******************************************************************************/
static uint32_t use_buffer_size;
static uint32_t use_buffer_mask;
static DEFINE_PER_CPU(int, use_buffer_seq);
static DEFINE_PER_CPU(int, use_buffer_read);
static DEFINE_PER_CPU(int, use_buffer_write);
static DEFINE_PER_CPU(int, use_buffer_commit);
static DEFINE_PER_CPU(char *, use_buffer);

static void gator_buffer_write_packed_int(int cpu, unsigned int x)
{
	uint32_t write = per_cpu(use_buffer_write, cpu);
	uint32_t mask = use_buffer_mask;
	char *buffer = per_cpu(use_buffer, cpu);
	int write0 = (write + 0) & mask;
	int write1 = (write + 1) & mask;
	int write2 = (write + 2) & mask;
	int write3 = (write + 3) & mask;
	int write4 = (write + 4) & mask;
	int write5 = (write + 5) & mask;

	if ((x & 0xffffff80) == 0) {
		buffer[write0] = x & 0x7f;
		per_cpu(use_buffer_write, cpu) = write1;
	} else if ((x & 0xffffc000) == 0) {
		buffer[write0] = x | 0x80;
		buffer[write1] = (x>>7) & 0x7f;
		per_cpu(use_buffer_write, cpu) = write2;
	} else if ((x & 0xffe00000) == 0) {
		buffer[write0] = x | 0x80;
		buffer[write1] = (x>>7) | 0x80;
		buffer[write2] = (x>>14) & 0x7f;
		per_cpu(use_buffer_write, cpu) = write3;
	} else if ((x & 0xf0000000) == 0) {
		buffer[write0] = x | 0x80;
		buffer[write1] = (x>>7) | 0x80;
		buffer[write2] = (x>>14) | 0x80;
		buffer[write3] = (x>>21) & 0x7f;
		per_cpu(use_buffer_write, cpu) = write4;
	} else {
		buffer[write0] = x | 0x80;
		buffer[write1] = (x>>7) | 0x80;
		buffer[write2] = (x>>14) | 0x80;
		buffer[write3] = (x>>21) | 0x80;
		buffer[write4] = (x>>28) & 0x0f;
		per_cpu(use_buffer_write, cpu) = write5;
	}
}

static void gator_buffer_write_bytes(int cpu, char *x, int len)
{
	uint32_t write = per_cpu(use_buffer_write, cpu);
	uint32_t mask = use_buffer_mask;
	char *buffer = per_cpu(use_buffer, cpu);
	int i;

	for (i = 0; i < len; i++) {
		buffer[write] = x[i];
		write = (write + 1) & mask;
	}

	per_cpu(use_buffer_write, cpu) = write;
}

static void gator_buffer_write_string(int cpu, char *x)
{
	int len = strlen(x);
	gator_buffer_write_packed_int(cpu, len);
	gator_buffer_write_bytes(cpu, x, len);
}

static void gator_buffer_header(int cpu)
{
	gator_buffer_write_packed_int(cpu, PROTOCOL_FRAME);
	gator_buffer_write_packed_int(cpu, cpu);
	gator_buffer_write_packed_int(cpu, per_cpu(use_buffer_seq, cpu));
}

static void gator_buffer_commit(int cpu)
{
	per_cpu(use_buffer_commit, cpu) = per_cpu(use_buffer_write, cpu);

	per_cpu(use_buffer_seq, cpu)++;
	gator_buffer_header(cpu);

	atomic_set(&per_cpu(gator_buffer_ready, cpu), 1);
	wake_up(&gator_buffer_wait);
}

static void gator_buffer_check(int cpu)
{
	int commit = 0;
	int available = per_cpu(use_buffer_write, cpu) - per_cpu(use_buffer_read, cpu);
	if (available < 0) {
		available += use_buffer_size;
	}

	if (!cpu && gator_dump) {
		gator_dump = 0;
		commit = 1;
	} else if (available >= ((use_buffer_size * 3) / 4)) {
		commit = 1;
	} else if (cpu && (per_cpu(use_buffer_seq, cpu) < per_cpu(use_buffer_seq, 0))) {
		commit = 1;
	}

	if (commit) {
		gator_buffer_commit(cpu);
	}
}

static void gator_add_trace(int cpu, unsigned int address)
{
	off_t offset = 0;
	unsigned long cookie = get_address_cookie(cpu, current, address & ~1, &offset);

	if (cookie == NO_COOKIE || cookie == INVALID_COOKIE) {
		offset = address;
	}

	gator_buffer_write_packed_int(cpu, offset & ~1);
	gator_buffer_write_packed_int(cpu, cookie);
}

static void gator_add_sample(int cpu, struct pt_regs * const regs)
{
	int inKernel = regs ? !user_mode(regs) : 1;
	unsigned long cookie = !inKernel ? get_exec_cookie(cpu, current) : NO_COOKIE;

	gator_buffer_write_packed_int(cpu, PROTOCOL_START_BACKTRACE);

	// TGID::PID::inKernel
	gator_buffer_write_packed_int(cpu, cookie);
	gator_buffer_write_packed_int(cpu, (unsigned int)current->tgid);
	gator_buffer_write_packed_int(cpu, (unsigned int)current->pid);
	gator_buffer_write_packed_int(cpu, inKernel);

	// get_irq_regs() will return NULL outside of IRQ context (e.g. nested IRQ)
	if (regs) {
		if (inKernel) {
			gator_buffer_write_packed_int(cpu, PC_REG & ~1);
			gator_buffer_write_packed_int(cpu, 0); // cookie
		} else {
			// Cookie+PC
			gator_add_trace(cpu, PC_REG);

			// Backtrace
			if (gator_backtrace_depth)
				arm_backtrace_eabi(cpu, regs, gator_backtrace_depth);
		}
	}

	gator_buffer_write_packed_int(cpu, PROTOCOL_END_BACKTRACE);
}

static void gator_write_packet(int cpu, int type, int len, int *buffer)
{
	int i;
	gator_buffer_write_packed_int(cpu, type);
	gator_buffer_write_packed_int(cpu, len);
	for (i = 0; i < len; i++) {
		gator_buffer_write_packed_int(cpu, buffer[i]);
	}
}

static void gator_write_annotate(int cpu, int len, int *buffer)
{
	int pos = 0;

	while (pos < len) {
		unsigned int tid = buffer[pos++];
		unsigned int bytes = buffer[pos++];
		unsigned int words = (bytes + 3) / 4;
		char *ptr = (char *)&buffer[pos];
		pos += words;

		gator_buffer_write_packed_int(cpu, PROTOCOL_ANNOTATE);
		gator_buffer_write_packed_int(cpu, tid);
		gator_buffer_write_packed_int(cpu, bytes);
		gator_buffer_write_bytes(cpu, ptr, bytes);
	}
}

/******************************************************************************
 * Interrupt Processing
 ******************************************************************************/
static gator_interface *gi = NULL;

static void gator_timer_interrupt(unsigned int ticks)
{
	struct pt_regs * const regs = get_irq_regs();
	int cpu = raw_smp_processor_id();
	int *buffer, len;
	gator_interface *i;

	// check full backtrace has enough space, otherwise may
	// have breaks between samples in the same callstack
	if (per_cpu(gator_first_time, cpu)) {
		per_cpu(gator_first_time, cpu) = 0;

		for (i = gi; i != NULL; i = i->next) {
			if (i->read) {
				i->read(NULL);
			}
		}
		per_cpu(gator_tick, cpu) += ticks;
		return;
	}

	// Header
	gator_buffer_write_packed_int(cpu, PROTOCOL_START_TICK);			// Escape

	// Output scheduler
	len = gator_trace_sched_read(&buffer);
	if (len > 0) {
		gator_write_packet(cpu, PROTOCOL_SCHEDULER_TRACE, len, buffer);
	}

	// Output annotate
	len = gator_annotate_read(&buffer);
	if (len > 0)
		gator_write_annotate(cpu, len, buffer);

	// Output counters
	for (i = gi; i != NULL; i = i->next) {
		if (i->read) {
			len = i->read(&buffer);
			if (len > 0) {
				gator_write_packet(cpu, PROTOCOL_COUNTERS, len, buffer);
			}
		}
	}

	// Output backtrace
	gator_add_sample(cpu, regs);

	// Timer Tick
	gator_write_packet(cpu, PROTOCOL_END_TICK, 1, &per_cpu(gator_tick, cpu));
	per_cpu(gator_tick, cpu) += ticks;

	// Check and commit
	gator_buffer_check(cpu);
}

/******************************************************************************
 * hrtimer
 ******************************************************************************/
DEFINE_PER_CPU(struct hrtimer, percpu_hrtimer);
extern void gator_timer_stop(void);
static int hrtimer_running;
static ktime_t profiling_interval;
static atomic_t num_active_timers;

static enum hrtimer_restart gator_hrtimer_notify(struct hrtimer *hrtimer)
{
	unsigned int ticks = (unsigned int)hrtimer_forward_now(hrtimer, profiling_interval);
	gator_timer_interrupt(ticks);
	return HRTIMER_RESTART;
}

int gator_timer_init(void)
{
	return 0;
}

static void __gator_timer_start(void *unused)
{
	int cpu = smp_processor_id();

	struct hrtimer *hrtimer = &per_cpu(percpu_hrtimer, cpu);
	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer->function = gator_hrtimer_notify;
	hrtimer_start(hrtimer, profiling_interval, HRTIMER_MODE_REL_PINNED);
	atomic_inc(&num_active_timers);

	per_cpu(gator_first_time, cpu) = 1;
	per_cpu(gator_tick, cpu) = 0;
}

int gator_timer_start(unsigned long setup)
{
	atomic_set(&num_active_timers, 0);

	if (!setup) {
		pr_err("gator: cannot start due to a system tick value of zero");
		return -1;
	} else if (hrtimer_running) {
		pr_notice("gator: high res timer already running");
		return 0;
	}

	hrtimer_running = 1;

	// calculate profiling interval
	profiling_interval = ns_to_ktime(1000000000UL / setup);

	// timer interrupt
	on_each_cpu(__gator_timer_start, NULL, 1);

	if (atomic_read(&num_active_timers) != num_present_cpus()) {
		pr_err("gator: %d timer(s) started yet %d cpu(s) detected, please bring all cpus online manually and restart\n", atomic_read(&num_active_timers), nr_cpu_ids);
		gator_timer_stop();
		return -1;
	}

	return 0;
}

void __gator_timer_stop(void *unused)
{
	struct hrtimer *hrtimer = &per_cpu(percpu_hrtimer, smp_processor_id());
	hrtimer_cancel(hrtimer);
	atomic_dec(&num_active_timers);
}

void gator_timer_stop(void)
{
	if (hrtimer_running) {
		int previously_running = atomic_read(&num_active_timers);
		hrtimer_running = 0;
		on_each_cpu(__gator_timer_stop, NULL, 1);
		if (atomic_read(&num_active_timers) != 0) {
			pr_err("gator: %d timers stopped yet %d were running, it is advised to quit and restart gatord", previously_running - atomic_read(&num_active_timers), previously_running);
			atomic_set(&num_active_timers, 0);
		}
	}
}

static uint64_t gator_get_time(void)
{
	struct timespec ts;
	uint64_t timestamp;

	ktime_get_ts(&ts);
	timestamp = timespec_to_ns(&ts);

	return timestamp;
}

/******************************************************************************
 * Main
 ******************************************************************************/
int gator_event_install(int (*event_install)(gator_interface *))
{
	gator_interface *ni = (gator_interface*)kmalloc(sizeof(gator_interface), GFP_KERNEL);
	if (ni == NULL) {
		return -1;
	}

	ni->create_files = NULL;
	ni->init = NULL;
	ni->start = NULL;
	ni->stop = NULL;
	ni->read = NULL;
	ni->next = NULL;

	// Initialize ni gator interface
	if (!event_install(ni)) {
		if (gi == NULL) {
			// Set gi to point to the first gator interface
			gi = ni;
		} else {
			// Link the gator interfaces
			gator_interface *i = gi;
			while (i->next) {
				i = i->next;
			}
			i->next = ni;
		}
	} else {
		kfree(ni);
	}

	return 0;
}

static int gator_init(void)
{
	gator_interface *i;
	int key = 0;

	if (gator_timer_init())
		return -1;
	if (gator_trace_sched_init())
		return -1;
	if (gator_annotate_init())
		return -1;

	// set up gator interface linked list structure
	if (gator_events_install())
		return -1;

	// initialize all events
	for (i = gi; i != NULL; i = i->next) {
		if (i->init) {
			if (i->init(&key)) {
				return -1;
			}
		}
	}

	return 0;
}

static int gator_start(void)
{
	gator_interface *i, *f;

	// start all events
	for (i = gi; i != NULL; i = i->next) {
		if (i->start) {
			if (i->start()) {
				goto events_failure;
			}
		}
	}

	if (gator_annotate_start())
		goto annotate_failure;
	if (gator_trace_sched_start())
		goto sched_failure;
	if (gator_timer_start(gator_timer_count))
		goto timer_failure;

	return 0;

timer_failure:
	gator_trace_sched_stop();
sched_failure:
	gator_annotate_stop();
annotate_failure:
events_failure:
	for (f = gi; f != i; f = f->next) {
		f->stop();
	}

	return -1;
}

static void gator_stop(void)
{
	gator_interface *i;

	// stop all interrupt callback reads before tearing down other interfaces
	gator_timer_stop();
	gator_annotate_stop();
	gator_trace_sched_stop();

	// stop all events
	for (i = gi; i != NULL; i = i->next) {
		if (i->stop) {
			i->stop();
		}
	}
}

static void gator_exit(void)
{
	gator_interface *i = gi;

	while (i) {
		gator_interface *p = i;
		i = i->next;
		kfree(p);
	}
}

/******************************************************************************
 * Filesystem
 ******************************************************************************/
/* fopen("buffer") */
static int gator_op_setup(void)
{
	int err = 0;
	int cpu;

	mutex_lock(&start_mutex);

	use_buffer_size = gator_buffer_size;
	use_buffer_mask = use_buffer_size - 1;

	// must be a power of 2
	if (use_buffer_size & (use_buffer_size - 1)) {
		err = -ENOEXEC;
		goto setup_error;
	}

	for_each_possible_cpu(cpu) {
		per_cpu(use_buffer, cpu) = vmalloc(use_buffer_size);
		if (!per_cpu(use_buffer, cpu)) {
			err = -ENOMEM;
			goto setup_error;
		}

		atomic_set(&per_cpu(gator_buffer_ready, cpu), 0);
		per_cpu(use_buffer_seq, cpu) = 0;
		per_cpu(use_buffer_read, cpu) = 0;
		per_cpu(use_buffer_write, cpu) = 0;
		per_cpu(use_buffer_commit, cpu) = 0;
		gator_buffer_header(cpu);
	}

setup_error:
	mutex_unlock(&start_mutex);
	return err;
}

/* Actually start profiling (echo 1>/dev/gator/enable) */
static int gator_op_start(void)
{
	int err = 0;

	mutex_lock(&start_mutex);

	if (gator_started || gator_start())
		err = -EINVAL;
	else
		gator_started = 1;

	cookies_initialize();

	mutex_unlock(&start_mutex);

	return err;
}

/* echo 0>/dev/gator/enable */
static void gator_op_stop(void)
{
	int cpu;

	mutex_lock(&start_mutex);

	if (gator_started) {
		gator_stop();

		mutex_lock(&gator_buffer_mutex);

		/* wake up the daemon to read what remains */
		for_each_possible_cpu(cpu) {
			gator_buffer_commit(cpu);
			atomic_set(&per_cpu(gator_buffer_ready, cpu), 1);
		}
		gator_started = 0;
		cookies_release();
		wake_up(&gator_buffer_wait);

		mutex_unlock(&gator_buffer_mutex);
	}

	mutex_unlock(&start_mutex);
}

static void gator_shutdown(void)
{
	int cpu;

	mutex_lock(&start_mutex);

	for_each_possible_cpu(cpu) {
		mutex_lock(&gator_buffer_mutex);
		vfree(per_cpu(use_buffer, cpu));
		per_cpu(use_buffer, cpu) = NULL;
		per_cpu(use_buffer_seq, cpu) = 0;
		per_cpu(use_buffer_read, cpu) = 0;
		per_cpu(use_buffer_write, cpu) = 0;
		per_cpu(use_buffer_commit, cpu) = 0;
		mutex_unlock(&gator_buffer_mutex);
	}

	mutex_unlock(&start_mutex);
}

static int gator_set_backtrace(unsigned long val)
{
	int err = 0;

	mutex_lock(&start_mutex);

	if (gator_started)
		err = -EBUSY;
	else
		gator_backtrace_depth = val;

	mutex_unlock(&start_mutex);

	return err;
}

static ssize_t enable_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	return gatorfs_ulong_to_user(gator_started, buf, count, offset);
}

static ssize_t enable_write(struct file *file, char const __user *buf, size_t count, loff_t *offset)
{
	unsigned long val;
	int retval;

	if (*offset)
		return -EINVAL;

	retval = gatorfs_ulong_from_user(&val, buf, count);
	if (retval)
		return retval;

	if (val)
		retval = gator_op_start();
	else
		gator_op_stop();

	if (retval)
		return retval;
	return count;
}

static const struct file_operations enable_fops = {
	.read		= enable_read,
	.write		= enable_write,
};

static int event_buffer_open(struct inode *inode, struct file *file)
{
	int err = -EPERM;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (test_and_set_bit_lock(0, &gator_buffer_opened))
		return -EBUSY;

	/* Register as a user of dcookies
	 * to ensure they persist for the lifetime of
	 * the open event file
	 */
	err = -EINVAL;
	file->private_data = dcookie_register();
	if (!file->private_data)
		goto out;

	if ((err = gator_op_setup()))
		goto fail;

	/* NB: the actual start happens from userspace
	 * echo 1 >/dev/gator/enable
	 */

	return 0;

fail:
	dcookie_unregister(file->private_data);
out:
	__clear_bit_unlock(0, &gator_buffer_opened);
	return err;
}

static int event_buffer_release(struct inode *inode, struct file *file)
{
	int cpu;
	gator_op_stop();
	gator_shutdown();
	dcookie_unregister(file->private_data);
	for_each_possible_cpu(cpu) {
		atomic_set(&per_cpu(gator_buffer_ready, cpu), 0);
	}
	__clear_bit_unlock(0, &gator_buffer_opened);
	return 0;
}

static int event_buffer_ready(void)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		if (atomic_read(&per_cpu(gator_buffer_ready, cpu)))
			return cpu;
	}
	return -1;
}

static ssize_t event_buffer_read(struct file *file, char __user *buf,
				 size_t count, loff_t *offset)
{
	int retval = -EINVAL;
	int commit, length1, length2, read;
	char *buffer1, *buffer2;
	int cpu;

	/* do not handle partial reads */
	if (count != use_buffer_size || *offset)
		return -EINVAL;

	wait_event_interruptible(gator_buffer_wait, event_buffer_ready() >= 0 || !gator_started);
	cpu = event_buffer_ready();

	if (signal_pending(current))
		return -EINTR;

	if (cpu < 0)
		return 0;

	/* should not happen */
	if (!atomic_read(&per_cpu(gator_buffer_ready, cpu)))
		return -EAGAIN;

	mutex_lock(&gator_buffer_mutex);

	retval = -EFAULT;

	/* May happen if the buffer is freed during pending reads. */
	if (!per_cpu(use_buffer, cpu)) {
		retval = -EFAULT;
		goto out;
	}

	/* determine the size of two halves */
	commit = per_cpu(use_buffer_commit, cpu);
	read = per_cpu(use_buffer_read, cpu);
	length1 = commit - read;
	length2 = 0;
	buffer1 = &(per_cpu(use_buffer, cpu)[read]);
	buffer2 = &(per_cpu(use_buffer, cpu)[0]);
	if (length1 < 0) {
		length1 = use_buffer_size - read;
		length2 = commit;
	}

	/* start, middle or end */
	if (length1 > 0) {
		if (copy_to_user(&buf[0], buffer1, length1)) {
			goto out;
		}
	}

	/* possible wrap around */
	if (length2 > 0) {
		if (copy_to_user(&buf[length1], buffer2, length2)) {
			goto out;
		}
	}

	/* update position */
	retval = length1 + length2;
	per_cpu(use_buffer_read, cpu) = (read + retval) & use_buffer_mask;

	atomic_set(&per_cpu(gator_buffer_ready, cpu), 0);

	/* kick just in case we've lost an SMP event */
	wake_up(&gator_buffer_wait);

out:
	mutex_unlock(&gator_buffer_mutex);
	return retval;
}

const struct file_operations gator_event_buffer_fops = {
	.open		= event_buffer_open,
	.release	= event_buffer_release,
	.read		= event_buffer_read,
};

static ssize_t depth_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	return gatorfs_ulong_to_user(gator_backtrace_depth, buf, count,
					offset);
}

static ssize_t depth_write(struct file *file, char const __user *buf, size_t count, loff_t *offset)
{
	unsigned long val;
	int retval;

	if (*offset)
		return -EINVAL;

	retval = gatorfs_ulong_from_user(&val, buf, count);
	if (retval)
		return retval;

	retval = gator_set_backtrace(val);

	if (retval)
		return retval;
	return count;
}

static const struct file_operations depth_fops = {
	.read		= depth_read,
	.write		= depth_write
};

static const char gator_cpu_type[] = "gator";

static ssize_t cpu_type_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	return gatorfs_str_to_user(gator_cpu_type, buf, count, offset);
}

static const struct file_operations cpu_type_fops = {
	.read		= cpu_type_read,
};

void gator_op_create_files(struct super_block *sb, struct dentry *root)
{
	struct dentry *dir;
	gator_interface *i;

	/* reinitialize default values */
	gator_buffer_size =	BUFFER_SIZE_DEFAULT;

	gatorfs_create_file(sb, root, "enable", &enable_fops);
	gatorfs_create_file(sb, root, "buffer", &gator_event_buffer_fops);
	gatorfs_create_file(sb, root, "backtrace_depth", &depth_fops);
	gatorfs_create_file(sb, root, "cpu_type", &cpu_type_fops);
	gatorfs_create_ulong(sb, root, "buffer_size", &gator_buffer_size);
	gatorfs_create_ulong(sb, root, "tick", &gator_timer_count);
	gatorfs_create_ulong(sb, root, "dump", &gator_dump);
	gatorfs_create_ro_ulong(sb, root, "version", &gator_protocol_version);

	// Annotate interface
	gator_annotate_create_files(sb, root);

	// Linux Events
	dir = gatorfs_mkdir(sb, root, "events");
	for (i = gi; i != NULL; i = i->next) {
		if (i->create_files) {
			i->create_files(sb, dir);
		}
	}
}

/******************************************************************************
 * Module
 ******************************************************************************/
static int gator_initialized;

static int __init gator_module_init(void)
{
	if (gatorfs_register()) {
		return -1;
	}

	if (gator_init()) {
		gatorfs_unregister();
		return -1;
	}

	gator_initialized = 1;
#ifdef GATOR_DEBUG
	pr_err("gator_module_init");
#endif
	return 0;
}

static void __exit gator_module_exit(void)
{
#ifdef GATOR_DEBUG
	pr_err("gator_module_exit");
#endif
	gatorfs_unregister();
	if (gator_initialized) {
		gator_initialized = 0;
		gator_exit();
	}
}

module_init(gator_module_init);
module_exit(gator_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ARM Ltd");
MODULE_DESCRIPTION("Gator system profiler");
