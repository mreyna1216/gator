/**
 * Copyright 2010  ARM, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#	error Kernels prior to 2.6.32 not supported
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
#	define GATOR_DEFINE_PROBE(probe_name, proto) \
		static void probe_##probe_name(PARAMS(proto))
#	define GATOR_REGISTER_TRACE(probe_name) \
		register_trace_##probe_name(probe_##probe_name)
#	define GATOR_UNREGISTER_TRACE(probe_name) \
		unregister_trace_##probe_name(probe_##probe_name)
#else
#	define GATOR_DEFINE_PROBE(probe_name, proto) \
		static void probe_##probe_name(void *data, PARAMS(proto))
#	define GATOR_REGISTER_TRACE(probe_name) \
		register_trace_##probe_name(probe_##probe_name, NULL)
#	define GATOR_UNREGISTER_TRACE(probe_name) \
		unregister_trace_##probe_name(probe_##probe_name, NULL)
#endif
