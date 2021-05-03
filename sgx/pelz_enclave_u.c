#include "pelz_enclave_u.h"
#include <errno.h>

typedef struct ms_key_table_init_t {
	int ms_retval;
} ms_key_table_init_t;

typedef struct ms_key_table_destroy_t {
	int ms_retval;
} ms_key_table_destroy_t;

typedef struct ms_pelz_request_handler_impl_t {
	RequestResponseStatus ms_retval;
	RequestType ms_request_type;
	CharBuf ms_key_id;
	CharBuf ms_data;
	CharBuf* ms_output;
} ms_pelz_request_handler_impl_t;

typedef struct ms_key_load_t {
	int ms_retval;
	KeyEntry* ms_key_values;
} ms_key_load_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL pelz_enclave_key_load(void* pms)
{
	ms_key_load_t* ms = SGX_CAST(ms_key_load_t*, pms);
	ms->ms_retval = key_load(ms->ms_key_values);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pelz_enclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pelz_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pelz_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pelz_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pelz_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pelz_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_pelz_enclave = {
	7,
	{
		(void*)pelz_enclave_key_load,
		(void*)pelz_enclave_u_sgxssl_ftime,
		(void*)pelz_enclave_sgx_oc_cpuidex,
		(void*)pelz_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)pelz_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)pelz_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)pelz_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t key_table_init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_key_table_init_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_pelz_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t key_table_destroy(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_key_table_destroy_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_pelz_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t pelz_request_handler_impl(sgx_enclave_id_t eid, RequestResponseStatus* retval, RequestType request_type, CharBuf key_id, CharBuf data, CharBuf* output)
{
	sgx_status_t status;
	ms_pelz_request_handler_impl_t ms;
	ms.ms_request_type = request_type;
	ms.ms_key_id = key_id;
	ms.ms_data = data;
	ms.ms_output = output;
	status = sgx_ecall(eid, 2, &ocall_table_pelz_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

