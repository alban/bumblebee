#include "vmlinux.h"
#include "solo_types.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

const volatile bool show_threads = false;

struct placeholder_inner_field{
	void *dummy;
};
struct placeholder_struct {
	struct placeholder_inner_field *inner_field;
};

SEC("iter/task")
int ig_snap_proc(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	__u64 session_id = ctx->meta->session_id;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;
	pid_t parent_pid;
	static struct btf_ptr ptr = {};

	if (!task)
		return 0;

	if (!show_threads && task->tgid != task->pid)
		return 0;

	__u64 mntns_id = task->nsproxy->mnt_ns->ns.inum;

	parent = task->real_parent;
	if (!parent)
		parent_pid = -1;
	else
		parent_pid = parent->pid;

	__u32 uid = task->cred->uid.val;
	__u32 gid = task->cred->gid.val;

	BPF_SEQ_PRINTF(seq, "%d %d %d %llu %d %d %s\n",
		task->tgid, task->pid, parent_pid, mntns_id, uid, gid, task->comm);

	struct placeholder_struct *task2 = (struct placeholder_struct *) task;
        ptr.type_id = bpf_core_type_id_kernel(struct placeholder_inner_field);

        ptr.ptr = BPF_CORE_READ(task2, inner_field);

	bpf_seq_printf_btf(seq, &ptr, sizeof(ptr), 0);

	return 0;
}
