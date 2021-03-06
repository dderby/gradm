#ifndef __GRADM_DEFS_H
#define __GRADM_DEFS_H

#ifndef GRSEC_DIR
#define GRSEC_DIR		"/etc/grsec"
#endif
#define GRLEARN_PATH		"/sbin/grlearn"
#define GRADM_PATH		"/sbin/gradm"
#define GRPAM_PATH		"/sbin/gradm_pam"
#define GRDEV_PATH		"/dev/grsec"
#define GR_POLICY_PATH 		GRSEC_DIR "/policy"
#define GR_PW_PATH 		GRSEC_DIR "/pw"
#define GR_LEARN_CONFIG_PATH	GRSEC_DIR "/learn_config"
#define GR_LEARN_PIPE_PATH	GRSEC_DIR "/.grlearn.pipe"
#define GR_LEARN_PID_PATH	GRSEC_DIR "/.grlearn.pid"

#define GR_VERSION		"3.1"
#define GRADM_VERSION		0x3100


#define LEARN_LOG_BUFFER_SIZE	(16 * 1024 * 1024)

#define GR_PWONLY		0
#define GR_PWANDSUM		1

#define GR_PW_LEN		128
#define GR_SALT_SIZE		16
#define GR_SHA_SUM_SIZE		32

#define GR_SPROLE_LEN		64

#define GR_FEXIST		0x1
#define GR_FFAKE		0x2
#define GR_FLEARN		0x4

#define CHK_FILE		0
#define CHK_CAP			1

#undef PATH_MAX
#define PATH_MAX 		4096
#define MAX_LINE_LEN 		5000

// CAP_AUDIT_READ
#define CAP_MAX			37

#define SYSCALL_MAX		326

#define MAX_INCLUDE_DEPTH	20
#define MAX_NEST_DEPTH		8
#define MAX_SYMLINK_DEPTH	8

#ifndef RLIMIT_LOCKS
#define RLIMIT_LOCKS 10
#endif
#ifndef RLIMIT_SIGPENDING
#define RLIMIT_SIGPENDING 11
#endif
#ifndef RLIMIT_MSGQUEUE
#define RLIMIT_MSGQUEUE 12
#endif
#ifndef RLIMIT_NICE
#define RLIMIT_NICE 13
#endif
#ifndef RLIMIT_RTPRIO
#define RLIMIT_RTPRIO 14
#endif
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

#ifndef AF_RDS
#define AF_RDS 21
#endif
#ifndef AF_SNA
#define AF_SNA 22
#endif
#ifndef AF_IRDA
#define AF_IRDA 23
#endif
#ifndef AF_PPOX
#define AF_PPOX 24
#endif
#ifndef AF_WANPIPE
#define AF_WANPIPE 25
#endif
#ifndef AF_LLC
#define AF_LLC 26
#endif
#ifndef AF_CAN
#define AF_CAN 29
#endif
#ifndef AF_TIPC
#define AF_TIPC 30
#endif
#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#ifndef AF_IUCV
#define AF_IUCV 32
#endif
#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef AF_ISDN
#define AF_ISDN 34
#endif
#ifndef AF_PHONET
#define AF_PHONET 35
#endif
#ifndef AF_IEEE802154
#define AF_IEEE802154 36
#endif
#ifndef AF_CAIF
#define AF_CAIF 37
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef AF_NFC
#define AF_NFC 39
#endif
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
#undef AF_MAX
#define AF_MAX 41

#define GR_NLIMITS	32
#define GR_CRASH_RES	31

#undef CAP_TO_INDEX
#undef CAP_TO_MASK
#undef cap_raise
#undef cap_lower
#undef cap_raised
#define CAP_TO_INDEX(x)     ((x) >> 5)        /* 1 << 5 == bits in __u32 */
#define CAP_TO_MASK(x)      (1U << ((x) & 31)) /* mask for indexed __u32 */
#define cap_raise(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] |= CAP_TO_MASK(flag))
#define cap_lower(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] &= ~CAP_TO_MASK(flag))
#define cap_raised(c, flag) ((c).cap[CAP_TO_INDEX(flag)] & CAP_TO_MASK(flag))
#define CAP_SETUID 7
#define CAP_SETGID 6

#undef SYSCALL_TO_INDEX
#undef SYSCALL_TO_MASK
#undef syscall_raise
#undef syscall_lower
#undef syscall_raised
#define SYSCALL_TO_INDEX(x)    ((x) >> 5)         /* 1 << 5 == bits in __u32 */
#define SYSCALL_TO_MASK(x)     (1U << ((x) & 31)) /* mask for indexed __u32 */
#define syscall_raise(sc, flag) ((sc).syscall[SYSCALL_TO_INDEX(flag)] |= SYSCALL_TO_MASK(flag))
#define syscall_lower(sc, flag) ((sc).syscall[SYSCALL_TO_INDEX(flag)] &= ~SYSCALL_TO_MASK(flag))
#define syscall_raised(sc, flag) ((sc).cap[CAP_TO_INDEX(flag)] & CAP_TO_MASK(flag))

enum {
	GRADM_DISABLE 	= 0,
	GRADM_ENABLE 	= 1,
	GRADM_SPROLE 	= 2,
	GRADM_OLDRELOAD = 3,
	GRADM_MODSEGV 	= 4,
	GRADM_STATUS 	= 5,
	GRADM_UNSPROLE 	= 6,
	GRADM_PASSSET	= 7,
	GRADM_SPROLEPAM = 8,
	GRADM_RELOAD	= 9
};

enum {
	GR_IP_BIND 	= 0x01,
	GR_IP_CONNECT 	= 0x02,
	GR_IP_INVERT 	= 0x04,
	GR_SOCK_FAMILY  = 0x20
};

enum {
	GR_ID_USER 	= 0x01,
	GR_ID_GROUP 	= 0x02,
};

enum {
	GR_ID_ALLOW	= 0x01,
	GR_ID_DENY	= 0x02,
};

enum {
	GR_READ 	= 0x00000001,
	GR_APPEND 	= 0x00000002,
	GR_WRITE 	= 0x00000004,
	GR_EXEC 	= 0x00000008,
	GR_FIND 	= 0x00000010,
	GR_INHERIT 	= 0x00000020,
	GR_SETID 	= 0x00000040,
	GR_CREATE 	= 0x00000080,
	GR_DELETE 	= 0x00000100,
	GR_LINK		= 0x00000200,
	GR_AUDIT_READ 	= 0x00000400,
	GR_AUDIT_APPEND = 0x00000800,
	GR_AUDIT_WRITE 	= 0x00001000,
	GR_AUDIT_EXEC 	= 0x00002000,
	GR_AUDIT_FIND 	= 0x00004000,
	GR_AUDIT_INHERIT= 0x00008000,
	GR_AUDIT_SETID 	= 0x00010000,
	GR_AUDIT_CREATE = 0x00020000,
	GR_AUDIT_DELETE = 0x00040000,
	GR_AUDIT_LINK	= 0x00080000,
	GR_PTRACERD 	= 0x00100000,
	GR_NOPTRACE	= 0x00200000,
	GR_SUPPRESS 	= 0x00400000,
	GR_NOLEARN	= 0x00800000,
	GR_INIT_TRANSFER= 0x01000000,
	GR_OBJ_REPLACE	= 0x02000000
};

enum {
	GR_ROLE_USER 	= 0x0001,
	GR_ROLE_GROUP 	= 0x0002,
	GR_ROLE_DEFAULT = 0x0004,
	GR_ROLE_SPECIAL = 0x0008,
	GR_ROLE_AUTH 	= 0x0010,
	GR_ROLE_NOPW 	= 0x0020,
	GR_ROLE_GOD 	= 0x0040,
	GR_ROLE_LEARN 	= 0x0080,
	GR_ROLE_TPE 	= 0x0100,
	GR_ROLE_DOMAIN 	= 0x0200,
	GR_ROLE_PAM 	= 0x0400,
	GR_ROLE_PERSIST = 0x0800,
	GR_ROLE_ISID	= 0x1000,
	GR_ROLE_IGNORENOEXIST = 0x8000
};

enum {
	GR_DELETED = 0x80000000
};

enum {
	GR_KILL 	= 0x00000001,
	GR_VIEW 	= 0x00000002,
	GR_PROTECTED 	= 0x00000004,
	GR_LEARN 	= 0x00000008,
	GR_IGNORE 	= 0x00000010,
	GR_OVERRIDE 	= 0x00000020,
	GR_PROTSHM 	= 0x00000040,
	GR_KILLPROC 	= 0x00000080,
	GR_KILLIPPROC 	= 0x00000100,
	GR_NOTROJAN 	= 0x00000200,
	GR_PROTPROCFD 	= 0x00000400,
	GR_PROCACCT 	= 0x00000800,
	GR_RELAXPTRACE  = 0x00001000,
	GR_INHERITLEARN = 0x00004000,
	GR_PROCFIND	= 0x00008000,
	GR_POVERRIDE	= 0x00010000,
	GR_KERNELAUTH	= 0x00020000,
	GR_ATSECURE	= 0x00040000,
	GR_SHMEXEC	= 0x00080000,
	GR_GLOBANCHOR	= 0x00100000,
	GR_SUBJ_REPLACE	= 0x00200000
};

enum {
	GR_DONT_LEARN_ALLOWED_IPS = 0x00000001,
	GR_SPLIT_ROLES = 0x00000002
};

/* internal use only.  not to be modified */

typedef struct _gr_cap_t {
	u_int32_t cap[2];
} gr_cap_t;

typedef struct _gr_syscall_t {
	u_int32_t syscall[12];
} gr_syscall_t;

struct capability_set {
	const char *cap_name;
	int cap_val;
};

struct family_set {
	const char *family_name;
	int family_val;
};

struct paxflag_set {
	const char *paxflag_name;
	u_int16_t paxflag_val;
};

struct systemcall_set {
	const char *syscall_name;
	u_int16_t syscall_val;
};

struct namespace_set {
	const char *namespace_name;
	u_int32_t namespace_val;
};

struct rlimconv {
	const char *name;
	unsigned short val;
};

struct chk_perm {
	unsigned short type;
	u_int32_t w_modes;
	u_int32_t u_modes;
	gr_cap_t w_caps;
	gr_cap_t u_caps;
};

struct role_allowed_ip {
	u_int32_t addr;
	u_int32_t netmask;

	struct role_allowed_ip *prev;
	struct role_allowed_ip *next;
};

struct ip_acl {
	char *iface;
	u_int32_t addr;
	u_int32_t netmask;
	u_int16_t low, high;
	u_int8_t mode;		// connect or bind
	u_int32_t type;		// stream, dgram, raw..etc
	u_int32_t proto[8];		// we have to support all 255 protocols

	struct ip_acl *prev;
	struct ip_acl *next;
};

struct file_acl {
	const char *filename;
	u_int64_t inode;
	u_int32_t dev;
	u_int32_t mode;

	struct proc_acl *nested;
	struct file_acl *globbed;

	struct file_acl *prev;
	struct file_acl *next;
};

enum {
	VAR_FILE_OBJECT = 0,
	VAR_NET_OBJECT = 1,
	VAR_CAP_OBJECT = 2
};

struct var_object {
	union {
		struct {
			const char *filename;
			u_int32_t mode;
		} file_obj;
		struct {
			struct ip_acl ip;
			u_int8_t mode;
			const char *host;
		} net_obj;
		struct {
			const char *cap;
			const char *audit;
		} cap_obj;
	};
	unsigned int type;

	struct var_object *prev;
	struct var_object *next;
};

struct role_transition {
	const char *rolename;

	struct role_transition *prev;
	struct role_transition *next;
};

struct role_acl {
	const char *rolename;
	uid_t uidgid;
	u_int16_t roletype;

	u_int16_t auth_attempts;
	unsigned long expires;

	struct proc_acl *root_label;
	struct gr_hash_struct *hash;

	struct role_acl *prev;
	struct role_acl *next;

	struct role_transition *transitions;
	struct role_allowed_ip *allowed_ips;
	uid_t *domain_children;
	u_int16_t domain_child_num;

	u_int16_t  umask;

	struct proc_acl **subj_hash;
	u_int32_t subj_hash_size;
};

struct proc_acl {
	const char *filename;
	u_int64_t inode;
	u_int32_t dev;
	u_int32_t mode;
	gr_cap_t cap_mask;
	gr_cap_t cap_drop;
	gr_cap_t cap_invert_audit;

	struct rlimit res[GR_NLIMITS];
	u_int32_t resmask;

	u_int8_t user_trans_type;
	u_int8_t group_trans_type;
	uid_t *user_transitions;
	gid_t *group_transitions;
	u_int16_t user_trans_num;
	u_int16_t group_trans_num;

	u_int32_t sock_families[2];
	u_int32_t ip_proto[8];
	u_int32_t ip_type;
	struct ip_acl **ips;
	u_int32_t ip_num;
	u_int32_t inaddr_any_override;

	u_int32_t crashes;
	unsigned long expires;

	struct proc_acl *parent_subject;
	struct gr_hash_struct *hash;
	struct proc_acl *prev;
	struct proc_acl *next;

	struct file_acl **obj_hash;
	u_int32_t obj_hash_size;
	u_int16_t pax_flags;

	gr_syscall_t syscall_mask;
	gr_syscall_t syscall_drop;

	u_int32_t namespaces;
};

struct gr_learn_ip_node {
	struct gr_learn_ip_node *prev;
	struct gr_learn_ip_node *next;
	u_int8_t ip_node;
	u_int16_t **ports;
	u_int32_t ip_proto[8];
	u_int32_t ip_type;
	unsigned char root_node:1;
	unsigned char all_low_ports:1;
	unsigned char all_high_ports:1;
	struct gr_learn_ip_node *parent;
	struct gr_learn_ip_node *leaves;
};

struct gr_learn_role_entry {
	struct gr_learn_role_entry *prev;
	struct gr_learn_role_entry *next;
	const char *rolename;
	u_int16_t rolemode;
	unsigned int id;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};

struct gr_learn_group_node {
	struct gr_learn_group_node *prev;
	struct gr_learn_group_node *next;
	char *rolename;
	gid_t gid;
	struct gr_learn_user_node *users;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};

struct gr_learn_file_tmp_node {
	char *filename;
	u_int32_t key;
	u_int32_t mode;
};

struct gr_learn_user_node {
	struct gr_learn_user_node *prev;
	struct gr_learn_user_node *next;
	char *rolename;
	uid_t uid;
	int multgroups;
	struct gr_learn_group_node *group;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *subject_list;
	struct gr_learn_ip_node *allowed_ips;
};

struct gr_learn_subject_node {
	gr_cap_t cap_raise;
	struct rlimit res[GR_NLIMITS];
	u_int32_t resmask;
	u_int16_t pax_flags;
	u_int32_t inaddr_any_override;
	u_int32_t sock_families[2];
};

struct gr_learn_file_node {
	struct gr_learn_file_node *prev;
	struct gr_learn_file_node *next;
	char *filename;
	u_int32_t mode;
	struct gr_learn_file_node *leaves;
	struct gr_learn_file_node *parent;
	struct gr_hash_struct *hash;
	struct gr_learn_file_node *object_list;
	struct gr_learn_ip_node *connect_list;
	struct gr_learn_ip_node *bind_list;
	unsigned int **user_trans_list;
	unsigned int **group_trans_list;
	struct gr_learn_subject_node *subject;
	unsigned char dont_display:1;
};

struct gr_pw_entry {
	unsigned char rolename[GR_SPROLE_LEN];
	unsigned char passwd[GR_PW_LEN];
	unsigned char sum[GR_SHA_SUM_SIZE];
	unsigned char salt[GR_SALT_SIZE];
	u_int32_t segv_dev;
	u_int64_t segv_inode;
	uid_t segv_uid;
	u_int16_t mode;
};

/* We use this to keep track of deleted files, since each subject needs
   to agree on an inode/dev
*/

struct deleted_file {
	const char *filename;
	u_int64_t ino;
	struct deleted_file *next;
};

/* to keep track of symlinks, for processing after all other objects have
   been added
*/

struct symlink {
	struct role_acl *role;
	struct file_acl *obj;
	struct proc_acl *subj;
	const char *policy_file;
	unsigned long lineno;
	struct symlink *next;
};

/* to keep track of globbed files, so that the ordering of their anchor
   doesn't matter
*/

struct glob_file {
	struct role_acl *role;
	struct proc_acl *subj;
	const char *filename;
	u_int32_t mode;
	int type;
	const char *policy_file;
	unsigned long lineno;
	struct glob_file *next;
};

extern struct glob_file *glob_files_head;
extern struct glob_file *glob_files_tail;

extern struct symlink *symlinks;

extern struct proc_acl *global_nested_subject_list;

extern struct deleted_file *deleted_files;

extern unsigned long lineno;

extern struct role_acl *current_role;
extern struct proc_acl *current_subject;

extern char *current_acl_file;

enum {
	GR_HASH_SUBJECT,
	GR_HASH_OBJECT,
	GR_HASH_FILENAME
};

struct gr_hash_struct {
	void **table;
	void **nametable;
	void *first;
	u_int32_t table_size;
	u_int32_t used_size;
	int type;
};

struct user_acl_role_db {
	struct role_acl **r_table;
	u_int32_t num_pointers;		/* Number of allocations to track */
	u_int32_t num_roles;		/* Number of roles */
	u_int32_t num_domain_children;	/* Number of domain children */
	u_int32_t num_subjects;		/* Number of subjects */
	u_int32_t num_objects; 		/* Number of objects */
};

struct sprole_pw {
	const unsigned char *rolename;
	unsigned char salt[GR_SALT_SIZE];
	unsigned char sum[GR_SHA_SUM_SIZE];
};

struct gr_arg {
	struct user_acl_role_db role_db;
	unsigned char pw[GR_PW_LEN];
	unsigned char salt[GR_SALT_SIZE];
	unsigned char sum[GR_SHA_SUM_SIZE];
	unsigned char sp_role[GR_SPROLE_LEN];
	struct sprole_pw *sprole_pws;
	u_int32_t segv_dev;
	u_int64_t segv_inode;
	uid_t segv_uid;
	u_int16_t num_sprole_pws;
	u_int16_t mode;
};

struct gr_arg_wrapper {
	struct gr_arg *arg;
	u_int32_t version;
	u_int32_t size;
};

extern const char *rlim_table[GR_NLIMITS];
extern struct capability_set capability_list[CAP_MAX+2];
extern struct paxflag_set paxflag_list[5];
extern struct systemcall_set systemcall_list[SYSCALL_MAX+2];
extern struct namespace_set namespace_list[6];
extern struct family_set sock_families[AF_MAX+2];

extern int is_24_kernel;

extern uid_t special_role_uid;

extern u_int32_t num_subjects;
extern u_int32_t num_roles;
extern u_int32_t num_objects;
extern u_int32_t num_pointers;
extern u_int32_t num_domain_children;

extern char *current_learn_rolename;
extern char *current_learn_subject;
extern u_int16_t current_learn_rolemode;

extern char ** dont_reduce_dirs;
extern char ** always_reduce_dirs;
extern char ** protected_paths;
extern char ** read_protected_paths;
extern char ** high_reduce_dirs;
extern char ** high_protected_paths;
extern u_int32_t grlearn_options;

extern int gr_learn;
extern int gr_fulllearn;
extern char *output_log;

extern char *learn_log_buffer;

#endif
