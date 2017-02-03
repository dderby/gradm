#include "gradm.h"

struct namespace_set namespace_list[] = {
	{"CLONE_NEWNS",   0x00020000},
	{"CLONE_NEWUTS",  0x04000000},
	{"CLONE_NEWIPC",  0x08000000},
	{"CLONE_NEWUSER", 0x10000000},
	{"CLONE_NEWPID",  0x20000000},
	{"CLONE_NEWNET",  0x40000000},
};

u_int32_t
namespace_conv(const char *namespace)
{
	int i;

	for (i = 0; i < sizeof (namespace_list) / sizeof (struct namespace_set); i++)
		if (!strcmp(namespace, namespace_list[i].namespace_name))
			return (namespace_list[i].namespace_val);

	fprintf(stderr, "Invalid namespace name \"%s\" on line %lu of %s.\n"
		"The RBAC system will not load until this"
		" error is fixed.\n", namespace, lineno, current_acl_file);

	exit(EXIT_FAILURE);

	return 0;
}

void
add_namespace_acl(struct proc_acl *subject, const char *namespace)
{
	u_int32_t knamespace = namespace_conv(namespace + 1);

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a namespace without a subject declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (*namespace == '+')
		subject->namespaces |= knamespace;
	else
		subject->namespaces |= (knamespace << 8);

	return;
}

