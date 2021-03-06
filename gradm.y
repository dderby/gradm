%{
/*
 * Copyright (C) 2002-2014 Bradley Spengler, Open Source Security, Inc.
 *        http://www.grsecurity.net spender@grsecurity.net
 *
 * This file is part of gradm.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include "gradm.h"

extern int gradmlex(void);

struct ip_acl ip;
struct var_object *var_obj = NULL;
char *nested[MAX_NEST_DEPTH];
int current_nest_depth = 0;
%}

%union {
	char *string;
	u_int32_t num;
	u_int16_t shortnum;
	struct var_object * var;
}

%token <string> ROLE ROLE_NAME SUBJECT SUBJ_NAME OBJ_NAME HOSTNAME
%token <string> RES_NAME RES_SOFTHARD CONNECT BIND IPTYPE
%token <string> IPPROTO CAP_NAME ROLE_ALLOW_IP PAX_NAME
%token <string> SC_NAME NS_NAME
%token <string> ROLE_TRANSITION VARIABLE DEFINE DEFINE_NAME DISABLED
%token <string> ID_NAME USER_TRANS_ALLOW GROUP_TRANS_ALLOW 
%token <string> USER_TRANS_DENY GROUP_TRANS_DENY DOMAIN_TYPE DOMAIN
%token <string> INTERFACE IPOVERRIDE REPLACE REP_ARG AUDIT
%token <string> SOCKALLOWFAMILY SOCKFAMILY ROLE_UMASK
%token <num> OBJ_MODE SUBJ_MODE IPADDR IPNETMASK NOT
%token <shortnum> IPPORT ROLE_TYPE UMASK
%type <num> subj_mode obj_mode ip_netmask invert_socket
%type <shortnum> role_type
%type <var> variable_expression
%left '&'
%left '|'
%left '-'

%%

compiled_acl:			various_acls
	|			compiled_acl various_acls
	;

various_acls:			role_label
	|			replace_rule
	|			domain_label
	|			role_allow_ip
	|			role_umask
	|			role_transitions
	|			subject_label
	|			user_allow_label
	|			user_deny_label
	|			group_allow_label
	|			group_deny_label
	|			variable_object
	|			variable_expression
				{
					interpret_variable($1);
				}
	|			nested_label
	|			object_file_label
	|			object_cap_label
	|			object_paxflag_label
	|			object_sc_label
	|			object_ns_label
	|			object_res_label
	|			object_connect_ip_label
	|			object_bind_ip_label
	|			object_ip_override_label
	|			object_sock_allow_family
	;

replace_rule:			REPLACE REP_ARG REP_ARG
				{
					add_replace_string($2, $3);
				}
	;
variable_expression:		VARIABLE
				{
					$$ = sym_retrieve($1);
					if (!$$) {
						fprintf(stderr, "Variable \"%s\" not defined on line %lu of %s.\n", $1, lineno, current_acl_file);
						exit(EXIT_FAILURE);
					}
				}
	|			variable_expression '|' variable_expression
				{
					$$ = union_objects($1, $3);
				}
	|			variable_expression '&' variable_expression
				{
					$$ = intersect_objects($1, $3);
				}
	|			variable_expression '-' variable_expression
				{
					$$ = differentiate_objects($1, $3);
				}
	|			'(' variable_expression ')'
				{
					$$ = $2;
				}
	;

variable_object:		DEFINE DEFINE_NAME '{' var_object_list '}'
				{
				  if (sym_retrieve($2)) {
					fprintf(stderr, "Duplicate variable \"%s\" defined on line %lu of %s.\n", $2, lineno, current_acl_file);
					exit(EXIT_FAILURE);
				  }
				  sym_store($2, var_obj);
				  var_obj = NULL;
				}
	;

var_object_file:		OBJ_NAME obj_mode
				{
				  add_file_var_object(&var_obj, $1, $2);
				}
	;

var_object_cap:			CAP_NAME AUDIT
				{
                                add_cap_var_object(&var_obj, $1, $2);
                                free($1);
                                free($2);
                               }
       |                       CAP_NAME
                               {
                                add_cap_var_object(&var_obj, $1, NULL);
				 free($1);
				}
	;


var_object_net:			CONNECT invert_socket IPADDR ip_netmask ip_ports ip_typeproto
				{
				 ip.addr = $3;
				 ip.netmask = $4;
				 add_net_var_object(&var_obj, &ip, GR_IP_CONNECT | $2, NULL);
				 memset(&ip, 0, sizeof(ip));
				}
	|			CONNECT invert_socket HOSTNAME ip_netmask ip_ports ip_typeproto
				{
				 ip.netmask = $4;
				 add_net_var_object(&var_obj, &ip, GR_IP_CONNECT | $2, $3);
				 memset(&ip, 0, sizeof(ip));
				 free($3);
				}
	|
				CONNECT DISABLED
				{
				 add_net_var_object(&var_obj, &ip, GR_IP_CONNECT, NULL);
				}
	|			BIND invert_socket IPADDR ip_netmask ip_ports ip_typeproto
				{
				 ip.addr = $3;
				 ip.netmask = $4;
				 add_net_var_object(&var_obj, &ip, GR_IP_BIND | $2, NULL);
				 memset(&ip, 0, sizeof(ip));
				}
	|			BIND invert_socket HOSTNAME ip_netmask ip_ports ip_typeproto
				{
				 ip.netmask = $4;
				 add_net_var_object(&var_obj, &ip, GR_IP_BIND | $2, $3);
				 memset(&ip, 0, sizeof(ip));
				 free($3);
				}
	|			BIND invert_socket INTERFACE ip_ports ip_typeproto
				{
				 ip.iface = $3;
				 add_net_var_object(&var_obj, &ip, GR_IP_BIND | $2, NULL);
				 memset(&ip, 0, sizeof(ip));
				}
	|
				BIND DISABLED
				{
				 add_net_var_object(&var_obj, &ip, GR_IP_BIND, NULL);
				}
	;

var_object_list:		var_object_file
	|			var_object_net
	|			var_object_cap
	|			var_object_list var_object_file
	|			var_object_list var_object_net
	|			var_object_list var_object_cap
	;

domain_label:			DOMAIN ROLE_NAME DOMAIN_TYPE 
				{
				 add_role_acl(&current_role, $2, GR_ROLE_DOMAIN | role_mode_conv($3), 1);
				}
				domain_user_list
	;

domain_user_list:		ROLE_NAME
				{
					add_domain_child(current_role, $1);
				}
	|			domain_user_list ROLE_NAME
				{
					add_domain_child(current_role, $2);
				}
	;

role_label: 			ROLE ROLE_NAME role_type
				{
				 add_role_acl(&current_role, $2, $3, 0);
				}
	;

role_type: /* empty */
				{ $$ = role_mode_conv(""); }
	|			ROLE_TYPE
				{ $$ = $1; }
	;

subject_label:			SUBJECT SUBJ_NAME subj_mode
				{
				 if (current_role && current_role->roletype & GR_ROLE_LEARN) {
					fprintf(stderr, "Error on line %lu of %s.\n"
							"Subjects are not allowed for a role with learning enabled, as "
							"they are generated by the learning mode.\n"
							"The RBAC system will not load until you correct this error.\n\n",
							lineno, current_acl_file);
					exit(EXIT_FAILURE);
				 }

				 add_proc_subject_acl(current_role, $2, $3, 0);
				}
	;

nested_label:			SUBJECT SUBJ_NAME nested_subjs subj_mode
				{
					add_proc_nested_acl(current_role, $2, (const char * const *)nested, current_nest_depth, $4);
					current_nest_depth = 0;
				}
	;

nested_subjs:			':' SUBJ_NAME
				{
					nested[current_nest_depth] = $2;
					current_nest_depth++;
				}
	|
				nested_subjs ':' SUBJ_NAME
				{
					if (current_nest_depth >= MAX_NEST_DEPTH) {
						fprintf(stderr, "Nesting too deep (over %d) on line %lu of %s.\n", MAX_NEST_DEPTH,
								lineno, current_acl_file);
						exit(EXIT_FAILURE);
					}
					nested[current_nest_depth] = $3;
					current_nest_depth++;
				}
	;

user_allow_ids:			ID_NAME
				{
					add_id_transition(current_subject, $1, GR_ID_USER, GR_ID_ALLOW);
				}
	|
				user_allow_ids ID_NAME
				{
					add_id_transition(current_subject, $2, GR_ID_USER, GR_ID_ALLOW);
				}
	;
user_allow_label:		USER_TRANS_ALLOW user_allow_ids
				{
				}
	;

user_deny_ids:			ID_NAME
				{
					add_id_transition(current_subject, $1, GR_ID_USER, GR_ID_DENY);
				}
	|
				user_deny_ids ID_NAME
				{
					add_id_transition(current_subject, $2, GR_ID_USER, GR_ID_DENY);
				}
	;
user_deny_label:		USER_TRANS_DENY user_deny_ids
				{
				}
	;

group_allow_ids:		ID_NAME
				{
					add_id_transition(current_subject, $1, GR_ID_GROUP, GR_ID_ALLOW);
				}
	|
				group_allow_ids ID_NAME
				{
					add_id_transition(current_subject, $2, GR_ID_GROUP, GR_ID_ALLOW);
				}
	;
group_allow_label:		GROUP_TRANS_ALLOW group_allow_ids
				{
				}
	;

group_deny_ids:			ID_NAME
				{
					add_id_transition(current_subject, $1, GR_ID_GROUP, GR_ID_DENY);
				}
	|
				group_deny_ids ID_NAME
				{
					add_id_transition(current_subject, $2, GR_ID_GROUP, GR_ID_DENY);
				}
	;
group_deny_label:		GROUP_TRANS_DENY group_deny_ids
				{
				}
	;

object_file_label:		OBJ_NAME obj_mode
				{
				 add_proc_object_acl(current_subject, $1, $2, GR_FEXIST);
				}
	;

object_cap_label:		CAP_NAME AUDIT
				{
                                add_cap_acl(current_subject, $1, $2);
                                free($1);
                                free($2);
                               }
       |                       CAP_NAME
                               {
                                add_cap_acl(current_subject, $1, NULL);
				 free($1);
				}
	;

object_paxflag_label:		PAX_NAME
				{
				 add_paxflag_acl(current_subject, $1);
				 free($1);
				}
	;

object_sc_label:		SC_NAME
				{
				 add_systemcall_acl(current_subject, $1);
				 free($1);
				}
	;

object_ns_label:		NS_NAME
				{
				 add_namespace_acl(current_subject, $1);
				 free($1);
				}
	;

object_res_label:		RES_NAME RES_SOFTHARD RES_SOFTHARD
				{
				 add_res_acl(current_subject, $1, $2, $3);
				 free($1);
				 free($2);
				 free($3);
				}
	;

subj_mode: /* empty */
				{ $$ = proc_subject_mode_conv(""); }
	|			SUBJ_MODE
				{ $$ = $1; }
	;

obj_mode: /* empty */
				{ $$ = proc_object_mode_conv(""); }
	|			OBJ_MODE
				{ $$ = $1; }
	;

invert_socket:	/* empty */
		{ $$ = 0; }
	|	NOT
		{ $$ = GR_IP_INVERT; }
	;

role_transitions:		ROLE_TRANSITION role_names
				{
				}
	;

role_names:			ROLE_NAME
				{
					add_role_transition(current_role, $1);
				}
	|			role_names ROLE_NAME
				{
					add_role_transition(current_role, $2);
				}
	;

role_umask:			ROLE_UMASK UMASK
				{
					set_role_umask(current_role, $2);
				}
	;

role_allow_ip:			ROLE_ALLOW_IP IPADDR ip_netmask
				{
					add_role_allowed_ip(current_role, $2, $3);
				}
	|			ROLE_ALLOW_IP HOSTNAME ip_netmask
				{
					add_role_allowed_host(current_role, $2, $3);
				}
	;

object_connect_ip_label:	CONNECT invert_socket IPADDR ip_netmask ip_ports ip_typeproto
				{
				 ip.addr = $3;
				 ip.netmask = $4;
				 add_ip_acl(current_subject, GR_IP_CONNECT | $2, &ip);
				 memset(&ip, 0, sizeof(ip));
				}
	|			CONNECT invert_socket HOSTNAME ip_netmask ip_ports ip_typeproto
				{
				 ip.netmask = $4;
				 add_host_acl(current_subject, GR_IP_CONNECT | $2, $3, &ip);
				 memset(&ip, 0, sizeof(ip));
				 free($3);
				}
	|
				CONNECT DISABLED
				{
				 add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
				}
	;

object_sock_allow_family:	SOCKALLOWFAMILY sock_families
				{
				}
	;

sock_families:			SOCKFAMILY
				{
				 add_sock_family(current_subject, $1);
				}
	|			sock_families SOCKFAMILY
				{
				 add_sock_family(current_subject, $2);
				}
	;
object_ip_override_label:
				IPOVERRIDE IPADDR
				{
				 current_subject->inaddr_any_override = $2;
				}
	;

object_bind_ip_label:		BIND invert_socket IPADDR ip_netmask ip_ports ip_typeproto
				{
				 ip.addr = $3;
				 ip.netmask = $4;
				 add_ip_acl(current_subject, GR_IP_BIND | $2, &ip);
				 memset(&ip, 0, sizeof(ip));
				}
	|			BIND invert_socket HOSTNAME ip_netmask ip_ports ip_typeproto
				{
				 ip.netmask = $4;
				 add_host_acl(current_subject, GR_IP_BIND | $2, $3, &ip);
				 memset(&ip, 0, sizeof(ip));
				 free($3);
				}
	|			BIND invert_socket INTERFACE ip_ports ip_typeproto
				{
				 ip.iface = $3;
				 add_ip_acl(current_subject, GR_IP_BIND | $2, &ip);
				 memset(&ip, 0, sizeof(ip));
				}
	|
				BIND DISABLED
				{
				 add_ip_acl(current_subject, GR_IP_BIND, &ip);
				}
	;

ip_netmask: /* emtpy */
				{ $$ = 0xffffffff; }
	|			'/' IPNETMASK
				{ $$ = $2; }
	;

ip_ports: /* emtpy */
				{
				 ip.low = 0;
				 ip.high = 65535;
				}
	|			':' IPPORT
				{
				 ip.low = ip.high = $2;
				}
	|			':' IPPORT '-' IPPORT
				{
				 ip.low = $2;
				 ip.high = $4;
				}
	;

ip_typeproto:			IPPROTO
				{ conv_name_to_type(&ip, $1);
				  free($1);
				}
	|			IPTYPE
				{ conv_name_to_type(&ip, $1);
				  free($1);
				}
	| 			ip_typeproto IPPROTO
				{ conv_name_to_type(&ip, $2);
				  free($2);
				}
	|			ip_typeproto IPTYPE
				{ conv_name_to_type(&ip, $2);
				  free($2);
				}
	;
