# -*- Makefile -*-

SUBDIRS = lib

AM_CPPFLAGS  = -Wall -I${top_srcdir}/include -I${top_builddir}/include -D_GNU_SOURCE -DSYSCONFDIR=\"$(sysconfdir)/libnl\"

LDADD = \
	${top_builddir}/src/lib/libnl-cli-3.la \
	${top_builddir}/lib/libnl-3.la \
	${top_builddir}/lib/libnl-nf-3.la \
	${top_builddir}/lib/libnl-genl-3.la \
	${top_builddir}/lib/libnl-route-3.la \
	$(top_builddir)/lib/libnl-dect-3.la

sbin_PROGRAMS = \
	genl-ctrl-list \
	nl-qdisc-add nl-qdisc-list nl-qdisc-delete \
	nl-class-add nl-class-list nl-class-delete \
	nl-cls-add nl-cls-list nl-cls-delete \
	nl-classid-lookup \
	nl-link-list

noinst_PROGRAMS = \
	nf-ct-list nf-log nf-queue nf-monitor \
	nf-exp-list nf-exp-add nf-exp-delete \
	nl-addr-add nl-addr-delete nl-addr-list \
	nl-link-set nl-link-stats \
	nl-link-ifindex2name nl-link-name2ifindex \
	nl-neigh-add nl-neigh-delete nl-neigh-list \
	nl-rule-list \
	nl-neightbl-list \
	nl-monitor \
	nl-tctree-list \
	nl-route-add nl-route-delete nl-route-get nl-route-list \
	nl-fib-lookup \
	nl-list-caches nl-list-sockets \
	nl-util-addr \
	nl-link-enslave \
	nl-link-release \
	dect-transceiver-bind dect-transceiver-list \
	dect-cell-add dect-cell-delete dect-cell-list \
	dect-cluster-add dect-cluster-delete dect-cluster-list \
	dect-llme-monitor dect-llme-scan

genl_ctrl_list_SOURCES = genl-ctrl-list.c 

nf_ct_list_SOURCES = nf-ct-list.c 
nf_log_SOURCES = nf-log.c
nf_queue_SOURCES = nf-queue.c 
nf_monitor_SOURCES = nf-monitor.c

nf_exp_list_SOURCES = nf-exp-list.c 
nf_exp_add_SOURCES = nf-exp-add.c 
nf_exp_delete_SOURCES = nf-exp-delete.c 

nl_addr_add_SOURCES = nl-addr-add.c
nl_addr_delete_SOURCES = nl-addr-delete.c
nl_addr_list_SOURCES = nl-addr-list.c

nl_link_list_SOURCES = nl-link-list.c
nl_link_set_SOURCES = nl-link-set.c
nl_link_stats_SOURCES = nl-link-stats.c
nl_link_ifindex2name_SOURCES = nl-link-ifindex2name.c
nl_link_name2ifindex_SOURCES = nl-link-name2ifindex.c

nl_monitor_SOURCES = nl-monitor.c

nl_neigh_add_SOURCES = nl-neigh-add.c
nl_neigh_delete_SOURCES = nl-neigh-delete.c
nl_neigh_list_SOURCES = nl-neigh-list.c

nl_neightbl_list_SOURCES = nl-neightbl-list.c

nl_qdisc_add_SOURCES = nl-qdisc-add.c
nl_qdisc_delete_SOURCES = nl-qdisc-delete.c
nl_qdisc_list_SOURCES = nl-qdisc-list.c

nl_class_add_SOURCES = nl-class-add.c
nl_class_delete_SOURCES = nl-class-delete.c
nl_class_list_SOURCES = nl-class-list.c

nl_cls_add_SOURCES = nl-cls-add.c
nl_cls_list_SOURCES = nl-cls-list.c
nl_cls_delete_SOURCES = nl-cls-delete.c

nl_route_add_SOURCES = nl-route-add.c
nl_route_delete_SOURCES = nl-route-delete.c
nl_route_get_SOURCES = nl-route-get.c
nl_route_list_SOURCES = nl-route-list.c

nl_rule_list_SOURCES = nl-rule-list.c

nl_tctree_list_SOURCES = nl-tctree-list.c

nl_fib_lookup_SOURCES = nl-fib-lookup.c

nl_list_caches_SOURCES = nl-list-caches.c
nl_list_sockets_SOURCES = nl-list-sockets.c

nl_util_addr_SOURCES = nl-util-addr.c

nl_pktloc_lookup_SOURCES = nl-pktloc-lookup.c
nl_pktloc_lookup_LDADD = -lnl-route-3

nl_classid_lookup_SOURCES = nl-classid-lookup.c

dect_transceiver_bind_SOURCES = dect-transceiver-bind.c
dect_transceiver_list_SOURCES = dect-transceiver-list.c

dect_cell_add_SOURCES = dect-cell-add.c
dect_cell_delete_SOURCES = dect-cell-delete.c
dect_cell_list_SOURCES = dect-cell-list.c

dect_cluster_add_SOURCES = dect-cluster-add.c
dect_cluster_delete_SOURCES = dect-cluster-delete.c
dect_cluster_list_SOURCES = dect-cluster-list.c

dect_llme_monitor_SOURCES = dect-llme-monitor.c
dect_llme_scan_SOURCES = dect-llme-scan.c
