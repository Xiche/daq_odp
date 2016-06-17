/*
** Copyright (C) 2015 Michael R. Altizer <xiche@verizon.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if.h>
#include <stdio.h>

#include <daq_api.h>
#include <sfbpf.h>

#include <odp.h>

#define DAQ_ODP_VERSION 1

#define SHM_PKT_POOL_SIZE      (512*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856
#define MAX_PKT_BURST          16

#define ODP_MODE_PKT_BURST  0   /* Handle packets in bursts */
#define ODP_MODE_PKT_SCHED  1   /* Handle packets in scheduled queues */

typedef struct _odp_interface
{
    struct _odp_interface *next;
    struct _odp_interface *peer;
    odp_pktio_t pktio;
    odp_pktin_queue_t pktin;
    odp_pktout_queue_t pktout;
    char *ifname;
    int index;
} ODP_Interface_t;

typedef struct _odp_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;   // Sadly unused in non-scheduled mode for now...
    uint64_t sched_wait;
    ODP_Interface_t *interfaces;
    odp_pool_t pool;
    odp_instance_t instance;
    int mode;
    bool debug;
    struct sfbpf_program fcode;
    volatile bool break_loop;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
} ODP_Context_t;

static void stop_odp_context(ODP_Context_t *odpc)
{
    ODP_Interface_t *intf;
    odp_queue_t queue;

    for (intf = odpc->interfaces; intf; intf = intf->next)
    {
        if (intf->pktio != ODP_PKTIO_INVALID)
        {
            odp_pktio_stop(intf->pktio);
            odp_pktio_close(intf->pktio);
            intf->pktio = ODP_PKTIO_INVALID;
        }
    }
    if (odpc->pool != ODP_POOL_INVALID)
    {
        odp_pool_destroy(odpc->pool);
        odpc->pool = ODP_POOL_INVALID;
    }
}

static void destroy_odp_daq_context(ODP_Context_t *odpc)
{
    ODP_Interface_t *intf;

    if (odpc)
    {
        while ((intf = odpc->interfaces) != NULL)
        {
            odpc->interfaces = intf->next;
            free(intf->ifname);
            free(intf);
        }
        free(odpc->device);
        free(odpc->filter);
        sfbpf_freecode(&odpc->fcode);
        free(odpc);
    }
}

static int odp_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    ODP_Context_t *odpc;
    ODP_Interface_t *intf;
    DAQ_Dict *entry;
    char *dev;
    size_t len;
    int num_intfs = 0, rval;

    odpc = calloc(1, sizeof(ODP_Context_t));
    if (!odpc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new ODP context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    odpc->device = strdup(config->name);
    if (!odpc->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    odpc->snaplen = SHM_PKT_POOL_BUF_SIZE;
    odpc->timeout = config->timeout;    /* Cannot convert with odp_schedule_wait_time() until ODP has been init'd. */
    odpc->pool = ODP_POOL_INVALID;

    /* Default configuration options */
    odpc->mode = ODP_MODE_PKT_SCHED;

    dev = odpc->device;
    while (*dev != '\0')
    {
        len = strcspn(dev, ",");
        if (len >= IFNAMSIZ)
        {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            rval = DAQ_ERROR_INVAL;
            goto err;
        }
        if (len != 0)
        {
            num_intfs++;
            intf = calloc(1, sizeof(ODP_Interface_t));
            if (!intf)
            {
                snprintf(errbuf, errlen, "%s: Couldn't allocate memory for an interface structure!", __FUNCTION__);
                rval = DAQ_ERROR_NOMEM;
                goto err;
            }
            intf->ifname = strndup(dev, len);
            if (!intf->ifname)
            {
                free(intf);
                snprintf(errbuf, errlen, "%s: Couldn't allocate memory for an interface name!", __FUNCTION__);
                rval = DAQ_ERROR_NOMEM;
                goto err;
            }
            intf->pktio = ODP_PKTIO_INVALID;
            intf->index = num_intfs;
            intf->next = odpc->interfaces;
            odpc->interfaces = intf;
            if (config->mode != DAQ_MODE_PASSIVE && num_intfs % 2 == 0)
            {
                odpc->interfaces->peer = odpc->interfaces->next;
                odpc->interfaces->next->peer = odpc->interfaces;
            }
        }
        else
            len += 1;
        dev += len;
    }

    if (!odpc->interfaces || (config->mode != DAQ_MODE_PASSIVE && num_intfs % 2 != 0))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, odpc->device);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "debug"))
            odpc->debug = true;
        else if (!strcmp(entry->key, "mode"))
        {
            if (!entry->value)
            {
                snprintf(errbuf, errlen, "%s: %s requires an argument!", __FUNCTION__, entry->key);
                rval = DAQ_ERROR_INVAL;
                goto err;
            }
            if (!strcmp(entry->value, "burst"))
                odpc->mode = ODP_MODE_PKT_BURST;
            else if (!strcmp(entry->value, "scheduled"))
                odpc->mode = ODP_MODE_PKT_SCHED;
            else
            {
                snprintf(errbuf, errlen, "%s: Unrecognized argument for %s: '%s'!", __FUNCTION__, entry->key, entry->value);
                rval = DAQ_ERROR_INVAL;
                goto err;
            }
        }
    }

    odpc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = odpc;
    return DAQ_SUCCESS;

err:
    destroy_odp_daq_context(odpc);

    return rval;
}

static int odp_daq_set_filter(void *handle, const char *filter)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    struct sfbpf_program fcode;

    if (odpc->filter)
        free(odpc->filter);

    odpc->filter = strdup(filter);
    if (!odpc->filter)
    {
        DPE(odpc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(odpc->snaplen, DLT_EN10MB, &fcode, odpc->filter, 1, 0) < 0)
    {
        DPE(odpc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&odpc->fcode);
    odpc->fcode.bf_len = fcode.bf_len;
    odpc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int odp_daq_start(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    ODP_Interface_t *intf;
    odp_pool_param_t params;
    int rval = DAQ_ERROR;

    /* Init ODP before calling anything else */
    if (odp_init_global(&odpc->instance, NULL, NULL))
    {
        DPE(odpc->errbuf, "Error: ODP global init failed.");
        goto err;
    }

    /* Init this thread */
    if (odp_init_local(odpc->instance, ODP_THREAD_WORKER))
    {
        DPE(odpc->errbuf, "Error: ODP local init failed.");
        goto err;
    }

    /* Calculate the scheduler timeout period. */
    odpc->sched_wait = (odpc->timeout > 0) ? odp_schedule_wait_time(odpc->timeout * ODP_TIME_MSEC_IN_NS) : ODP_SCHED_WAIT;

    /* Create packet pool */
    memset(&params, 0, sizeof(params));
    params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
    params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
    params.pkt.num     = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
    params.type        = ODP_POOL_PACKET;

    odpc->pool = odp_pool_create("packet_pool", &params);
    if (odpc->pool == ODP_POOL_INVALID)
    {
        DPE(odpc->errbuf, "Error: packet pool create failed.");
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    if (odpc->debug)
        odp_pool_print(odpc->pool);

    /* Create a pktio and scheduled input queue for each interface. */
    for (intf = odpc->interfaces; intf; intf = intf->next)
    {
        odp_pktio_param_t pktio_param;
        odp_pktin_queue_param_t pktin_param;

        odp_pktio_param_init(&pktio_param);

        if (odpc->mode == ODP_MODE_PKT_BURST)
            pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT; 
        else if (odpc->mode == ODP_MODE_PKT_SCHED)
            pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

        intf->pktio = odp_pktio_open(intf->ifname, odpc->pool, &pktio_param);
        if (intf->pktio == ODP_PKTIO_INVALID)
        {
            DPE(odpc->errbuf, "Error: pktio create failed for %s", intf->ifname);
            rval = DAQ_ERROR_NODEV;
            goto err;
        }

        odp_pktin_queue_param_init(&pktin_param);
        pktin_param.queue_param.context = intf;

        if (odpc->mode == ODP_MODE_PKT_SCHED)
            pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

        if (odp_pktin_queue_config(intf->pktio, &pktin_param))
        {
            DPE(odpc->errbuf, "Error: pktin config failed for %s", intf->ifname);
            rval = DAQ_ERROR;
            goto err;
        }

        if (odp_pktout_queue_config(intf->pktio, NULL))
        {
            DPE(odpc->errbuf, "Error: pktout config failed for %s", intf->ifname);
            rval = DAQ_ERROR;
            goto err;
        }

        if (odp_pktio_start(intf->pktio))
        {
            DPE(odpc->errbuf, "Error: unable to start %s", intf->ifname);
            rval = DAQ_ERROR;
            goto err;
        }

        if (odpc->mode == ODP_MODE_PKT_BURST)
        {
            if (odp_pktin_queue(intf->pktio, &intf->pktin, 1) != 1)
            {
                DPE(odpc->errbuf, "Error: no pktin queue for %s", intf->ifname);
                rval = DAQ_ERROR;
                goto err;
            }
        }

        if (odp_pktout_queue(intf->pktio, &intf->pktout, 1) != 1)
        {
            DPE(odpc->errbuf, "Error: no pktout queue for %s", intf->ifname);
            rval = DAQ_ERROR;
            goto err;
        }
    }

    odpc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;

err:
    return rval;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static int odp_daq_acquire_burst(ODP_Context_t *odpc, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
    struct timeval tv;
    ODP_Interface_t *intf;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    odp_packet_t pkt_tbl_recv[MAX_PKT_BURST], pkt_tbl_send[MAX_PKT_BURST];
    odp_packet_t pkt;
    const uint8_t *data;
    uint16_t len;
    int pkts_recv, pkts_send, pkt_burst;
    int i, c = 0;

    while (c < cnt || cnt <= 0)
    {
        for (intf = odpc->interfaces; intf; intf = intf->next)
        {
            /* Has breakloop() been called? */
            if (odpc->break_loop)
            {
                odpc->break_loop = false;
                return 0;
            }

            pkt_burst = MAX_PKT_BURST;
            if (cnt > 0)
            {
                if (c > cnt)
                    break;
                if (cnt - c < MAX_PKT_BURST)
                    pkt_burst = cnt - c;
            }

            pkts_recv = odp_pktin_recv(intf->pktin, pkt_tbl_recv, pkt_burst);
            if (pkts_recv < 0)
                return DAQ_ERROR;
            if (pkts_recv == 0)
                continue;

            odpc->stats.hw_packets_received += pkts_recv;

            /* Use a single timestamp for all packets received in a burst. */
            gettimeofday(&tv, NULL);

            /* Process each packet received, adding packets to send to the output
                table and freeing the rest. */
            pkts_send = 0;
            for (i = 0; i < pkts_recv; i++)
            {
                pkt = pkt_tbl_recv[i];
                data = odp_packet_data(pkt);

                verdict = DAQ_VERDICT_PASS;
                len = odp_packet_len(pkt);
                if (!odpc->fcode.bf_insns || sfbpf_filter(odpc->fcode.bf_insns, data, len, len) != 0)
                {
                    daqhdr.ts = tv;
                    daqhdr.caplen = len;
                    daqhdr.pktlen = len;
                    daqhdr.ingress_index = intf->index;
                    daqhdr.egress_index = intf->peer ? intf->peer->index : DAQ_PKTHDR_UNKNOWN;
                    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
                    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
                    daqhdr.flags = 0;
                    daqhdr.opaque = 0;
                    daqhdr.priv_ptr = NULL;
                    daqhdr.address_space_id = 0;

                    if (callback)
                    {
                        verdict = callback(user, &daqhdr, data);
                        if (verdict >= MAX_DAQ_VERDICT)
                            verdict = DAQ_VERDICT_PASS;
                        odpc->stats.verdicts[verdict]++;
                        verdict = verdict_translation_table[verdict];
                    }
                    odpc->stats.packets_received++;
                    c++;
                }
                else
                    odpc->stats.packets_filtered++;

                if (intf->peer && verdict == DAQ_VERDICT_PASS)
                {
                    pkt_tbl_send[pkts_send] = pkt;
                    pkts_send++;
                }
                else
                    odp_packet_free(pkt);
            }

            if (intf->peer && pkts_send > 0)
                odp_pktout_send(intf->peer->pktout, pkt_tbl_send, pkts_send);
        }
    }
    return 0;
}

static int odp_daq_acquire_scheduled(ODP_Context_t *odpc, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
    struct timeval tv;
    ODP_Interface_t *intf;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    odp_event_t ev_tbl_recv[MAX_PKT_BURST];
    odp_packet_t pkt;
    odp_event_t ev;
    odp_queue_t inq;
    odp_pktio_t pktio;
    const uint8_t *data;
    uint16_t len;
    int ev_recv, pkt_burst;
    int i, c = 0;

    while (c < cnt || cnt <= 0)
    {
        /* Has breakloop() been called? */
        if (odpc->break_loop)
        {
            odpc->break_loop = false;
            return 0;
        }

        pkt_burst = MAX_PKT_BURST;
        if (cnt > 0)
        {
            if (c > cnt)
                break;
            if (cnt - c < MAX_PKT_BURST)
                pkt_burst = cnt - c;
        }

        ev_recv = odp_schedule_multi(NULL, odpc->sched_wait, ev_tbl_recv, pkt_burst);
        if (ev_recv < 0)
            return DAQ_ERROR;
        if (ev_recv == 0)
            return 0;

        odpc->stats.hw_packets_received += ev_recv;
        
        /* Use a single timestamp for all packets received in a burst. */
        gettimeofday(&tv, NULL);

        /* Process each packet received, queuing packets to send to the associated
            output queue and freeing the rest. */
        for (i = 0; i < ev_recv; i++)
        {
            ev = ev_tbl_recv[i];
            if (odp_event_type(ev) != ODP_EVENT_PACKET)
            {
                printf("Received unexpected ODP event type (%d)!\n", odp_event_type(ev));
                odp_buffer_free(odp_buffer_from_event(ev));
                continue;
            }

            pkt = odp_packet_from_event(ev);
            data = odp_packet_data(pkt);
            len = odp_packet_len(pkt);

            /* Chain event => packet => pktio => default input queue => context
                to find the interface structure associated with the ingress
                interface of this packet.  This is kind of ridiculous. */
            odp_pktin_event_queue(odp_packet_input(pkt), &inq, 1);
            intf = (ODP_Interface_t *) odp_queue_context(inq);

            verdict = DAQ_VERDICT_PASS;
            if (!odpc->fcode.bf_insns || sfbpf_filter(odpc->fcode.bf_insns, data, len, len) != 0)
            {
                daqhdr.ts = tv;
                daqhdr.caplen = len;
                daqhdr.pktlen = len;
                daqhdr.ingress_index = intf->index;
                daqhdr.egress_index = intf->peer ? intf->peer->index : DAQ_PKTHDR_UNKNOWN;
                daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
                daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
                daqhdr.flags = 0;
                daqhdr.opaque = 0;
                daqhdr.priv_ptr = NULL;
                daqhdr.address_space_id = 0;

                if (callback)
                {
                    verdict = callback(user, &daqhdr, data);
                    if (verdict >= MAX_DAQ_VERDICT)
                        verdict = DAQ_VERDICT_PASS;
                    odpc->stats.verdicts[verdict]++;
                    verdict = verdict_translation_table[verdict];
                }
                odpc->stats.packets_received++;
                c++;
            }
            else
                odpc->stats.packets_filtered++;

            if (intf->peer && verdict == DAQ_VERDICT_PASS)
                odp_pktout_send(intf->peer->pktout, &pkt, 1);
            else
                odp_packet_free(pkt);
        }
    }
    return 0;
}

static int odp_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    if (odpc->mode == ODP_MODE_PKT_SCHED)
        return odp_daq_acquire_scheduled(odpc, cnt, callback, user);

    return odp_daq_acquire_burst(odpc, cnt, callback, user);
}

static int odp_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    ODP_Interface_t *intf;
    odp_packet_t pkt;

    for (intf = odpc->interfaces; intf && intf->index != hdr->ingress_index; intf = intf->next);
    if (!intf || (!reverse && !(intf = intf->peer)))
        return DAQ_ERROR;

    pkt = odp_packet_alloc(odpc->pool, len);
    if (!pkt)
        return DAQ_ERROR_NOMEM;

    if (odp_packet_copy_from_mem(pkt, 0, len, packet_data) < 0)
    {
        odp_packet_free(pkt);
        return DAQ_ERROR;
    }

    if (odp_pktout_send(intf->pktout, &pkt, 1) != 1)
    {
        odp_packet_free(pkt);
        return DAQ_ERROR;
    }

    odpc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static int odp_daq_breakloop(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    odpc->break_loop = true;

    return DAQ_SUCCESS;
}

static int odp_daq_stop(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    stop_odp_context(odpc);

    odpc->state = DAQ_STATE_STOPPED;

    return DAQ_SUCCESS;
}

static void odp_daq_shutdown(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    stop_odp_context(odpc);

    odp_term_local(); 
    odp_term_global(odpc->instance);

    destroy_odp_daq_context(odpc);
}

static DAQ_State odp_daq_check_status(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    return odpc->state;
}

static int odp_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    memcpy(stats, &odpc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

static void odp_daq_reset_stats(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    memset(&odpc->stats, 0, sizeof(DAQ_Stats_t));
}

static int odp_daq_get_snaplen(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    return odpc->snaplen;
}

static uint32_t odp_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF | DAQ_CAPA_DEVICE_INDEX;
}

static int odp_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *odp_daq_get_errbuf(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    return odpc->errbuf;
}

static void odp_daq_set_errbuf(void *handle, const char *string)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    if (!string)
        return;

    DPE(odpc->errbuf, "%s", string);
    return;
}

static int odp_daq_get_device_index(void *handle, const char *device)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    ODP_Interface_t *intf;

    for (intf = odpc->interfaces; intf; intf = intf->next)
    {
        if (!strcmp(device, intf->ifname))
            return intf->index;
    }

    return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t afpacket_daq_module_data =
#endif
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_ODP_VERSION,
    .name = "odp",
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE,
    .initialize = odp_daq_initialize,
    .set_filter = odp_daq_set_filter,
    .start = odp_daq_start,
    .acquire = odp_daq_acquire,
    .inject = odp_daq_inject,
    .breakloop = odp_daq_breakloop,
    .stop = odp_daq_stop,
    .shutdown = odp_daq_shutdown,
    .check_status = odp_daq_check_status,
    .get_stats = odp_daq_get_stats,
    .reset_stats = odp_daq_reset_stats,
    .get_snaplen = odp_daq_get_snaplen,
    .get_capabilities = odp_daq_get_capabilities,
    .get_datalink_type = odp_daq_get_datalink_type,
    .get_errbuf = odp_daq_get_errbuf,
    .set_errbuf = odp_daq_set_errbuf,
    .get_device_index = odp_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
};
