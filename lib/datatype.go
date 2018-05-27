package datatype

type FlowId struct {
	Src_ip uint32
    Dst_ip uint32
    Src_port uint16
    Dst_port uint16
	Ip_proto uint16
}

const MAX_INT_HOP = 6

type FlowInfo struct {
	// flow
    Src_ip uint32
    Dst_ip uint32
    Src_port uint16
    Dst_port uint16
    Ip_proto uint16

    // FIXME: should be `uint8`, but it cause memory shift,
    // (may be related to alignment and padding) 
    // which lead to wrong avlue of all below array. Dont
    // know how to fix yet
    Num_INT_hop uint16 

    Sw_ids [MAX_INT_HOP]uint32
    In_port_ids [MAX_INT_HOP]uint16
    E_port_ids [MAX_INT_HOP]uint16
    Hop_latencies [MAX_INT_HOP]uint32
    Queue_ids [MAX_INT_HOP]uint16
    Queue_occups [MAX_INT_HOP]uint16
    Ingr_times [MAX_INT_HOP]uint32
    Egr_times [MAX_INT_HOP]uint32
    Queue_congests [MAX_INT_HOP]uint16
    Tx_utilizes [MAX_INT_HOP]uint32

    Flow_latency uint32
    Flow_sink_time uint32
    Is_n_flow uint8
    Is_flow uint8
    Is_hop_latency uint8
    Is_queue_occup uint8
    Is_queue_congest uint8
    Is_tx_utilize uint8
}

type EgrId struct {
    Sw_id uint32
    P_id uint16
}

type EgrInfo struct {
    Tx_utilize uint32
    Egr_time uint32
}

type QueueId struct {
    Sw_id uint32
    Q_id uint16
}

type QueueInfo struct {
    Occup uint16
    Congest uint16
    Q_time uint32
}