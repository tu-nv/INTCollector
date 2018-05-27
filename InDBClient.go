

package main

import (
	"fmt"
	"os"
	"os/signal"
	"io/ioutil"
	"sync"
	"bytes"
	"encoding/binary"
	"time"

	// bpf "github.com/iovisor/gobpf/bcc"
	bpf "../gobpf/bcc"
	indbclient "github.com/influxdata/influxdb/client/v2"

	datatype "./lib"
)


// Do not remove the bellow comment.

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

func intToIPv4String(a uint32) string{
	return fmt.Sprintf("%d.%d.%d.%d", byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
}

// queryDB convenience function to query the database
func queryDB(clnt indbclient.Client, cmd string, db string) (res []indbclient.Result, err error) {
	q := indbclient.Query{
		Command:  cmd,
		Database: db,
	}
	if response, err := clnt.Query(q); err == nil {
		if response.Error() != nil {
			return res, response.Error()
		}
		res = response.Results
	} else {
		return res, err
	}
	return res, nil
}


func main() {
	var device string
	var wg sync.WaitGroup
	var mutex = &sync.Mutex{}
	INTdb := "INTdatabase"
	stop_flag := 0
	period_push := 10

	if len(os.Args) != 2 {
		usage()
	}

	device = os.Args[1]

	buf, err := ioutil.ReadFile("BPFCollector.c")
	if err != nil {
		fmt.Print(err)
	}
	source := string(buf)


	/*
	Load and attach XDP program
	*/

	module := bpf.NewModule(source, []string{
		"-w",
		"-D_MAX_INT_HOP=6",
	    "-D_INT_DST_PORT=54321",
	    "-D_SERVER_MODE=INFLUXDB",
	})
	defer module.Close()

	fn, err := module.Load("collector", C.BPF_PROG_TYPE_XDP, 0, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()


	/*
	InfluxDB CLient
	*/

	client, err := indbclient.NewHTTPClient(indbclient.HTTPConfig{
		Addr:     "http://192.168.122.106:8086",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create new HTTP client: %v\n", err)
	}
	defer client.Close()

	_, err = queryDB(client, fmt.Sprintf("CREATE DATABASE %s", INTdb), INTdb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create  DB %v\n", err)
	}

	defer func() {
		// Clear data for easy testing
		_, err = queryDB(client, fmt.Sprintf("DROP DATABASE %s", INTdb), INTdb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot clear old DBs %v\n", err)
		}
	}()

	hostEndian := bpf.GetHostByteOrder()

	tb_flow := bpf.NewTable(module.TableId("tb_flow"), module)
	tb_egr := bpf.NewTable(module.TableId("tb_egr"), module)
	tb_queue := bpf.NewTable(module.TableId("tb_queue"), module)


	/*
	Process event	
	*/

	channel := make(chan []byte)
	tb_event := bpf.NewTable(module.TableId("events"), module)
	perfMap, err := bpf.InitPerfMap(tb_event, channel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %v\n", err)
	}
	var points []*indbclient.Point

	go func() {
		for {
			var _points []*indbclient.Point

			data := <-channel
			var event datatype.FlowInfo
			err = binary.Read(bytes.NewBuffer(data), hostEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			var i uint16

			// flow info
			if event.Is_n_flow != 0 || event.Is_flow != 0 {
				var path []uint32
				for i := event.Num_INT_hop; i > 0; i-- {
					path = append(path, event.Sw_ids[i - 1])
				}
				path_str := fmt.Sprintf("%v", path)

				fields := map[string]interface{}{
					"flow_latency" : event.Flow_latency,
	                "path" : path_str,
				}

				point, err := indbclient.NewPoint(fmt.Sprintf("flow_stat,%s:%d->%s:%d,proto=%d",
												intToIPv4String(event.Src_ip), event.Src_port,
												intToIPv4String(event.Dst_ip), event.Dst_port,
												event.Ip_proto), nil, fields)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
				}

				_points = append(_points, point)
			}

			// flow_hop_latency
			if event.Is_hop_latency != 0 {
				for i = 0; i < event.Num_INT_hop; i ++ {
					if (event.Is_hop_latency >> i) & 0x01 != 0 {
						fields := map[string]interface{}{
			                "value" : event.Hop_latencies[i],
						}

						point, err := indbclient.NewPoint(fmt.Sprintf("flow_hop_latency,%s:%d->%s:%d,proto=%d,sw_id=%d",
												intToIPv4String(event.Src_ip), event.Src_port,
												intToIPv4String(event.Dst_ip), event.Dst_port,
												event.Ip_proto, event.Sw_ids[i]), nil, fields)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
						}

						_points = append(_points, point)
					}
				}
			}

			if event.Is_tx_utilize != 0 {
				for i = 0; i < event.Num_INT_hop; i ++ {
					if (event.Is_tx_utilize >> i) & 0x01 != 0 {
						fields := map[string]interface{}{
			                "value" : event.Tx_utilizes[i],
						}

						point, err := indbclient.NewPoint(fmt.Sprintf("port_tx_utilize,sw_id=%d,port_id=%d",
														event.Sw_ids[i], event.E_port_ids[i]), nil, fields)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
						}

						_points = append(_points, point)
					}
				}
			}

			// Queue occup
			if event.Is_queue_occup != 0 {
                for i = 0; i < event.Num_INT_hop; i ++ {
                    if (event.Is_queue_occup >> i) & 0x01 != 0 {
						fields := map[string]interface{}{
			                "value" : event.Queue_occups[i],
						}

						point, err := indbclient.NewPoint(fmt.Sprintf("queue_occupancy,sw_id=%d,queue_id=%d",
													event.Sw_ids[i], event.Queue_ids[i]), nil, fields)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
						}

						_points = append(_points, point)
                    }
                }
			}

			// Queue congest
			if event.Is_queue_congest != 0 {
                for i = 0; i < event.Num_INT_hop; i ++ {
                    if (event.Is_queue_congest >> i) & 0x01 != 0 {
						fields := map[string]interface{}{
			                "value" : event.Queue_congests[i],
						}

						point, err := indbclient.NewPoint(fmt.Sprintf("queue_congestion,sw_id=%d,queue_id=%d",
													event.Sw_ids[i], event.Queue_ids[i]), nil, fields)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
						}

						_points = append(_points, point)
					}
				}
			}

			mutex.Lock()
			points = append(points, _points...)
			mutex.Unlock()
		}

	}()

	perfMap.Start()

	/*
	Periodically push event data
	*/

	wg.Add(1)
	go func() {
		defer wg.Done()
			
		for stop_flag == 0 {
			time.Sleep(time.Second)

			if len(points) == 0 {
				continue

			}

			fmt.Printf("event len: %d\n", len(points))

			// New point batch for events
			bpEvent, err := indbclient.NewBatchPoints(indbclient.BatchPointsConfig{
				Database:  INTdb,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create new batch points: %v\n", err)
			}

			mutex.Lock()
			bpEvent.AddPoints(points)
			points = nil
			mutex.Unlock()

			if err := client.Write(bpEvent); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot write the batch: %v\n", err)
			}

		}

	}()


	/*
	Periodically collect data and push to server
	*/

	wg.Add(1)
	go func() {
		defer wg.Done()

		cnt := 0
		for stop_flag == 0 {

			time.Sleep(time.Second)
			cnt++
			if cnt < period_push {
				fmt.Printf("wait Push\n")
				continue
			}
			cnt = 0

			fmt.Printf("Periodically Push\n")

			// Create another point batch for Periodically collect data
			bp, err := indbclient.NewBatchPoints(indbclient.BatchPointsConfig{
				Database:  INTdb,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create new batch points: %v\n", err)
			}

			/*
			Scan tb_flow
			*/

			var i uint16
			flow_iter := tb_flow.Iter()
			for flow_iter.Next() {
				key, leaf := flow_iter.Key(), flow_iter.Leaf()
				if err != nil {
					fmt.Fprintf(os.Stderr, "flow_iter failed: cannot print value: %v\n", err)
				}

				var flow_id datatype.FlowId
				var flow_info datatype.FlowInfo

				if err := binary.Read(bytes.NewBuffer(key), hostEndian, &flow_id); err != nil {
					fmt.Fprintf(os.Stderr, "flow_iter failed: cannot decode key: %v\n", err)
				}

				if err := binary.Read(bytes.NewBuffer(leaf), hostEndian, &flow_info); err != nil {
					fmt.Fprintf(os.Stderr, "flow_iter failed: cannot decode value: %v\n", err)
				}

				// keyStr, leafStr, err := flow_iter.StringValues()
				// fmt.Println(keyStr + leafStr)
				// fmt.Printf("flow_id: %+v \n", flow_id)
				// fmt.Printf("flow_info: %+v \n", flow_info)

				// flow info
				var path []uint32
				for i = flow_info.Num_INT_hop; i > 0; i-- {
					path = append(path, flow_info.Sw_ids[i - 1])
				}
				path_str := fmt.Sprintf("%v", path)

				fields := map[string]interface{}{
					"flow_latency" : flow_info.Flow_latency,
	                "path" : path_str,
				}

				point, err := indbclient.NewPoint(fmt.Sprintf("flow_stat,%s:%d->%s:%d,proto=%d",
												intToIPv4String(flow_id.Src_ip), flow_id.Src_port,
												intToIPv4String(flow_id.Dst_ip), flow_id.Dst_port,
												flow_id.Ip_proto), nil, fields)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
				}

				bp.AddPoint(point)

				// flow_hop_latency
				if flow_info.Is_hop_latency != 0 {
					for i = 0; i < flow_info.Num_INT_hop; i ++ {
						fields := map[string]interface{}{
			                "value" : flow_info.Hop_latencies[i],
						}

						point, err := indbclient.NewPoint(fmt.Sprintf("flow_hop_latency,%s:%d->%s:%d,proto=%d,sw_id=%d",
												intToIPv4String(flow_id.Src_ip), flow_id.Src_port,
												intToIPv4String(flow_id.Dst_ip), flow_id.Dst_port,
												flow_id.Ip_proto, flow_info.Sw_ids[i]), nil, fields)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
						}

						bp.AddPoint(point)

					}
				}
			}


			/*
			Scan tb_egr
			*/

			egr_iter := tb_egr.Iter()
			for egr_iter.Next() {
				key, leaf := egr_iter.Key(), egr_iter.Leaf()
				if err != nil {
					fmt.Fprintf(os.Stderr, "egr_iter failed: cannot print value: %v\n", err)
				}

				var egr_id datatype.EgrId
				var egr_info datatype.EgrInfo

				if err := binary.Read(bytes.NewBuffer(key), hostEndian, &egr_id); err != nil {
					fmt.Fprintf(os.Stderr, "egr_iter failed: cannot decode key: %v\n", err)
				}

				if err := binary.Read(bytes.NewBuffer(leaf), hostEndian, &egr_info); err != nil {
					fmt.Fprintf(os.Stderr, "egr_iter failed: cannot decode value: %v\n", err)
				}

				fields := map[string]interface{}{
	                "value" : egr_info.Tx_utilize,
				}

				point, err := indbclient.NewPoint(fmt.Sprintf("port_tx_utilize,sw_id=%d,port_id=%d",
												egr_id.Sw_id, egr_id.P_id), nil, fields)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
				}

				bp.AddPoint(point)
			}

			/*
			Scan tb_queue
			*/

			queue_iter := tb_queue.Iter()
			for queue_iter.Next() {
				key, leaf := queue_iter.Key(), queue_iter.Leaf()
				if err != nil {
					fmt.Fprintf(os.Stderr, "queue_iter failed: cannot print value: %v\n", err)
				}

				var queue_id datatype.QueueId
				var queue_info datatype.QueueInfo

				if err := binary.Read(bytes.NewBuffer(key), hostEndian, &queue_id); err != nil {
					fmt.Fprintf(os.Stderr, "queue_iter failed: cannot decode key: %v\n", err)
				}

				if err := binary.Read(bytes.NewBuffer(leaf), hostEndian, &queue_info); err != nil {
					fmt.Fprintf(os.Stderr, "queue_iter failed: cannot decode value: %v\n", err)
				}

				// Queue occup
				fields := map[string]interface{}{
	                "value" : queue_info.Occup,
				}

				point, err := indbclient.NewPoint(fmt.Sprintf("queue_occupancy,sw_id=%d,queue_id=%d",
											queue_id.Sw_id, queue_id.Q_id), nil, fields)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
				}

				bp.AddPoint(point)

				// Queue congest
				fields = map[string]interface{}{
	                "value" : queue_info.Congest,
				}

				point, err = indbclient.NewPoint(fmt.Sprintf("queue_congestion,sw_id=%d,queue_id=%d",
											queue_id.Sw_id, queue_id.Q_id), nil, fields)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot create new point: %v\n", err)
				}

				bp.AddPoint(point)
			}



			if err := client.Write(bp); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot write the batch: %v\n", err)
			}
		}

	}()



	// Stop program
	fmt.Println("Prog started ...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	perfMap.Stop()
	stop_flag = 1
	wg.Wait()
}