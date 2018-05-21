#!/bin/bash

# xdotool key ctrl+112 # prev tab
# xdotool key ctrl+117 # next tab

# LX terminal
# We need 3 tabs: 1: for run script - 2: for tcpreplay - 
# 3: for ssh to run BPF collector - 4: for ssh mpstat - 5: VM2 for influxDB and Prometheus
TCPREPLAY=2
BPF=3
MPSTAT=4
VM2=5

CPU_EVAL_TIME=30


# TEST 0: how does the packet report rate affect CPU usage?
# -- tcpreplay (Mpps): 0.4, 0.6, 0.8, 1.0, 1.2, 1.4
# -- 6sw, flow path on hop latency

xdotool key alt+$MPSTAT
xdotool type "echo --------TEST 0--------- >> result.txt"
xdotool key Return
sleep 2

# start test
for RATE in 400000 600000 800000 1000000 1200000 1400000; do
	for COLLECTOR in "PTCollector.py" "InDBClient.py --cython -H 192.168.122.106"; do

		if [ $COLLECTOR == "PTCollector.py" ]
		then
			# start prometheus
			xdotool key alt+$VM2
			xdotool type "./prometheus --config.file=prometheus.yml"
			xdotool key Return
			sleep 2
		fi

		# start Collector
		xdotool key alt+$BPF
		xdotool type "python $COLLECTOR ens4"
		xdotool key Return
		sleep 6

		# start tcpreplay
		xdotool key alt+$TCPREPLAY
		xdotool type "tcpreplay -i vtap0  -K --loop 50000000 --unique-ip -p $RATE pcaps/t3_6sw_100fl_swid_hoplatency.pcap"
		xdotool key Return
		sleep 4

		# start mpstart
		xdotool key alt+$MPSTAT
		xdotool type "echo $COLLECTOR, rate: $RATE >> result.txt"
		xdotool key Return
		sleep 2
		xdotool type "mpstat $CPU_EVAL_TIME 1 | grep -E \"idle|Average\" >> result.txt"
		xdotool key Return
		sleep $CPU_EVAL_TIME
		sleep 2
		xdotool type "echo >> result.txt"
		xdotool key Return
		sleep 2

		#cancel tcpreplay
		xdotool key alt+$TCPREPLAY
		xdotool key ctrl+c
		sleep 2

		# cancel Collector
		xdotool key alt+$BPF
		xdotool key ctrl+c
		sleep 2

		if [ $COLLECTOR == "PTCollector.py" ]
		then
			# delete prometheus data
			xdotool key alt+$VM2
			xdotool key ctrl+c
			sleep 2
			xdotool type "rm  -rf data/wal"
			xdotool key Return
			sleep 2
		fi
	done
done



# TEST 1, 2, 3, 4

xdotool key alt+$MPSTAT
xdotool type "echo --------TEST 1, 2, 3, 4--------- >> result.txt"
xdotool key Return
sleep 2


# start test
for REPORT in 	"t1_6sw_10fl_swid.pcap" \
				"t1_6sw_100fl_swid.pcap" \
				"t1_6sw_500fl_swid.pcap" \
				"t1_6sw_1000fl_swid.pcap" \
				"t1_6sw_2000fl_swid.pcap" \
				"t1_6sw_5000fl_swid.pcap" \
				"t2_1sw_100fl_swid.pcap" \
				"t2_2sw_100fl_swid.pcap" \
				"t2_3sw_100fl_swid.pcap" \
				"t2_4sw_100fl_swid.pcap" \
				"t2_5sw_100fl_swid.pcap" \
				"t2_6sw_100fl_swid.pcap" \
				"t2_1sw_100fl_all.pcap" \
				"t2_2sw_100fl_all.pcap" \
				"t2_3sw_100fl_all.pcap" \
				"t2_4sw_100fl_all.pcap" \
				"t2_5sw_100fl_all.pcap" \
				"t2_6sw_100fl_all.pcap" \
				"t3_3sw_100fl_swid.pcap" \
				"t3_3sw_100fl_swid_hoplatency.pcap" \
				"t3_3sw_100fl_swid_qoccup_qcongest.pcap" \
				"t3_3sw_100fl_swid_txutilize.pcap" \
				"t3_3sw_100fl_all.pcap" \
				"t3_6sw_100fl_swid.pcap" \
				"t3_6sw_100fl_swid_hoplatency.pcap" \
				"t3_6sw_100fl_swid_qoccup_qcongest.pcap" \
				"t3_6sw_100fl_swid_txutilize.pcap" \
				"t3_6sw_100fl_all.pcap" \
				"t4_3sw_100fl_20event_all.pcap" \
				"t4_3sw_100fl_50event_all.pcap" \
				"t4_3sw_100fl_100event_all.pcap" \
				"t4_3sw_100fl_200event_all.pcap" \
				"t4_3sw_100fl_500event_all.pcap"; do

	for COLLECTOR in "PTCollector.py" "InDBClient.py --cython -H 192.168.122.106"; do

		if [ $COLLECTOR == "PTCollector.py" ]
		then
			# start prometheus
			xdotool key alt+$VM2
			xdotool type "./prometheus --config.file=prometheus.yml"
			xdotool key Return
			sleep 2
		fi

		# start Collector
		xdotool key alt+$BPF
		xdotool type "python $COLLECTOR ens4"
		xdotool key Return
		sleep 6

		# start tcpreplay
		xdotool key alt+$TCPREPLAY
		xdotool type "tcpreplay -i vtap0  -K --loop 50000000 --unique-ip -p 1000000 pcaps/$REPORT"
		xdotool key Return
		sleep 4

		# start mpstart
		xdotool key alt+$MPSTAT
		xdotool type "echo $COLLECTOR, test file: $REPORT >> result.txt"
		xdotool key Return
		sleep 2
		xdotool type "mpstat $CPU_EVAL_TIME 1 | grep -E \"idle|Average\" >> result.txt"
		xdotool key Return
		sleep $CPU_EVAL_TIME
		sleep 2
		xdotool type "echo >> result.txt"
		xdotool key Return
		sleep 2

		#cancel tcpreplay
		xdotool key alt+$TCPREPLAY
		xdotool key ctrl+c
		sleep 2

		# cancel Collector
		xdotool key alt+$BPF
		xdotool key ctrl+c
		sleep 2

		if [ $COLLECTOR == "PTCollector.py" ]
		then
			# delete prometheus data
			xdotool key alt+$VM2
			xdotool key ctrl+c
			sleep 2
			xdotool type "rm  -rf data/wal"
			xdotool key Return
			sleep 2
		fi
	done
done

xdotool key Return