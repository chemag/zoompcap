


all: \
    atlas.zoom.pcap.packets.csv \
    atlas.zoom.pcap.packets.csv.summary.txt \
    atlas.zoom.pcap.packets.csv.distribution.txt \
    atlas.zoom.pcap.packets.csv.distribution.png \
    aloha.zoom.pcap.packets.csv \
    aloha.zoom.pcap.packets.csv.summary.txt \
    aloha.zoom.pcap.packets.csv.distribution.txt \
    aloha.zoom.pcap.packets.csv.distribution.png \
    atlas.pcap.network-time.csv \
    aloha.pcap.network-time.csv


atlas.zoom.pcap.packets.csv: atlas.zoom.pcap
	tshark -r atlas.zoom.pcap -Y 'not ip.proto==1 && ip.proto==17' -n -T fields -E header=y -E separator=, -e frame.number -e frame.len -e ip.src -e ip.dst -e udp.payload > atlas.zoom.pcap.packets.csv
	sed -i 's/^frame.number/#frame.number/' atlas.zoom.pcap.packets.csv


aloha.zoom.pcap.packets.csv: aloha.zoom.pcap
	tshark -r aloha.zoom.pcap -Y 'not ip.proto==1 && ip.proto==17' -n -T fields -E header=y -E separator=, -e frame.number -e frame.len -e ip.src -e ip.dst -e udp.payload > aloha.zoom.pcap.packets.csv
	sed -i 's/^frame.number/#frame.number/' aloha.zoom.pcap.packets.csv


atlas.zoom.pcap.packets.csv.summary.txt: atlas.zoom.pcap.packets.csv
	./analyze.py atlas.zoom.pcap.packets.csv > atlas.zoom.pcap.packets.csv.summary.txt

aloha.zoom.pcap.packets.csv.summary.txt: aloha.zoom.pcap.packets.csv
	./analyze.py aloha.zoom.pcap.packets.csv > aloha.zoom.pcap.packets.csv.summary.txt


atlas.zoom.pcap.packets.csv.distribution.txt:
	cat atlas.zoom.pcap.packets.csv |awk -F ',' '{print $$2}' |sort -n |uniq -c |sort -n > $@


aloha.zoom.pcap.packets.csv.distribution.txt:
	cat aloha.zoom.pcap.packets.csv |awk -F ',' '{print $$2}' |sort -n |uniq -c |sort -n > $@


atlas.zoom.pcap.packets.csv.distribution.png: atlas.zoom.pcap.packets.csv
	~/proj/plotty/plotty-histogram.py -d --legend-loc none --sep ',' --xcol frame.len --xlabel "packet length (bytes)" --ylabel "occurrences" --title "Packet size distribution" --histogram-bins 1500 -i atlas.zoom.pcap.packets.csv $@

aloha.zoom.pcap.packets.csv.distribution.png: aloha.zoom.pcap.packets.csv
	~/proj/plotty/plotty-histogram.py -d --legend-loc none --sep ',' --xcol frame.len --xlabel "packet length (bytes)" --ylabel "occurrences" --title "Packet size distribution" --histogram-bins 1500 -i aloha.zoom.pcap.packets.csv $@


atlas.pcap: atlas.zoom.pcap
	../bin/zoompcap.py atlas.zoom.pcap atlas.pcap

aloha.pcap: aloha.zoom.pcap
	../bin/zoompcap.py aloha.zoom.pcap aloha.pcap

atlas.pcap.network-time.csv: atlas.pcap
	~/proj/rtpcap/rtpcap.py --connections 11 --network-time atlas.pcap

aloha.pcap.network-time.csv: aloha.pcap
	~/proj/rtpcap/rtpcap.py --connections 11 --network-time aloha.pcap


clean:
	\rm -rf atlas.zoom.pcap.packets.csv atlas.zoom.pcap.packets.csv.summary.txt atlas.zoom.pcap.packets.csv.distribution.txt atlas.zoom.pcap.packets.csv.distribution.png
	\rm -rf atlas.pcap.network-time.csv
	\rm -rf atlas.pcap.network-time.ip_src_*.csv
	\rm -rf aloha.zoom.pcap.packets.csv aloha.zoom.pcap.packets.csv.summary.txt aloha.zoom.pcap.packets.csv.distribution.txt aloha.zoom.pcap.packets.csv.distribution.png
	\rm -rf aloha.pcap.network-time.csv
	\rm -rf aloha.pcap.network-time.ip_src_*.csv

realclean: clean
	\rm -rf aloha.pcap atlas.pcap
