all:
	g++ -std=c++11 -Wall fsniffer.cxx -o fsniffer -lpcap
clean:
	rm -f fsniffer
