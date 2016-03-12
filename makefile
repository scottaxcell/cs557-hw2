all:
	g++ -std=c++11 fsniffer.cxx -o fsniffer -lpcap
deter:
	g++48 -std=c++11 fsniffer.cxx -o fsniffer -lpcap
clean:
	rm -f fsniffer
