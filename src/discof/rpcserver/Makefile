all : keywords.c keywords.h

keywords.c keywords.h : genkeywords.cxx keywords.txt
	g++ -g -o genkeywords genkeywords.cxx
	./genkeywords
	rm genkeywords
