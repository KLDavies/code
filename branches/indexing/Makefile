#CXX = g++
#CXXFLAGS = -W -Wall -O0 -ggdb

CXX=clang++
CXXFLAGS = -O0 -g

GOAL = test
OBJ = main.o helpers.o

all: $(GOAL)

#fast: CXXFLAGS = -W -Wall -O3
fast: CXXFLAGS = -O4
fast: $(GOAL)

test: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(GOAL) $(OBJ) -lfuzzy

nice:
	rm -f *~

clean: nice
	rm -f $(OBJ) $(GOAL)
