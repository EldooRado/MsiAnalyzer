TARGET := MsiAnalyzer.out
SOURCES := source/main.cpp source/LogHelper.cpp source/CfbExtractor.cpp source/MsiTableParser.cpp
OBJECTS := obj/main.o obj/LogHelper.o obj/CfbExtractor.o obj/MsiTableParser.o

INCLUDE := -I./include

FLAGS := -std=c++17 -Wall
CXXFLAGS := $(FLAGS)

CXX := g++

all: $(OBJECTS)
	$(CXX) $(CCFLAGS) $(INCLUDE) $(OBJECTS) -o $(TARGET) 

obj/%.o: source/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $^ -o $@

clean:
	rm -rf obj/*.o
	rm -f $(TARGET)