CC:=g++ -std=c++11 -g3 -O0
exe:=siver
obj:=siver.o Sign.o
link:= -lssl -lcrypto

all:$(obj)
	$(CC) -o $(exe) $^ $(link) 

%.o:%.cpp
	$(CC) -c $^ -o $@

.PHONY:clean 
clean:
	rm -f *.o *.out

rebuild:clean all
