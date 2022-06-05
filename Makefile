all : 
	gcc -o rate_limiter src/rate_limiter.c -lnetfilter_queue

clean:
	rm rate_limiter
