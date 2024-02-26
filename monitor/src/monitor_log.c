#include <stdio.h>
#include <unistd.h>
#include "tcp_syn_monitor.h"
#include "monitor_log.h"

void*
log_thread(void* arg)
{
	log_thread_data *data = (log_thread_data*)arg;
	cb_ptr buffer = (cb_ptr)arg;
	FILE *tcp_count_logfile = fopen("tcp_count_log.tsv", "w");
	if (tcp_count_logfile == NULL) {
		printf("Error opening file!\n");
		return NULL;
	}

	struct timeval t;
	while (1) {
		usleep(100000);
		gettimeofday(&t, NULL);
		fprintf(tcp_count_logfile, "%ld.%03d\t", t.tv_sec, t.tv_usec / 1000);
		fprintf(stdout, "%ld.%03d\t", t.tv_sec, t.tv_usec / 1000);

		for (int i = 0; i < ISP_NUMBER; i++) {
			fprintf(tcp_count_logfile, "%d\t", get_circular_buffer_isp_count(buffer, i));
			fprintf(stdout, "%d\t", get_circular_buffer_isp_count(buffer, i));
		}

		fflush(tcp_count_logfile);
		fflush(stdout);

	}

	fclose(tcp_count_logfile);
	tcp_count_logfile = NULL;

	return NULL;
}

void
start_log_thread(log_thread_data *data)
{
	int ret = pthread_create(&data->tid, NULL, (void*)log_thread, (void*)data);
	if (ret) {
		fprintf(stderr, "Error: log pthread_create() failed: (%d)\n", ret);
	}
}

void
stop_log_thread(log_thread_data *data)
{
	int ret = pthread_cancel(data->tid);
	if (ret) {
		fprintf(stderr, "Error: log pthread_cancel() failed: (%d)\n", ret);
	}
}
