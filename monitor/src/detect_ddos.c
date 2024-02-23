#include <unistd.h>
#include "tcp_syn_monitor.h"

// Normal traffic of each ISP
int ISP_NORMAL_TRAFFIC[ISP_NUMBER] = { 100, 100, 100, 100, 100, 100, 100, 100, 100, 100 };
unsigned int DIFFICULTY[16] = {6000000, 3000000, 1500000, 1000000, 500000, 210000, 110000, 55000, 30000, 20000, 6500, 3500, 2500, 2000, 1500, 1000};

void
set_difficulty(int isp_id, int current)
{
	// TODO: implement this function - set the difficulty of the ISP
	//         according to the ISP_NORMAL_TRAFFIC and the current traffic
	
	int tmp = ISP_NORMAL_TRAFFIC[isp_id];
	int rise = 0;
	while (tmp <= current) {
		tmp *= 2;
		rise++;
		if (rise == 16) {
			break;
		}
	}

	unsigned int puzzle_threshold = DIFFICULTY[rise];
	char *isp_dns_ip_str;

	switch (isp_id) {
		case 0:
			isp_dns_ip_str = "192.168.0.12";
			break;
		case 1:
			isp_dns_ip_str = "192.168.0.13";
			break;
		case 2:
			isp_dns_ip_str = "192.168.0.14";
			break;
		case 3:
			isp_dns_ip_str = "192.168.0.15";
			break;
		case 4:
			isp_dns_ip_str = "192.168.0.16";
			break;
		case 5:
			isp_dns_ip_str = "192.168.0.17";
			break;
		case 6:
			isp_dns_ip_str = "192.168.0.18";
			break;
		case 7:
			isp_dns_ip_str = "192.168.0.19";
			break;
		case 8:
			isp_dns_ip_str = "192.168.0.10";
			break;
		case 9:
			isp_dns_ip_str = "192.168.0.11";
			break;
		default:
			isp_dns_ip_str = "";
	}

	syscall(454, inet_addr(isp_dns_ip_str), puzzle_threshold);
}

void
handle_ddos(cb_ptr buffer)
{
	for (int i = 0; i < ISP_NUMBER; i++) {
		int current_traffic = get_circular_buffer_isp_count(buffer, i);
		set_difficulty(i, current_traffic);
	}
}

int
detect_ddos(void)
{
	const int DDOS_THRESHOLD = 1000;
	struct circular_buffer buffer;
	init_circular_buffer(&buffer);

	pcap_thread_data data;
	init_pcap_thread(&data, &buffer);

	start_pcap_thread(&data);

	printf("pcap thread started\n");
	printf("press any key to stop\n");
	printf("ISP number:\t");

	for (int i = 0; i < ISP_NUMBER; i++) {
		printf("ISP%d\t", i);
	}

	printf("\n");

	FILE *tcp_count_logfile = fopen("tcp_count_log.tsv", "w");
	if (tcp_count_logfile == NULL) {
		printf("Error opening file!\n");
		return 1;
	}

	struct timeval t;
	while (1) {
		usleep(100000);
		gettimeofday(&t, NULL);
		fprintf(tcp_count_logfile, "%ld.%03d\t", t.tv_sec, t.tv_usec / 1000);

		if (get_circular_buffer_size(&buffer) > DDOS_THRESHOLD) {
			printf("DDOS detected\n");
			handle_ddos(&buffer);
		}

		for (int i = 0; i < ISP_NUMBER; i++) {
			fprintf(tcp_count_logfile, "%d\t", get_circular_buffer_isp_count(&buffer, i));
		}

		printf("\n");

		fflush(tcp_count_logfile);
		fflush(stdout);
	}

	fclose(tcp_count_logfile);

	stop_pcap_thread(&data);

	return 0;
}

void
start_detect_ddos_thread(pthread_t *tid)
{
	pthread_create(tid, NULL, (void*)detect_ddos, NULL);
}

void
stop_detect_ddos_thread(pthread_t *tid)
{
	pthread_join(*tid, NULL);
}
