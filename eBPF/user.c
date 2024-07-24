#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <bpf/bpf.h>
#include <errno.h>

#define MAX_COMMAND_LEN 256


// This user space program reads data from an eBPF
// map and executes it as a system command.
int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/my_map");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    char command[MAX_COMMAND_LEN];

    while (1) {
        // Read data from the BPF map
        __u32 key = 1;
        int ret = bpf_map_lookup_elem(map_fd, &key, command);
		
		// Check if the map has anything written in it.
		if (ret == 0) {
            // Execute the command
            system(command);

	    // Clear the map entry
            bpf_map_delete_elem(map_fd, &key);
        }
        usleep(1000000);  // 1 second interval, why not?
    }

    return 0;
}

