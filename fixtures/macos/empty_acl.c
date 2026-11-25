/* Provision the explicit empty ACL on a fresh directory owned by the CLI test. */
#include <fcntl.h>
#include <stdio.h>
#include <sys/acl.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc != 2) {
		return 2;
	}

	int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (directory < 0) {
		perror("open synthetic directory");
		return 1;
	}

	acl_t empty = acl_init(0);
	if (empty == NULL) {
		perror("allocate empty ACL");
		close(directory);
		return 1;
	}

	int status = acl_set_fd_np(directory, empty, ACL_TYPE_EXTENDED);
	if (status < 0) {
		perror("set explicit empty ACL");
	}
	acl_free(empty);
	close(directory);
	return status < 0;
}
