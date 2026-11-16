#include "woody.h"

off_t get_file_size(int fd)
{
	off_t	size;

	size = lseek(fd, 0, SEEK_END);
	error_if(size < 0, ERR_LSEEK, strerror(errno));
	error_if(lseek(fd, 0, SEEK_SET) < 0, ERR_LSEEK, strerror(errno));
	return size;
}

void seek_safe(int fd, int64_t offset)
{
	error_if(
		lseek(fd, (off_t)offset, SEEK_SET) < 0,
		ERR_LSEEK,
		strerror(errno));
}

bool read_safe(int fd, void *buffer, size_t size) {
	size_t	done = 0;
	ssize_t	ret;
	size_t	chunk;

	while (done < size) {
		chunk = size - done;
		if (chunk > (size_t)SSIZE_MAX) {
			chunk = (size_t)SSIZE_MAX;
        }
		ret = read(fd, (char *)buffer + done, chunk);
		if (ret < 0 && errno == EINTR) {
			continue;
        } else if (ret <= 0) {
			return false;
		}
		done += (size_t)ret;
	}
	return true;
}
