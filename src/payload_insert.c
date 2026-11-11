#include "woody.h"

void create_woody(void *file_ptr, size_t total_file_size, char **err_msg)
{
    // create woody file
    int fd_out = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd_out == -1) {
		munmap(file_ptr, total_file_size);
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    // write content
    if (write(fd_out, file_ptr, total_file_size) == -1) {
		close(fd_out);
		munmap(file_ptr, total_file_size);
		vprintf_exit(ERR_WRITE, err_msg, strerror(errno));
    }

    close(fd_out);
}

static mmap_alloc	get_payload(parsing_info *info, mmap_alloc *executable, char **err_msg)
{
	mmap_alloc res;
    int fd = 0;
	if (info->is_64)
		fd = open(PAYLOAD64, O_RDWR);
	else
		fd = open(PAYLOAD32, O_RDWR);

    if (fd == -1) {
		munmap(executable->addr, executable->size);
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
		munmap(executable->addr, executable->size);
        vprintf_exit(ERR_STAT, err_msg, strerror(errno));
    }
    res.size = st.st_size;

    res.addr = mmap(NULL, res.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (res.addr == MAP_FAILED)
	{
		munmap(executable->addr, executable->size);
        vprintf_exit(ERR_MMAP, err_msg, strerror(errno));
	}
	return res;
}

void	payload_insert(parsing_info *info, mmap_alloc *executable, char **err_msg)
{
    // Get raw payload (readonly)
    mmap_alloc payload = get_payload(info, executable, err_msg);

    // call injection function
    if (info->is_64)
        payload_insert64(info, executable, &payload, err_msg);
    else
        payload_insert32(info, executable, &payload, err_msg);
}