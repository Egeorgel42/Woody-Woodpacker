#include "woody.h"

static void	*get_payload(parsing_info *info, size_t *payload_size, char *file_buf, char *exec_path, char **err_msg)
{
	char *str;
	char payload_path[22] = "Payload/payload32.bin";
	if (info->is_64)
		ft_memcpy(payload_path, "Payload/payload64.bin", 22);

	exec_path[ft_strlen(exec_path) - ft_strlen("woody_woodpacker")] = 0;

	str = ft_strjoinfree(exec_path, payload_path, true, false);
	if (!str)
	{
		freeall(3, file_buf, info->encrypt, info->payload);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}
	int fd = open(str, O_RDONLY);
	free(str);
    if (fd == -1) {
		freeall(3, file_buf, info->encrypt, info->payload);
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
		freeall(3, file_buf, info->encrypt, info->payload);
        vprintf_exit(ERR_STAT, err_msg, strerror(errno));
    }
    *payload_size = st.st_size;

    void *ptr = mmap(NULL, *payload_size, PROT_READ, 0, fd, 0);
    close(fd);

    if (ptr == MAP_FAILED)
	{
		freeall(3, file_buf, info->encrypt, info->payload);
        vprintf_exit(ERR_MMAP, err_msg, strerror(errno));
	}
	return ptr;
}

void	payload_insert(parsing_info *info, char *file_buf, char *exec_path, char **err_msg)
{
	size_t	payload_size;
	void *payload = get_payload(info, &payload_size, file_buf, exec_path, err_msg);
	if (info->is_64)
		payload_insert64(info, file_buf, payload, payload_size, err_msg);
	else
		payload_insert32(info, file_buf, payload, payload_size, err_msg);

}