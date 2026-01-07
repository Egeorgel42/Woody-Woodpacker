#include "woody.h"

void create_woody(void *file_ptr, size_t total_file_size, char **err_msg)
{
    // create woody file
    int fd_out = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd_out == -1) {
        munmap(file_ptr, total_file_size); // free the mapped file in ram
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    // write content
    if (write(fd_out, file_ptr, total_file_size) == -1) {
         close(fd_out);
         munmap(file_ptr, total_file_size);
         vprintf_exit(ERR_READ, err_msg, strerror(errno));
    }

    close(fd_out);
}

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

static void *patch_payload(parsing_info *info, void *raw_payload, size_t size, char **err_msg)
{
	// create an editable copy of payload
	char *patched = malloc(size);
	if (!patched) {
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}
	ft_memcpy(patched, raw_payload, size);

	if (info->is_64)
	{
		// Offsets calculated from the end of asm 64 bits
		// ASM structure : [ ...Code... | key (16) | Start(8) | Size (8) | Old_EP (8) }
		size_t off_key 		= size - 40;
		size_t off_start 	= size - 24;
		size_t off_size 	= size - 16;
		size_t off_ep 		= size - 8;

		ft_memcpy(patched + off_key, info->key, 16); // Key (16 bits)
		ft_memcpy(patched + off_start, &info->encrypt->mem_addr, 8); // Virtual Address .text
		ft_memcpy(patched + off_size, &info->encrypt->file_size, 8); // .text Size
		ft_memcpy(patched + off_ep, &info->encrypt->old_entry_point, 8); // old entry point
	}
	else //32 bits
	{
		// ASM structure: [ ...Code... | Key (16) | Start (4) | Size (4) | Old_EP (4) ]
        size_t off_key   = size - 28;
        size_t off_start = size - 12;
        size_t off_size  = size - 8;
        size_t off_ep    = size - 4;

        // convert in 32 bits
        uint32_t start32 = (uint32_t)info->encrypt->mem_addr;
        uint32_t size32  = (uint32_t)info->encrypt->file_size;
        uint32_t ep32    = (uint32_t)info->encrypt->old_entry_point;

        ft_memcpy(patched + off_key, info->key, 16);               // key stays 16 bits
        ft_memcpy(patched + off_start, &start32, 4);
        ft_memcpy(patched + off_size, &size32, 4);
        ft_memcpy(patched + off_ep, &ep32, 4);
	}
	return (patched);
}


void	payload_insert(parsing_info *info, char *file_buf, char *exec_path, char **err_msg)
{
    size_t raw_size;
    
    // Get raw payload (readonly)
    void *raw_payload = get_payload(info, &raw_size, file_buf, exec_path, err_msg);

    // Create final payload with the data inside (malloc'd ptr)
    void *final_payload = patch_payload(info, raw_payload, raw_size, err_msg);

    // free raw_payload
    munmap(raw_payload, raw_size);

    // call injection function
    if (info->is_64)
        payload_insert64(info, file_buf, final_payload, raw_size, err_msg);
    else
        payload_insert32(info, file_buf, final_payload, raw_size, err_msg);

    free(final_payload);
}