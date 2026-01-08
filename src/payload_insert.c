#include "woody.h"

void create_woody(void *file_ptr, size_t total_file_size, char **err_msg)
{
    // create woody file
    int fd_out = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd_out == -1) {
        free(file_ptr);
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    // write content
    if (write(fd_out, file_ptr, total_file_size) == -1) {
		close(fd_out);
		free(file_ptr);
		vprintf_exit(ERR_WRITE, err_msg, strerror(errno));
    }

    close(fd_out);
	free(file_ptr);
}

static mmap_alloc	get_payload(parsing_info *info, mmap_alloc *executable, char *exec_path, char **err_msg)
{
	mmap_alloc res;
	char *str;
	char payload_path[22] = "Payload/payload32.bin";
	if (info->is_64)
		ft_memcpy(payload_path, "Payload/payload64.bin", 22);

	exec_path[ft_strlen(exec_path) - ft_strlen("woody_woodpacker")] = 0;

	str = ft_strjoinfree(exec_path, payload_path, false, false);
	if (!str)
	{
		munmap(executable->addr, executable->size);
		free(info->payload);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}
	int fd = open(str, O_RDWR);
	free(str);
    if (fd == -1) {
		munmap(executable->addr, executable->size);
		free(info->payload);
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
		munmap(executable->addr, executable->size);
		free(info->payload);
        vprintf_exit(ERR_STAT, err_msg, strerror(errno));
    }
    res.size = st.st_size;

    res.addr = mmap(NULL, res.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (res.addr == MAP_FAILED)
	{
		munmap(executable->addr, executable->size);
		free(info->payload);
        vprintf_exit(ERR_MMAP, err_msg, strerror(errno));
	}
	return res;
}

static void	patch_payload(parsing_info *info, mmap_alloc payload)
{
	if (info->is_64)
	{
		// Offsets calculated from the end of asm 64 bits
		// ASM structure : [ ...Code... | key (16) | Start(8) | Size (8) | Old_EP (8) }
		size_t off_key 		= payload.size - 40;
		size_t off_start 	= payload.size - 24;
		size_t off_size 	= payload.size - 16;
		size_t off_ep 		= payload.size - 8;

        uint64_t ep64    = (uint32_t)((payload_info64 *) info->payload)->main_header_replace.e_entry;

		ft_memcpy(payload.addr + off_key, info->encrypt.key, 16); // Key (16 bits)
		ft_memcpy(payload.addr + off_start, &info->encrypt.mem_addr, 8); // Virtual Address .text
		ft_memcpy(payload.addr + off_size, &info->encrypt.file_size, 8); // .text Size
		ft_memcpy(payload.addr + off_ep, &ep64, 8); // old entry point
	}
	else //32 bits
	{
		// ASM structure: [ ...Code... | Key (16) | Start (4) | Size (4) | Old_EP (4) ]
        size_t off_key   = payload.size - 28;
        size_t off_start = payload.size - 12;
        size_t off_size  = payload.size - 8;
        size_t off_ep    = payload.size - 4;

        // convert in 32 bits
        uint32_t start32 = (uint32_t)info->encrypt.mem_addr;
        uint32_t size32  = (uint32_t)info->encrypt.file_size;
        uint32_t ep32    = (uint32_t)((payload_info32 *) info->payload)->main_header_replace.e_entry;

        ft_memcpy(payload.addr + off_key, info->encrypt.key, 16);               // key stays 16 bits
        ft_memcpy(payload.addr + off_start, &start32, 4);
        ft_memcpy(payload.addr + off_size, &size32, 4);
        ft_memcpy(payload.addr + off_ep, &ep32, 4);
	}
}


void	payload_insert(parsing_info *info, mmap_alloc *executable, char *exec_path, char **err_msg)
{
    // Get raw payload (readonly)
    mmap_alloc payload = get_payload(info, executable, exec_path, err_msg);

    // Create final payload with the data inside (malloc'd ptr)
    patch_payload(info, payload);

    // call injection function
    if (info->is_64)
        payload_insert64(info, executable, &payload, err_msg);
    else
        payload_insert32(info, executable, &payload, err_msg);
}