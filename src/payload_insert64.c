#include "../include/woody.h"



void	payload_insert64(char *file_buf, char *payload_path, char **err_msg)
{
	size_t	payload_size;
	char *payload_buff = get_payload(&payload_size, true, file_buf, payload_path, err_msg);

}