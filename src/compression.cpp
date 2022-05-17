#include <stdio.h>
#include <string.h>
#include "rat_server.h"

#include "miniz.c"

void decompress_buffer(struct compression *decompress)
{
    //strncpy((char*)decompress->transformed_buffer, (char*)decompress->orig_buffer, decompress->orig_size);
    //decompress->transformed_size = decompress->orig_size;
    //return;

    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = (uInt)decompress->orig_size;
    infstream.next_in = (Bytef *)decompress->orig_buffer;
    infstream.avail_out = (uInt)BUFFER_SIZE;
    infstream.next_out = (Bytef *)decompress->transformed_buffer;

    inflateInit(&infstream);
    inflate(&infstream, Z_NO_FLUSH);
    inflateEnd(&infstream);

    decompress->transformed_size = infstream.total_out;
}

void compress_buffer(struct compression *compress)
{
    //strncpy((char*)compress->transformed_buffer, (char*)compress->orig_buffer, compress->orig_size);
    //compress->transformed_size = compress->orig_size;
    //return;

    z_stream defstream;
    defstream.zalloc = Z_NULL;
    defstream.zfree = Z_NULL;
    defstream.opaque = Z_NULL;
    defstream.avail_in = (uInt)compress->orig_size;
    defstream.next_in = (Bytef *)compress->orig_buffer;
    defstream.avail_out = (uInt)BUFFER_SIZE;
    defstream.next_out = (Bytef *)compress->transformed_buffer;

    if (Z_OK != deflateInit(&defstream, Z_DEFAULT_COMPRESSION)) {
        #ifdef DEBUG
        printf("Error compressing\n");
        #endif
        return;
    }
    deflate(&defstream, Z_FINISH);
    deflateEnd(&defstream);
    compress->transformed_size = defstream.total_out;
}

