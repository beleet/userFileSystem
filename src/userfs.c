#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include "userfs.h"

enum {
    BLOCK_SIZE = 512,
    MAX_FILE_SIZE = 1024 * 1024 * 100,
};

/** Global error code. Set from any function on any error. */
static enum ufs_error_code ufs_error_code = UFS_ERR_NO_ERR;

struct block {
    /** Block memory. */
    char *memory;
    /** How many bytes are occupied. */
    int occupied;
    /** Next block in the file. */
    struct block *next;
    /** Previous block in the file. */
    struct block *prev;

    /* PUT HERE OTHER MEMBERS */
};

typedef struct block Block;

struct file {
    /** Double-linked list of file blocks. */
    struct block *block_list;
    /**
     * Last block in the list above for fast access to the end
     * of file.
     */
    struct block *current_block;
    /** How many file descriptors are opened on the file. */
    int refs;
    /** File name. */
    const char *name;
    /** Files are stored in a double-linked list. */
    struct file *next;
    struct file *prev;

    /* PUT HERE OTHER MEMBERS */
    size_t size;

    bool obsolete;
};

/** List of all files. */
static struct file *file_list = NULL;

struct filedesc {
    struct file *file;

    int flags;

    size_t position;
};

/**
 * An array of file descriptors. When a file descriptor is
 * created, its pointer drops here. When a file descriptor is
 * closed, its place in this array is set to NULL and can be
 * taken by next ufs_open() call.
 */
static struct filedesc **file_descriptors = NULL;
static int file_descriptor_count = 0;
static int file_descriptor_capacity = 0;

enum ufs_error_code
ufs_errno()
{
    return ufs_error_code;
}


int
ufs_open(const char *filename, int flags) {

    struct file *ptr = file_list;

    while (ptr != NULL) {
        if (!ptr->obsolete && !strcmp(ptr->name, filename))
            break;
        ptr = ptr->next;
    }

    if (ptr != NULL) (ptr->refs)++;
    else {
        if (flags == 0 || UFS_CREATE == 0) {
            ufs_error_code = UFS_ERR_NO_FILE;
            return -1;
        }

        else {
            ptr = (struct file *) malloc(sizeof(struct file));

            if (ptr == NULL) {
                ufs_error_code = UFS_ERR_NO_MEM;
                return -1;
            }

            else {
                ptr->block_list = NULL, ptr->current_block = NULL, ptr->name = strdup(
                        filename), ptr->next = NULL, ptr->prev = NULL;
                ptr->refs = 1, ptr->size = 0, ptr->obsolete = false;

                if (file_list == NULL) file_list = ptr;

                else {
                    struct file *last_file = file_list;
                    while (last_file->next != NULL) last_file = last_file->next;
                    last_file->next = ptr, ptr->prev = last_file;
                }
            }
        }
    }

    struct filedesc *fd_ptr = (struct filedesc *) malloc(sizeof(struct filedesc));
    if (fd_ptr == NULL) {
        ufs_error_code = UFS_ERR_NO_MEM;
        return -1;
    }

    else {
        fd_ptr->file = ptr, fd_ptr->flags = flags, fd_ptr->position = 0;
        int free_fd = -1, i = file_descriptor_capacity - 1;

        while (i >= 0 && !file_descriptors[i]) {
            free_fd = i;
            break;
        }

        if (free_fd == -1) {
            file_descriptors = realloc(
                    file_descriptors,
                    sizeof(struct file_descriptor *) * (file_descriptor_capacity + 1)
            );
            free_fd = file_descriptor_capacity, file_descriptor_capacity++;
        }

        file_descriptors[free_fd] = fd_ptr;
        return free_fd;
    }
}


ssize_t
ufs_write(int fdes, const char *buffer, size_t size) {

    int error, pass = 0;

    if (fdes < 0 || fdes >= file_descriptor_capacity) error =  UFS_ERR_NO_FILE;
    else if (!file_descriptors[fdes]) error = UFS_ERR_NO_FILE;
    else error = UFS_ERR_NO_ERR;

    if (error) {
        ufs_error_code = error;
        return -1;
    }

    else {
        struct filedesc *fd = file_descriptors[fdes];

        if (fd->flags & UFS_READ_ONLY) {
            ufs_error_code = UFS_ERR_NO_PERMISSION;
            return -1;
        }

        else {
            struct file *file = fd->file;

            if (fd->position > fd->file->size) fd->position = fd->file->size;

            if (file->current_block == NULL) {
                file->current_block = (Block *) malloc(sizeof(Block)), file->block_list = file->current_block;
                file->current_block->memory = (char *) malloc(sizeof(char) * BLOCK_SIZE);
                file->current_block->prev = NULL, file->current_block->next = NULL, file->current_block->occupied = 0;
            }

            Block *block = file->block_list;

            while (++pass * BLOCK_SIZE < fd->position) {
                block = block->next;
                if (block == NULL)
                    block = (Block *) malloc(sizeof(Block)), block->memory = (char *) malloc(sizeof(char) * BLOCK_SIZE), \
                    block->prev = file->current_block, block->next = NULL, block->occupied = 0, \
                    file->current_block->next = block, file->current_block = block;
            }

            size_t block_offset = fd->position % BLOCK_SIZE, bytes = 0;

            while (bytes < size) {
                if (block->occupied == BLOCK_SIZE) {
                    Block *new_block = (Block *) malloc(sizeof(Block));
                    new_block->memory = (char *) malloc(sizeof(char) * BLOCK_SIZE);
                    new_block->prev = file->current_block, new_block->next = NULL, new_block->occupied = 0;
                    file->current_block->next = new_block, file->current_block = new_block, block = new_block, block_offset = 0;
                }

                size_t written = BLOCK_SIZE - block_offset;
                if (written > size - bytes) written = size - bytes;
                if (MAX_FILE_SIZE < file->size + written) break;

                memcpy(block->memory + block_offset, buffer + bytes, written);
                fd->position += written, block_offset += written, block->occupied =
                        block->occupied > block_offset ? block->occupied : block_offset;
                file->size = fd->position > file->size ? fd->position : file->size, bytes += written;
            }

            if (MAX_FILE_SIZE == file->size && size > bytes) {
                ufs_error_code = UFS_ERR_NO_MEM;
                return -1;
            }
            else return bytes;
        }
    }
}


ssize_t
ufs_read(int fd, char *buffer, size_t size)
{
    int error = 0;

    if (fd < 0 || fd >= file_descriptor_capacity) error = UFS_ERR_NO_FILE;
    else if (file_descriptors[fd] == NULL) error = UFS_ERR_NO_FILE;
    else error = UFS_ERR_NO_ERR;

    if (error != 0) {
        ufs_error_code = error;
        return -1;
    }

    else {
        struct filedesc *f_des = file_descriptors[fd];

        if (UFS_WRITE_ONLY & f_des->flags) {
            ufs_error_code = UFS_ERR_NO_PERMISSION;
            return -1;
        }

        else {
            if (f_des->position > f_des->file->size) f_des->position = f_des->file->size;
            Block *current_block = f_des->file->block_list;
            if (current_block == NULL) return 0;

            for (int i = 0; i < f_des->position / BLOCK_SIZE; i = i + 1, current_block = current_block->next)
                if (current_block == 0) return 0;

            size_t block_offset = f_des->position % BLOCK_SIZE, bytes_read = 0;

            while (bytes_read < size) {
                if (block_offset == BLOCK_SIZE) {
                    current_block = current_block->next, block_offset = 0;
                    if (!current_block) break;
                }

                if (current_block->occupied - block_offset == 0) break;
                size_t to_read = BLOCK_SIZE - block_offset;
                if (to_read > size - bytes_read) to_read = size - bytes_read;
                if (to_read > current_block->occupied - block_offset) to_read = current_block->occupied - block_offset;
                memcpy(buffer + bytes_read, current_block->memory + block_offset, to_read);
                f_des->position += to_read, bytes_read += to_read, block_offset += to_read;
            }

            return bytes_read;
        }
    }
}


int
ufs_close(int fd) {

    int error = 0;

    if (fd < 0 || fd >= file_descriptor_capacity) error = UFS_ERR_NO_FILE;
    else if (file_descriptors[fd] == NULL) error = UFS_ERR_NO_FILE;
    else error = UFS_ERR_NO_ERR;

    if (error) {
        ufs_error_code = error;
        return -1;
    }

    else {
        struct filedesc *f_des = file_descriptors[fd];
        struct file *f = f_des->file;
        (f->refs)--;

        if (f->obsolete != 0 && f->refs == 0) {

            Block *current_block = NULL;

            for (Block *b = f->block_list; b != NULL; b = b->next) {
                free(b->memory);
                if (b->prev) free(b->prev);
                current_block = b;
            }

            free(current_block);
            free((void *) f->name);
            if (f->next) f->next->prev = f->prev;
            if (f->prev) f->prev->next = f->next;
            if (file_list == f) file_list = f->next;

            free(f);
        }

        free(file_descriptors[fd]);
        file_descriptors[fd] = NULL;

        while (file_descriptor_capacity > 0 && !file_descriptors[file_descriptor_capacity - 1])
            free(file_descriptors[--file_descriptor_capacity]);

        file_descriptors = realloc(file_descriptors, sizeof(struct f_des *) * file_descriptor_capacity);

        return 0;
    }
}


int
ufs_delete(const char *filename)
{

    struct file *f = NULL, *i = file_list;

    while (i != NULL) {
        if (i->obsolete == 0 && strcmp(i->name, filename) == 0) {
            f = i;
            break;
        }
        i = i->next;
    }

    if (f == NULL){
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    else {
        if (f->refs != 0)
            f->obsolete = true;
        else {

            Block *current_block = NULL, *b = f->block_list;
            free((void *) f->name);

            while (b != NULL) {
                free(b->memory);
                if (b->prev) free(b->prev);
                current_block = b, b = b->next;
            }

            if (f->next) f->next->prev = f->prev;
            if (f->prev) f->prev->next = f->next;
            if (file_list == f) file_list = f->next;

            free(current_block);
            free(f);
        }

        return 0;
    }
}


int
ufs_resize(int fdes, size_t new_size) {

    if (file_descriptors[fdes] == NULL || file_descriptor_capacity <= fdes) {
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    else {
        if (new_size >= MAX_FILE_SIZE) {
            ufs_error_code = UFS_ERR_NO_MEM;
            return -1;
        }

        else {
            struct file *f = file_descriptors[fdes]->file;
            int number = 0;

            for (Block *block = f->block_list; block != NULL; block = block->next) number++;

            while (number * BLOCK_SIZE < new_size) {
                Block *new_block = (Block *) malloc(sizeof(Block));
                char *memory = (char *) malloc(sizeof(char) * BLOCK_SIZE);

                *new_block = (Block) {
                        .memory = memory, .prev = f->current_block, .next = NULL, .occupied = 0,
                };

                if (!f->block_list) f->block_list = new_block, f->current_block = new_block;
                else f->current_block->next = new_block, f->current_block = new_block;

                number++;
            }

            if (number != 0) {
                while (new_size < number * BLOCK_SIZE - BLOCK_SIZE) {
                    if (f->current_block->prev) {
                        Block *block = f->current_block->prev;
                        free(block->next->memory);
                        free(block->next);
                        block->next = NULL, f->current_block = block;
                    }
                    number--;
                }
            }

            f->size = new_size;
            if (f->current_block) f->current_block->occupied = new_size % BLOCK_SIZE;

            return 0;
        }
    }
}