/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
 * Copyright (c) 2022 Jon Woodruff <Jonathan.Woodruff@cl.cam.ac.uk>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#define FUSE_USE_VERSION 35

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "ioctl.h"
  
#define FMEM_MAXDEVS 128
#define FMEM_NAME "fmem"

 enum {
         FMEM_NONE,
         FMEM_ROOT,
         FMEM_FILE,
 };

struct fmem_dev {
        struct cdev             *cdev;
        uint64_t                offset;
        uint64_t                length;
};

struct fmem_dev dv_global = { .offset = 0, .length = 4096 };

struct fmem_softc {
        struct resource            *res[1];
        int                        mem_size;
        int                        mem_start;
        struct fmem_dev            fmem[FMEM_MAXDEVS];
        int                        ndevs;
};

struct fmem_softc sc_global = { .mem_start = 0, .mem_size = 4096, .ndevs = 1};

static int fmem_file_type(const char *path)
{
 if (strcmp(path, "/") == 0)
         return FMEM_ROOT;
 if (strcmp(path, "/" FMEM_NAME) == 0)
         return FMEM_FILE;
 return FMEM_NONE;
}

static int
fmem_open(const char *path, struct fuse_file_info *fi)
{
        (void) fi;
        if (fmem_file_type(path) != FMEM_NONE)
                return(0);
        return -ENOENT;
}

static int
fmemioctl(const char *path, unsigned int cmd, void *arg,
          struct fuse_file_info *fi, unsigned int flags, void *data)
{
        struct fmem_request *req;
        struct fmem_softc *sc;
        uint64_t addr;
        int unit;

        sc = &sc_global;

        req = (struct fmem_request *)data;
        if ((req->offset + req->access_width) > sc_global.mem_size)
                return (ERANGE);

        addr = /*dv_global.offset +*/ req->offset;

        FILE *fptr;
        fptr = fopen("/tmp/fmem_fuse_debug.txt","a");

        switch (cmd) {
        case FMEM_READ:
                fprintf(fptr,"read addr: %lx, size: %d\n", addr, req->access_width);
                req->data = addr;
                break;
        case FMEM_WRITE:
                fprintf(fptr,"write addr: %lx, size: %d, data: %x\n",
                        addr, req->access_width, req->data);
        }

        fclose(fptr);

        return (0);
}

static int fmem_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
        (void) fi;
        (void) offset;

        if (fmem_file_type(path) != FMEM_ROOT)
                return -ENOENT;

        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);
        filler(buf, FMEM_NAME, NULL, 0);
  
        return (0);
}

static int fmem_getattr(const char *path, struct stat *stbuf,
                 struct fuse_file_info *fi)
{
        (void) fi;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        stbuf->st_atime = stbuf->st_mtime = time(NULL);

        switch (fmem_file_type(path)) {
                case FMEM_ROOT:
                        stbuf->st_mode = S_IFDIR | 0755;
                        stbuf->st_nlink = 2;
                        break;
                case FMEM_FILE:
                        stbuf->st_mode = S_IFREG | 0644;
                        stbuf->st_nlink = 1;
                        stbuf->st_size = 0;
                        break;
                case FMEM_NONE:
                        return -ENOENT;
        }

        return (0);
}

static struct fuse_operations fmem_cdevsw = {
//        .d_version =        D_VERSION,
//        .d_flags =        0,
        .open = fmem_open,
//        .read = NULL,
//        .write = NULL,
        .ioctl = fmemioctl,
//        .d_name =        "fmem",
        .getattr = fmem_getattr,
        .readdir = fmem_readdir,
//        .truncate = NULL,
};
  
int main(int argc, char *argv[])
{
        return fuse_main(argc, argv, &fmem_cdevsw, NULL);
}
