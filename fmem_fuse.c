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
#include "axi4_bytestream.h"
#include "SocketPacketUtils/socket_packet_utils.c"
  
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

unsigned long long axi_sock;

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
        struct axi4_flit_bs flit;
        // only used in the read case.
        struct axi4_AR_flit_bs ar = AXI4_AR_FLIT_BS_DEFAULT;
        struct axi4_R_flit_bs r;
        // only used in the write case.
        struct axi4_AW_flit_bs aw = AXI4_AW_FLIT_BS_DEFAULT;
        struct axi4_W_flit_bs w = AXI4_W_FLIT_BS_DEFAULT;

        sc = &sc_global;

        req = (struct fmem_request *)data;
        if ((req->offset + req->access_width) > sc_global.mem_size)
                return (ERANGE);

        addr = /*dv_global.offset +*/ req->offset;
        
        uint8_t size = 0;
        switch(req->access_width) {
        case 1:
                size = 0;
                break;
        case 2:
                size = 1;
                break;
        case 4:
                size = 2;
                break;
        default:
                assert(0);
        }

        switch (cmd) {
        case FMEM_READ: ;
                ar.araddr = addr;
                ar.arsize = size;
                memcpy(&flit.flit, &ar, sizeof(ar) );
                flit.kind = AR;
                printf("flit kind: %x, ar.araddr: %lx, flit.flit[18]: %x flit.flit[17]: %x flit.flit[16]: %x sizeof(ar): %ld \n", flit.kind, ar.araddr, flit.flit[18], flit.flit[17], flit.flit[16], sizeof(ar));
                client_socket_putN(axi_sock, 20, &flit);
                flit.flit[20] = 0xff;
                while(flit.flit[20] == 0xff) client_socket_getN(&flit, axi_sock, 20);
                memcpy(&r, &flit.flit, sizeof(r) );
                req->data = r.rdata;
                for (int i = 0; i < 20; i++) printf("flit[%d]: %x ", i, flit.flit[i]);
                printf("\n received flit kind: %x \n", flit.kind);
                printf("read addr: %lx, size: %d, data: %lx\n", addr, req->access_width, r.rdata);
                //printf("read addr: %lx, size: %d\n", addr, req->access_width);
                break;
        case FMEM_WRITE: ;
                aw.awaddr = addr;
                aw.awsize = size;
                memcpy(&flit.flit, &aw, sizeof(aw) );
                flit.kind = AW;
                printf("flit kind: %x, aw.awaddr: %lx, sizeof(ar): %ld \n", flit.kind, aw.awaddr, sizeof(aw));
                client_socket_putN(axi_sock, 20, &flit);
                w.wdata = req->data;
                w.wstrb = ~(-1 << req->access_width);
                memcpy(&flit.flit, &w, sizeof(w) );
                flit.kind = W;
                printf("flit kind: %x, w.wdata: %lx sizeof(ar): %ld \n", flit.kind, w.wdata, sizeof(w));
                client_socket_putN(axi_sock, 20, &flit);
                // Get B response.
                flit.flit[20] = 0xff;
                while(flit.flit[20] == 0xff) client_socket_getN(&flit, axi_sock, 20);
                printf("received flit kind: %x \n", flit.kind);
        }

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
        axi_sock = client_socket_create("management_axi_port", 10001);
        client_socket_init(axi_sock);
        return fuse_main(argc, argv, &fmem_cdevsw, NULL);
}
