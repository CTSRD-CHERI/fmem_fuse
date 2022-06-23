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

enum axi4_bs_flit_kind {
  AW = 0,
  W  = 1,
  B  = 2,
  AR = 3,
  A  = 4,
};

struct __attribute__((__packed__)) axi4_AW_flit_bs {
  uint8_t awuser;
  uint8_t awregion;
  uint8_t awqos;
  uint8_t awprot;
  uint8_t awcache;
  uint8_t awlock;
  uint8_t awburst;
  uint8_t awsize;
  uint8_t awlen;
  uint64_t awaddr;
  uint16_t awid;
};

#define AXI4_AW_FLIT_BS_DEFAULT {0,0,0,0,0,0,0,0,0,0,0}

struct __attribute__((__packed__)) axi4_W_flit_bs {
  uint8_t wuser;
  uint8_t wlast;
  uint8_t wstrb;
  uint64_t wdata;
};

#define AXI4_W_FLIT_BS_DEFAULT {0,1,0,0}

struct __attribute__((__packed__)) axi4_B_flit_bs {
  uint8_t buser;
  uint8_t bresp;
  uint16_t bid;
};

struct __attribute__((__packed__)) axi4_AR_flit_bs {
  uint8_t aruser;
  uint8_t arregion;
  uint8_t arqos;
  uint8_t arprot;
  uint8_t arcache;
  uint8_t arlock;
  uint8_t arburst;
  uint8_t arsize;
  uint8_t arlen;
  uint64_t araddr;
  uint16_t arid;
};

#define AXI4_AR_FLIT_BS_DEFAULT {0,0,0,0,0,0,0,0,0,0,0}

struct __attribute__((__packed__)) axi4_R_flit_bs {
  uint8_t ruser;
  uint8_t rlast;
  uint8_t rresp;
  uint64_t rdata;
  uint16_t rid;
};

struct __attribute__((__packed__)) axi4_flit_bs {
  uint8_t flit[19];
  uint8_t kind;
  uint8_t padding;
};
