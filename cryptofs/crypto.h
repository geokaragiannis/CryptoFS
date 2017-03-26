/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)crypto.h	8.3 (Berkeley) 8/20/94
 *
 * $FreeBSD: releng/10.3/sys/fs/cryptofs/crypto.h 250505 2013-05-11 11:17:44Z kib $
 */

#ifndef	FS_CRYPTO_H
#define	FS_CRYPTO_H

#define	CRYPTOM_CACHE	0x0001

struct crypto_mount {
	struct mount	*cryptom_vfs;
	struct vnode	*cryptom_rootvp;	/* Reference to root crypto_node */
	uint64_t	cryptom_flags;
};

#ifdef _KERNEL
/*
 * A cache of vnode references
 */
struct crypto_node {
	LIST_ENTRY(crypto_node)	crypto_hash;	/* Hash list */
	struct vnode	        *crypto_lowervp;	/* VREFed once */
	struct vnode		*crypto_vnode;	/* Back pointer */
	u_int			crypto_flags;
};

#define	CRYPTOV_NOUNLOCK	0x0001
#define	CRYPTOV_DROP	0x0002

#define	MOUNTTOCRYPTOMOUNT(mp) ((struct crypto_mount *)((mp)->mnt_data))
#define	VTOCRYPTO(vp) ((struct crypto_node *)(vp)->v_data)
#define	CRYPTOTOV(xp) ((xp)->crypto_vnode)

int cryptofs_init(struct vfsconf *vfsp);
int cryptofs_uninit(struct vfsconf *vfsp);
int crypto_nodeget(struct mount *mp, struct vnode *target, struct vnode **vpp);
struct vnode *crypto_hashget(struct mount *mp, struct vnode *lowervp);
void crypto_hashrem(struct crypto_node *xp);
int crypto_bypass(struct vop_generic_args *ap);

#ifdef DIAGNOSTIC
struct vnode *crypto_checkvp(struct vnode *vp, char *fil, int lno);
#define	CRYPTOVPTOLOWERVP(vp) crypto_checkvp((vp), __FILE__, __LINE__)
#else
#define	CRYPTOVPTOLOWERVP(vp) (VTOCRYPTO(vp)->crypto_lowervp)
#endif

extern struct vop_vector crypto_vnodeops;

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_CRYPTOFSNODE);
#endif

#ifdef CRYPTOFS_DEBUG
#define CRYPTOFSDEBUG(format, args...) printf(format ,## args)
#else
#define CRYPTOFSDEBUG(format, args...)
#endif /* CRYPTOFS_DEBUG */

#endif /* _KERNEL */

#endif
