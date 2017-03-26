/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * John Heidemann of the UCLA Ficus project.
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
 *	@(#)crypto_vnops.c	8.6 (Berkeley) 5/27/95
 *
 * Ancestors:
 *	@(#)lofs_vnops.c	1.2 (Berkeley) 6/18/92
 *	...and...
 *	@(#)crypto_vnodeops.c 1.20 92/07/07 UCLA Ficus project
 *
 * $FreeBSD: releng/10.3/sys/fs/cryptofs/crypto_vnops.c 295970 2016-02-24 13:48:40Z kib $
 */

/*
 * Null Layer
 *
 * (See mount_cryptofs(8) for more information.)
 *
 * The crypto layer duplicates a portion of the filesystem
 * name space under a new name.  In this respect, it is
 * similar to the loopback filesystem.  It differs from
 * the loopback fs in two respects:  it is implemented using
 * a stackable layers techniques, and its "crypto-node"s stack above
 * all lower-layer vnodes, not just over directory vnodes.
 *
 * The crypto layer has two purposes.  First, it serves as a demonstration
 * of layering by proving a layer which does nothing.  (It actually
 * does everything the loopback filesystem does, which is slightly
 * more than nothing.)  Second, the crypto layer can serve as a prototype
 * layer.  Since it provides all necessary layer framework,
 * new filesystem layers can be created very easily be starting
 * with a crypto layer.
 *
 * The remainder of this man page examines the crypto layer as a basis
 * for constructing new layers.
 *
 *
 * INSTANTIATING NEW CRYPTO LAYERS
 *
 * New crypto layers are created with mount_cryptofs(8).
 * Mount_cryptofs(8) takes two arguments, the pathname
 * of the lower vfs (target-pn) and the pathname where the crypto
 * layer will appear in the namespace (alias-pn).  After
 * the crypto layer is put into place, the contents
 * of target-pn subtree will be aliased under alias-pn.
 *
 *
 * OPERATION OF A CRYPTO LAYER
 *
 * The crypto layer is the minimum filesystem layer,
 * simply bypassing all possible operations to the lower layer
 * for processing there.  The majority of its activity centers
 * on the bypass routine, through which nearly all vnode operations
 * pass.
 *
 * The bypass routine accepts arbitrary vnode operations for
 * handling by the lower layer.  It begins by examing vnode
 * operation arguments and replacing any crypto-nodes by their
 * lower-layer equivlants.  It then invokes the operation
 * on the lower layer.  Finally, it replaces the crypto-nodes
 * in the arguments and, if a vnode is return by the operation,
 * stacks a crypto-node on top of the returned vnode.
 *
 * Although bypass handles most operations, vop_getattr, vop_lock,
 * vop_unlock, vop_inactive, vop_reclaim, and vop_print are not
 * bypassed. Vop_getattr must change the fsid being returned.
 * Vop_lock and vop_unlock must handle any locking for the
 * current vnode as well as pass the lock request down.
 * Vop_inactive and vop_reclaim are not bypassed so that
 * they can handle freeing crypto-layer specific data. Vop_print
 * is not bypassed to avoid excessive debugging information.
 * Also, certain vnode operations change the locking state within
 * the operation (create, mknod, remove, link, rename, mkdir, rmdir,
 * and symlink). Ideally these operations should not change the
 * lock state, but should be changed to let the caller of the
 * function unlock them. Otherwise all intermediate vnode layers
 * (such as union, umapfs, etc) must catch these functions to do
 * the necessary locking at their layer.
 *
 *
 * INSTANTIATING VNODE STACKS
 *
 * Mounting associates the crypto layer with a lower layer,
 * effect stacking two VFSes.  Vnode stacks are instead
 * created on demand as files are accessed.
 *
 * The initial mount creates a single vnode stack for the
 * root of the new crypto layer.  All other vnode stacks
 * are created as a result of vnode operations on
 * this or other crypto vnode stacks.
 *
 * New vnode stacks come into existance as a result of
 * an operation which returns a vnode.
 * The bypass routine stacks a crypto-node above the new
 * vnode before returning it to the caller.
 *
 * For example, imagine mounting a crypto layer with
 * "mount_cryptofs /usr/include /dev/layer/crypto".
 * Changing directory to /dev/layer/crypto will assign
 * the root crypto-node (which was created when the crypto layer was mounted).
 * Now consider opening "sys".  A vop_lookup would be
 * done on the root crypto-node.  This operation would bypass through
 * to the lower layer which would return a vnode representing
 * the UFS "sys".  Null_bypass then builds a crypto-node
 * aliasing the UFS "sys" and returns this to the caller.
 * Later operations on the crypto-node "sys" will repeat this
 * process when constructing other vnode stacks.
 *
 *
 * CREATING OTHER FILE SYSTEM LAYERS
 *
 * One of the easiest ways to construct new filesystem layers is to make
 * a copy of the crypto layer, rename all files and variables, and
 * then begin modifing the copy.  Sed can be used to easily rename
 * all variables.
 *
 * The umap layer is an example of a layer descended from the
 * crypto layer.
 *
 *
 * INVOKING OPERATIONS ON LOWER LAYERS
 *
 * There are two techniques to invoke operations on a lower layer
 * when the operation cannot be completely bypassed.  Each method
 * is appropriate in different situations.  In both cases,
 * it is the responsibility of the aliasing layer to make
 * the operation arguments "correct" for the lower layer
 * by mapping a vnode arguments to the lower layer.
 *
 * The first approach is to call the aliasing layer's bypass routine.
 * This method is most suitable when you wish to invoke the operation
 * currently being handled on the lower layer.  It has the advantage
 * that the bypass routine already must do argument mapping.
 * An example of this is crypto_getattrs in the crypto layer.
 *
 * A second approach is to directly invoke vnode operations on
 * the lower layer with the VOP_OPERATIONNAME interface.
 * The advantage of this method is that it is easy to invoke
 * arbitrary operations on the lower layer.  The disadvantage
 * is that vnode arguments must be manualy mapped.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <fs/cryptofs/crypto.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vnode_pager.h>

/* TEAM WINNING */
#include <sys/my_rijndael.h>
#include <sys/stat.h>
#define KEYBITS 128

/* Malloc define */
MALLOC_DECLARE(MAL_BUFFS);
MALLOC_DEFINE(MAL_BUFFS, "buffer vector", "vectors of buffers");

extern struct userlist ul[16];
 
static int crypto_bug_bypass = 0;   /* for debugging: enables bypass printf'ing */
SYSCTL_INT(_debug, OID_AUTO, cryptofs_bug_bypass, CTLFLAG_RW, 
	&crypto_bug_bypass, 0, "");

/* TEAM WINNING */
static int decrypt(struct iovec *, struct uio *, int, int, int, int);
static int encrypt(struct iovec *, struct uio *, int, int, int, int);
/*
 * This is the 10-Apr-92 bypass routine.
 *    This version has been optimized for speed, throwing away some
 * safety checks.  It should still always work, but it's not as
 * robust to programmer errors.
 *
 * In general, we map all vnodes going down and unmap them on the way back.
 * As an exception to this, vnodes can be marked "unmapped" by setting
 * the Nth bit in operation's vdesc_flags.
 *
 * Also, some BSD vnode operations have the side effect of vrele'ing
 * their arguments.  With stacking, the reference counts are held
 * by the upper node, not the lower one, so we must handle these
 * side-effects here.  This is not of concern in Sun-derived systems
 * since there are no such side-effects.
 *
 * This makes the following assumptions:
 * - only one returned vpp
 * - no INOUT vpp's (Sun's vop_open has one of these)
 * - the vnode operation vector of the first vnode should be used
 *   to determine what implementation of the op should be invoked
 * - all mapped vnodes are of our vnode-type (NEEDSWORK:
 *   problems on rmdir'ing mount points and renaming?)
 */
int
crypto_bypass(struct vop_generic_args *ap)
{
	struct vnode **this_vp_p;
	int error;
	struct vnode *old_vps[VDESC_MAX_VPS];
	struct vnode **vps_p[VDESC_MAX_VPS];
	struct vnode ***vppp;
	struct vnodeop_desc *descp = ap->a_desc;
	int reles, i;

	if (crypto_bug_bypass)
		printf ("crypto_bypass: %s\n", descp->vdesc_name);

#ifdef DIAGNOSTIC
	/*
	 * We require at least one vp.
	 */
	if (descp->vdesc_vp_offsets == NULL ||
	    descp->vdesc_vp_offsets[0] == VDESC_NO_OFFSET)
		panic ("crypto_bypass: no vp's in map");
#endif

	/*
	 * Map the vnodes going in.
	 * Later, we'll invoke the operation based on
	 * the first mapped vnode's operation vector.
	 */
	reles = descp->vdesc_flags;
	for (i = 0; i < VDESC_MAX_VPS; reles >>= 1, i++) {
		if (descp->vdesc_vp_offsets[i] == VDESC_NO_OFFSET)
			break;   /* bail out at end of list */
		vps_p[i] = this_vp_p =
			VOPARG_OFFSETTO(struct vnode**,descp->vdesc_vp_offsets[i],ap);
		/*
		 * We're not guaranteed that any but the first vnode
		 * are of our type.  Check for and don't map any
		 * that aren't.  (We must always map first vp or vclean fails.)
		 */
		if (i && (*this_vp_p == NULLVP ||
		    (*this_vp_p)->v_op != &crypto_vnodeops)) {
			old_vps[i] = NULLVP;
		} else {
			old_vps[i] = *this_vp_p;
			*(vps_p[i]) = CRYPTOVPTOLOWERVP(*this_vp_p);
			/*
			 * XXX - Several operations have the side effect
			 * of vrele'ing their vp's.  We must account for
			 * that.  (This should go away in the future.)
			 */
			if (reles & VDESC_VP0_WILLRELE)
				VREF(*this_vp_p);
		}

	}

	/*
	 * Call the operation on the lower layer
	 * with the modified argument structure.
	 */
	if (vps_p[0] && *vps_p[0])
		error = VCALL(ap);
	else {
		printf("crypto_bypass: no map for %s\n", descp->vdesc_name);
		error = EINVAL;
	}

	/*
	 * Maintain the illusion of call-by-value
	 * by restoring vnodes in the argument structure
	 * to their original value.
	 */
	reles = descp->vdesc_flags;
	for (i = 0; i < VDESC_MAX_VPS; reles >>= 1, i++) {
		if (descp->vdesc_vp_offsets[i] == VDESC_NO_OFFSET)
			break;   /* bail out at end of list */
		if (old_vps[i]) {
			*(vps_p[i]) = old_vps[i];
#if 0
			if (reles & VDESC_VP0_WILLUNLOCK)
				VOP_UNLOCK(*(vps_p[i]), 0);
#endif
			if (reles & VDESC_VP0_WILLRELE)
				vrele(*(vps_p[i]));
		}
	}

	/*
	 * Map the possible out-going vpp
	 * (Assumes that the lower layer always returns
	 * a VREF'ed vpp unless it gets an error.)
	 */
	if (descp->vdesc_vpp_offset != VDESC_NO_OFFSET &&
	    !(descp->vdesc_flags & VDESC_NOMAP_VPP) &&
	    !error) {
		/*
		 * XXX - even though some ops have vpp returned vp's,
		 * several ops actually vrele this before returning.
		 * We must avoid these ops.
		 * (This should go away when these ops are regularized.)
		 */
		if (descp->vdesc_flags & VDESC_VPP_WILLRELE)
			goto out;
		vppp = VOPARG_OFFSETTO(struct vnode***,
				 descp->vdesc_vpp_offset,ap);
		if (*vppp)
			error = crypto_nodeget(old_vps[0]->v_mount, **vppp, *vppp);
	}

 out:
	return (error);
}

static int
crypto_add_writecount(struct vop_add_writecount_args *ap)
{
	struct vnode *lvp, *vp;
	int error;

	vp = ap->a_vp;
	lvp = CRYPTOVPTOLOWERVP(vp);
	KASSERT(vp->v_writecount + ap->a_inc >= 0, ("wrong writecount inc"));
	if (vp->v_writecount > 0 && vp->v_writecount + ap->a_inc == 0)
		error = VOP_ADD_WRITECOUNT(lvp, -1);
	else if (vp->v_writecount == 0 && vp->v_writecount + ap->a_inc > 0)
		error = VOP_ADD_WRITECOUNT(lvp, 1);
	else
		error = 0;
	if (error == 0)
		vp->v_writecount += ap->a_inc;
	return (error);
}

/*
 * We have to carry on the locking protocol on the crypto layer vnodes
 * as we progress through the tree. We also have to enforce read-only
 * if this layer is mounted read-only.
 */
static int
crypto_lookup(struct vop_lookup_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	int flags = cnp->cn_flags;
	struct vnode *vp, *ldvp, *lvp;
	struct mount *mp;
	int error;

	mp = dvp->v_mount;
	if ((flags & ISLASTCN) != 0 && (mp->mnt_flag & MNT_RDONLY) != 0 &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return (EROFS);
	/*
	 * Although it is possible to call crypto_bypass(), we'll do
	 * a direct call to reduce overhead
	 */
	ldvp = CRYPTOVPTOLOWERVP(dvp);
	vp = lvp = NULL;
	KASSERT((ldvp->v_vflag & VV_ROOT) == 0 ||
	    ((dvp->v_vflag & VV_ROOT) != 0 && (flags & ISDOTDOT) == 0),
	    ("ldvp %p fl %#x dvp %p fl %#x flags %#x", ldvp, ldvp->v_vflag,
	     dvp, dvp->v_vflag, flags));

	/*
	 * Hold ldvp.  The reference on it, owned by dvp, is lost in
	 * case of dvp reclamation, and we need ldvp to move our lock
	 * from ldvp to dvp.
	 */
	vhold(ldvp);

	error = VOP_LOOKUP(ldvp, &lvp, cnp);

	/*
	 * VOP_LOOKUP() on lower vnode may unlock ldvp, which allows
	 * dvp to be reclaimed due to shared v_vnlock.  Check for the
	 * doomed state and return error.
	 */
	if ((error == 0 || error == EJUSTRETURN) &&
	    (dvp->v_iflag & VI_DOOMED) != 0) {
		error = ENOENT;
		if (lvp != NULL)
			vput(lvp);

		/*
		 * If vgone() did reclaimed dvp before curthread
		 * relocked ldvp, the locks of dvp and ldpv are no
		 * longer shared.  In this case, relock of ldvp in
		 * lower fs VOP_LOOKUP() does not restore the locking
		 * state of dvp.  Compensate for this by unlocking
		 * ldvp and locking dvp, which is also correct if the
		 * locks are still shared.
		 */
		VOP_UNLOCK(ldvp, 0);
		vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
	}
	vdrop(ldvp);

	if (error == EJUSTRETURN && (flags & ISLASTCN) != 0 &&
	    (mp->mnt_flag & MNT_RDONLY) != 0 &&
	    (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME))
		error = EROFS;

	if ((error == 0 || error == EJUSTRETURN) && lvp != NULL) {
		if (ldvp == lvp) {
			*ap->a_vpp = dvp;
			VREF(dvp);
			vrele(lvp);
		} else {
			error = crypto_nodeget(mp, lvp, &vp);
			if (error == 0)
				*ap->a_vpp = vp;
		}
	}
	return (error);
}

static int
crypto_open(struct vop_open_args *ap)
{
	int retval;
	struct vnode *vp, *ldvp;

	vp = ap->a_vp;
	ldvp = CRYPTOVPTOLOWERVP(vp);
	retval = crypto_bypass(&ap->a_gen);
	if (retval == 0)
		vp->v_object = ldvp->v_object;
	return (retval);
}

/*
 * Setattr call. Disallow write attempts if the layer is mounted read-only.
 */
static int
crypto_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;

  	if ((vap->va_flags != VNOVAL || vap->va_uid != (uid_t)VNOVAL ||
	    vap->va_gid != (gid_t)VNOVAL || vap->va_atime.tv_sec != VNOVAL ||
	    vap->va_mtime.tv_sec != VNOVAL || vap->va_mode != (mode_t)VNOVAL) &&
	    (vp->v_mount->mnt_flag & MNT_RDONLY))
		return (EROFS);
	if (vap->va_size != VNOVAL) {
 		switch (vp->v_type) {
 		case VDIR:
 			return (EISDIR);
 		case VCHR:
 		case VBLK:
 		case VSOCK:
 		case VFIFO:
			if (vap->va_flags != VNOVAL)
				return (EOPNOTSUPP);
			return (0);
		case VREG:
		case VLNK:
 		default:
			/*
			 * Disallow write attempts if the filesystem is
			 * mounted read-only.
			 */
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
		}
	}

	return (crypto_bypass((struct vop_generic_args *)ap));
}

/*
 *  We handle getattr only to change the fsid.
 */
static int
crypto_getattr(struct vop_getattr_args *ap)
{
	int error;

	if ((error = crypto_bypass((struct vop_generic_args *)ap)) != 0)
		return (error);

	ap->a_vap->va_fsid = ap->a_vp->v_mount->mnt_stat.f_fsid.val[0];
	return (0);
}

/*
 * Handle to disallow write access if mounted read-only.
 */
static int
crypto_access(struct vop_access_args *ap)
{
	struct vnode *vp = ap->a_vp;
	accmode_t accmode = ap->a_accmode;

	/*
	 * Disallow write attempts on read-only layers;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the filesystem.
	 */
	if (accmode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
			break;
		default:
			break;
		}
	}
	return (crypto_bypass((struct vop_generic_args *)ap));
}

static int
crypto_accessx(struct vop_accessx_args *ap)
{
	struct vnode *vp = ap->a_vp;
	accmode_t accmode = ap->a_accmode;

	/*
	 * Disallow write attempts on read-only layers;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the filesystem.
	 */
	if (accmode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
			break;
		default:
			break;
		}
	}
	return (crypto_bypass((struct vop_generic_args *)ap));
}

/*
 * Increasing refcount of lower vnode is needed at least for the case
 * when lower FS is NFS to do sillyrename if the file is in use.
 * Unfortunately v_usecount is incremented in many places in
 * the kernel and, as such, there may be races that result in
 * the NFS client doing an extraneous silly rename, but that seems
 * preferable to not doing a silly rename when it is needed.
 */
static int
crypto_remove(struct vop_remove_args *ap)
{
	int retval, vreleit;
	struct vnode *lvp, *vp;

	vp = ap->a_vp;
	if (vrefcnt(vp) > 1) {
		lvp = CRYPTOVPTOLOWERVP(vp);
		VREF(lvp);
		vreleit = 1;
	} else
		vreleit = 0;
	VTOCRYPTO(vp)->crypto_flags |= CRYPTOV_DROP;
	retval = crypto_bypass(&ap->a_gen);
	if (vreleit != 0)
		vrele(lvp);
	return (retval);
}

/*
 * We handle this to eliminate crypto FS to lower FS
 * file moving. Don't know why we don't allow this,
 * possibly we should.
 */
static int
crypto_rename(struct vop_rename_args *ap)
{
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct vnode *tvp = ap->a_tvp;
	struct crypto_node *tnn;

	/* Check for cross-device rename. */
	if ((fvp->v_mount != tdvp->v_mount) ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		if (tvp)
			vput(tvp);
		vrele(fdvp);
		vrele(fvp);
		return (EXDEV);
	}

	if (tvp != NULL) {
		tnn = VTOCRYPTO(tvp);
		tnn->crypto_flags |= CRYPTOV_DROP;
	}
	return (crypto_bypass((struct vop_generic_args *)ap));
}

static int
crypto_rmdir(struct vop_rmdir_args *ap)
{

	VTOCRYPTO(ap->a_vp)->crypto_flags |= CRYPTOV_DROP;
	return (crypto_bypass(&ap->a_gen));
}

/*
 * We need to process our own vnode lock and then clear the
 * interlock flag as it applies only to our vnode, not the
 * vnodes below us on the stack.
 */
static int
crypto_lock(struct vop_lock1_args *ap)
{
	struct vnode *vp = ap->a_vp;
	int flags = ap->a_flags;
	struct crypto_node *nn;
	struct vnode *lvp;
	int error;


	if ((flags & LK_INTERLOCK) == 0) {
		VI_LOCK(vp);
		ap->a_flags = flags |= LK_INTERLOCK;
	}
	nn = VTOCRYPTO(vp);
	/*
	 * If we're still active we must ask the lower layer to
	 * lock as ffs has special lock considerations in it's
	 * vop lock.
	 */
	if (nn != NULL && (lvp = CRYPTOVPTOLOWERVP(vp)) != NULL) {
		VI_LOCK_FLAGS(lvp, MTX_DUPOK);
		VI_UNLOCK(vp);
		/*
		 * We have to hold the vnode here to solve a potential
		 * reclaim race.  If we're forcibly vgone'd while we
		 * still have refs, a thread could be sleeping inside
		 * the lowervp's vop_lock routine.  When we vgone we will
		 * drop our last ref to the lowervp, which would allow it
		 * to be reclaimed.  The lowervp could then be recycled,
		 * in which case it is not legal to be sleeping in it's VOP.
		 * We prevent it from being recycled by holding the vnode
		 * here.
		 */
		vholdl(lvp);
		error = VOP_LOCK(lvp, flags);

		/*
		 * We might have slept to get the lock and someone might have
		 * clean our vnode already, switching vnode lock from one in
		 * lowervp to v_lock in our own vnode structure.  Handle this
		 * case by reacquiring correct lock in requested mode.
		 */
		if (VTOCRYPTO(vp) == NULL && error == 0) {
			ap->a_flags &= ~(LK_TYPE_MASK | LK_INTERLOCK);
			switch (flags & LK_TYPE_MASK) {
			case LK_SHARED:
				ap->a_flags |= LK_SHARED;
				break;
			case LK_UPGRADE:
			case LK_EXCLUSIVE:
				ap->a_flags |= LK_EXCLUSIVE;
				break;
			default:
				panic("Unsupported lock request %d\n",
				    ap->a_flags);
			}
			VOP_UNLOCK(lvp, 0);
			error = vop_stdlock(ap);
		}
		vdrop(lvp);
	} else
		error = vop_stdlock(ap);

	return (error);
}

/*
 * We need to process our own vnode unlock and then clear the
 * interlock flag as it applies only to our vnode, not the
 * vnodes below us on the stack.
 */
static int
crypto_unlock(struct vop_unlock_args *ap)
{
	struct vnode *vp = ap->a_vp;
	int flags = ap->a_flags;
	int mtxlkflag = 0;
	struct crypto_node *nn;
	struct vnode *lvp;
	int error;

	if ((flags & LK_INTERLOCK) != 0)
		mtxlkflag = 1;
	else if (mtx_owned(VI_MTX(vp)) == 0) {
		VI_LOCK(vp);
		mtxlkflag = 2;
	}
	nn = VTOCRYPTO(vp);
	if (nn != NULL && (lvp = CRYPTOVPTOLOWERVP(vp)) != NULL) {
		VI_LOCK_FLAGS(lvp, MTX_DUPOK);
		flags |= LK_INTERLOCK;
		vholdl(lvp);
		VI_UNLOCK(vp);
		error = VOP_UNLOCK(lvp, flags);
		vdrop(lvp);
		if (mtxlkflag == 0)
			VI_LOCK(vp);
	} else {
		if (mtxlkflag == 2)
			VI_UNLOCK(vp);
		error = vop_stdunlock(ap);
	}

	return (error);
}

/*
 * Do not allow the VOP_INACTIVE to be passed to the lower layer,
 * since the reference count on the lower vnode is not related to
 * ours.
 */
static int
crypto_inactive(struct vop_inactive_args *ap __unused)
{
	struct vnode *vp, *lvp;
	struct crypto_node *xp;
	struct mount *mp;
	struct crypto_mount *xmp;

	vp = ap->a_vp;
	xp = VTOCRYPTO(vp);
	lvp = CRYPTOVPTOLOWERVP(vp);
	mp = vp->v_mount;
	xmp = MOUNTTOCRYPTOMOUNT(mp);
	if ((xmp->cryptom_flags & CRYPTOM_CACHE) == 0 ||
	    (xp->crypto_flags & CRYPTOV_DROP) != 0 ||
	    (lvp->v_vflag & VV_NOSYNC) != 0) {
		/*
		 * If this is the last reference and caching of the
		 * cryptofs vnodes is not enabled, or the lower vnode is
		 * deleted, then free up the vnode so as not to tie up
		 * the lower vnodes.
		 */
		vp->v_object = NULL;
		vrecycle(vp);
	}
	return (0);
}

/*
 * Now, the cryptofs vnode and, due to the sharing lock, the lower
 * vnode, are exclusively locked, and we shall destroy the crypto vnode.
 */
static int
crypto_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp;
	struct crypto_node *xp;
	struct vnode *lowervp;

	vp = ap->a_vp;
	xp = VTOCRYPTO(vp);
	lowervp = xp->crypto_lowervp;

	KASSERT(lowervp != NULL && vp->v_vnlock != &vp->v_lock,
	    ("Reclaiming incomplete crypto vnode %p", vp));

	crypto_hashrem(xp);
	/*
	 * Use the interlock to protect the clearing of v_data to
	 * prevent faults in crypto_lock().
	 */
	lockmgr(&vp->v_lock, LK_EXCLUSIVE, NULL);
	VI_LOCK(vp);
	vp->v_data = NULL;
	vp->v_object = NULL;
	vp->v_vnlock = &vp->v_lock;
	VI_UNLOCK(vp);

	/*
	 * If we were opened for write, we leased one write reference
	 * to the lower vnode.  If this is a reclamation due to the
	 * forced unmount, undo the reference now.
	 */
	if (vp->v_writecount > 0)
		VOP_ADD_WRITECOUNT(lowervp, -1);
	if ((xp->crypto_flags & CRYPTOV_NOUNLOCK) != 0)
		vunref(lowervp);
	else
		vput(lowervp);
	free(xp, M_CRYPTOFSNODE);

	return (0);
}

static int
crypto_print(struct vop_print_args *ap)
{
	struct vnode *vp = ap->a_vp;

	printf("\tvp=%p, lowervp=%p\n", vp, VTOCRYPTO(vp)->crypto_lowervp);
	return (0);
}

/* ARGSUSED */
static int
crypto_getwritemount(struct vop_getwritemount_args *ap)
{
	struct crypto_node *xp;
	struct vnode *lowervp;
	struct vnode *vp;

	vp = ap->a_vp;
	VI_LOCK(vp);
	xp = VTOCRYPTO(vp);
	if (xp && (lowervp = xp->crypto_lowervp)) {
		VI_LOCK_FLAGS(lowervp, MTX_DUPOK);
		VI_UNLOCK(vp);
		vholdl(lowervp);
		VI_UNLOCK(lowervp);
		VOP_GETWRITEMOUNT(lowervp, ap->a_mpp);
		vdrop(lowervp);
	} else {
		VI_UNLOCK(vp);
		*(ap->a_mpp) = NULL;
	}
	return (0);
}

static int
crypto_vptofh(struct vop_vptofh_args *ap)
{
	struct vnode *lvp;

	lvp = CRYPTOVPTOLOWERVP(ap->a_vp);
	return VOP_VPTOFH(lvp, ap->a_fhp);
}

static int
crypto_vptocnp(struct vop_vptocnp_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vnode **dvp = ap->a_vpp;
	struct vnode *lvp, *ldvp;
	struct ucred *cred = ap->a_cred;
	int error, locked;

	if (vp->v_type == VDIR)
		return (vop_stdvptocnp(ap));

	locked = VOP_ISLOCKED(vp);
	lvp = CRYPTOVPTOLOWERVP(vp);
	vhold(lvp);
	VOP_UNLOCK(vp, 0); /* vp is held by vn_vptocnp_locked that called us */
	ldvp = lvp;
	vref(lvp);
	error = vn_vptocnp(&ldvp, cred, ap->a_buf, ap->a_buflen);
	vdrop(lvp);
	if (error != 0) {
		vn_lock(vp, locked | LK_RETRY);
		return (ENOENT);
	}

	/*
	 * Exclusive lock is required by insmntque1 call in
	 * crypto_nodeget()
	 */
	error = vn_lock(ldvp, LK_EXCLUSIVE);
	if (error != 0) {
		vrele(ldvp);
		vn_lock(vp, locked | LK_RETRY);
		return (ENOENT);
	}
	vref(ldvp);
	error = crypto_nodeget(vp->v_mount, ldvp, dvp);
	if (error == 0) {
#ifdef DIAGNOSTIC
		CRYPTOVPTOLOWERVP(*dvp);
#endif
		VOP_UNLOCK(*dvp, 0); /* keep reference on *dvp */
	}
	vn_lock(vp, locked | LK_RETRY);
	return (error);
}

/* TEAM WINNING */
static int
crypto_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp; 
	struct uio *r_uio;
	struct ucred *uc; 
	uid_t uid;
	int error = 0;
	int decrypt_flag = 0;
	int k0, k1;
	int i;
	
	error =	crypto_bypass((struct vop_generic_args *) ap);
	
	vp = ap->a_vp;
	r_uio = ap->a_uio; 
	uc = ap->a_cred;	
	
	/* Grab file attributes */
	struct vattr vap;
	VOP_GETATTR(vp, &vap, uc);
	
	/* File owner ID */
	uid_t file_owner;
	file_owner = vap.va_uid;
	int fid;
	fid = vap.va_fileid;
	
	/* Grab file mode */
	/* If sticky bit is set, then encrypt what needs to be written and pass into bypass */
	/* Shouldn't happen though */
	mode_t mode;
	mode = vap.va_mode;

	/* Grab user ID and get respective keys*/
	uid = uc->cr_uid;
	for (i = 0; i < 16; i ++) 
	{
		/* Only decrypt if uid exists AND keys are not 0 */
		if ((ul[i].uid == uid) && (ul[i].k0 != 0) && (ul[i].k1 != 0) && ((mode & S_ISVTX) == S_ISVTX))
		{
			k0 = ul[i].k0;
			k1 = ul[i].k1;
			decrypt_flag = 1;
			break;
		}
	}
	/* Didn't modify buffers for read since we could not get it to work */
	decrypt_flag = 0;
	/* If flag isn't set, simply read w/o decrypting and return */
	if (!decrypt_flag){
		/* printf("READ: No decryption because no key for user OR sticky bit is 0.\n"); */
		return (error);
	}
	
	/* Decrypt here */
	struct iovec *bufs;
	int buf_count;
	
	/* printf("User has existing key. Decrypting data...\n"); */
	
	bufs = r_uio->uio_iov;
	buf_count = r_uio->uio_iovcnt;
	
	/* printf("READ: Number of buffers in Scatter/Gather list: %d\n", buf_count);
	printf("READ: Number of bytes remaining to be written: %zd\n", r_uio->uio_resid);
	 */
	/* LOCK VP */
	vn_lock(vp, LK_EXCLUSIVE);
	for (i = 0; i < buf_count; i ++)
	{
		/* printf("READ: Buffer length: %zu\n", bufs[i].iov_len); */
		decrypt(bufs, r_uio, fid, i, k0, k1);
	}
	
	/* UNLOCK VP */
	VOP_UNLOCK(vp, 0);
	return (error);
}

/*
 * Write data to a file or directory.
 * TEAM WINNING 
 */
static int
crypto_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp; 
	struct uio *w_uio;
	struct ucred *uc; 
	uid_t uid;
	int error = 0;
	int encrypt_flag = 0;
	int k0, k1;
	int i;
	
	vp = ap->a_vp;
	w_uio = ap->a_uio; 
	uc = ap->a_cred;
	
	/* Grab file attributes */
	struct vattr vap;
	VOP_GETATTR(vp, &vap, uc);
	
	/* File owner ID */
	uid_t file_owner;
	file_owner = vap.va_uid;
	int fid;
	fid = vap.va_fileid;
	
	/* Grab file mode */
	/* If sticky bit is set, then encrypt what needs to be written and pass into bypass */
	/* Shouldn't happen though */
	mode_t mode;
	mode = vap.va_mode;

	/* Grab user ID and get respective keys*/
	uid = uc->cr_uid;
	for (i = 0; i < 16; i ++) 
	{
		/* Only encrypt if uid exists AND keys are not 0 && sticky bit is on */
		if ((ul[i].uid == uid) && (ul[i].k0 != 0) && (ul[i].k1 != 0) && ((mode & S_ISVTX) == S_ISVTX))
		{
			k0 = ul[i].k0;
			k1 = ul[i].k1;
			encrypt_flag = 1;
			break;
		}
	}
		
	/* If flag isn't set, simply write w/o encrypting and return */
	if (!encrypt_flag){
		/* printf("WRITE: No encryption because no key for user OR sticky bit is 0.\n"); */
		error =	crypto_bypass((struct vop_generic_args *) ap);
		return (error);
	}
	
	/* Encrypt here */
	struct iovec *bufs;
	
	/* char **buffs; */
	/* Malloc a string array to store the data in the iovec buffers */
	/* buffs = malloc(sizeof(char *)*buf_count, MAL_BUFFS, M_ZERO); */
	
	int buf_count;
	
	/* printf("User has existing key. Encrypting data...\n"); */
	
	buf_count = w_uio->uio_iovcnt;
	bufs= w_uio->uio_iov;
	
	/* printf("Number of buffers in Scatter/Gather list: %d\n", buf_count);
	printf("Number of bytes remaining to be written: %zd\n", w_uio->uio_resid); */
	for (i = 0; i < buf_count; i ++)
	{
		/* printf("Buffer length: %zu\n", bufs[i].iov_len); */
		/* printf("Copied buffer length: %lu\n", sizeof(buffs[i])); */
		
		/* bufs is iovec */		
		encrypt(bufs, ap->a_uio, fid, i, k0, k1);
		
		/* printf("WRITE: finished bufs: %s\n", bufs[i].iov_base); */
		/* int rv = uiomove(bufs[i].iov_base, bufs[i].iov_len, ap->a_uio);
		if (rv != 0)
			return (rv); */
		/* printf("uiomove succes? %d\n", rv); */
	}

	error =	crypto_bypass((struct vop_generic_args *) ap);
	/* printf("ERROR?: %d\n", error); */
	return (error);
}

/* TEAM WINNING */
/* Simply calls encrypt since they do the same */
/* struct iovec bufs */
static int decrypt (struct iovec *bufs, struct uio *m_uio, int fid, int buf_num, int k0, int k1) {
	return encrypt(bufs, m_uio, fid, buf_num, k0, k1);
}

/* TEAM WINNING */
/* Encrypts the passed on buffer */
/* struct iovec bufs */
static int encrypt (struct iovec *bufs, struct uio *m_uio, int fid, int buf_num, int k0, int k1) {
	unsigned long rk[RKLENGTH(KEYBITS)];	/* round key */
	unsigned char key[KEYLENGTH(KEYBITS)];  /* cipher key */

	int i, ctr;
	int nrounds; /* # of Rijndael rounds */
	int totalbytes;
	size_t bytes_remaining = bufs[buf_num].iov_len;

	unsigned char filedata[16];
	unsigned char ciphertext[16];
	unsigned char ctrvalue[16];

	bzero(key, sizeof(key));
	bcopy (&k0, &(key[0]), sizeof (k0));
	bcopy (&k1, &(key[sizeof(k0)]), sizeof (k1));

	bzero(key, sizeof(key));
	bcopy (&k0, &(key[0]), sizeof (k0));
	bcopy (&k1, &(key[sizeof(k0)]), sizeof (k1));
	
	/* Initialize the Rijndael algorithm.*/
	nrounds = rijndaelSetupEncrypt(rk, key, 128);
	
	/* Copy entire buffer into a temp buffer */
	char tempbuf[bufs[buf_num].iov_len];
	char *bufpnt = bufs[buf_num].iov_base;
	
	/* printf("Copied realbuffer: %s\n=============\n", bufpnt); */
	bzero(tempbuf, sizeof(tempbuf));
	bcopy (&(bufpnt[0]), &(tempbuf[0]), bufs[buf_num].iov_len);
	/* printf("Current realbuffer: %s\n============\n", bufs[buf_num].iov_base);
	printf("Current tempbuffer: %s\n============\n", tempbuf);
	printf("Test line.\n"); */
	
	/* fileID goes into bytes 8-11 of the ctrvalue */
	bcopy (&fid, &(ctrvalue[8]), sizeof (fid));
	int pnt_offset = 0;
	int to_copy = 0;
	for (ctr = 0, totalbytes = 0; to_copy <= 0 ; ctr++, bytes_remaining -= to_copy, pnt_offset += to_copy)
	{
		/* Encrypt 16 bytes at a time unless less than 16 bytes left */
		if (bytes_remaining < 16) 
			to_copy = bytes_remaining;
		else
			to_copy = 16;
		
		/* printf("Bytes remaining: %d\n", to_copy); */
		
		/* Read 16 bytes (128 bits, the blocksize) from the data buffer */
		bcopy (&(tempbuf[pnt_offset]), &(filedata[0]), to_copy);	

		/* Set up the CTR value to be encrypted */
		bcopy (&ctr, &(ctrvalue[0]), sizeof (ctr));

		/* Call the encryption routine to encrypt the CTR value */
		my_rijndaelEncrypt(rk, nrounds, ctrvalue, ciphertext);

		/* XOR the result into the file data */
		/* printf("ENCRYPTING/DECRYPTING DATA...\n"); */
		for (i = 0; i < to_copy; i++) {
			filedata[i] ^= ciphertext[i];
		}		
		/* printf("Encrypted data: %s\n", filedata); */
		
		/* Copy encrypted data back into buffer */
		/* printf("Pointer offset: %d", pnt_offset); */
		bcopy (&(filedata[0]), &(tempbuf[pnt_offset]), to_copy);
		/* printf("tempbuf: %s\n", tempbuf); */
		
		/* Increment the total bytes written */
		totalbytes += to_copy;
	}
	bcopy(&(tempbuf[0]), bufs[buf_num].iov_base, bufs[buf_num].iov_len);
	/* printf("Finsihed bufpnt: %s\n", bufs[buf_num].iov_base); */
	/* move encrypted/decrypted buffer back into uio */
	/* uiomove(bufpnt, sizeof(tempbuf), m_uio); */
	/* printf("Total bytes written: %d\n", totalbytes); */
		
	return 1;
}

/*
 * Global vfs data structures
 */
struct vop_vector crypto_vnodeops = {
	.vop_bypass =		crypto_bypass,
	.vop_access =		crypto_access,
	.vop_accessx =		crypto_accessx,
	.vop_advlockpurge =	vop_stdadvlockpurge,
	.vop_bmap =		VOP_EOPNOTSUPP,
	.vop_getattr =		crypto_getattr,
	.vop_getwritemount =	crypto_getwritemount,
	.vop_inactive =		crypto_inactive,
	.vop_islocked =		vop_stdislocked,
	.vop_lock1 =		crypto_lock,
	.vop_lookup =		crypto_lookup,
	.vop_open =		crypto_open,
	.vop_print =		crypto_print,
	.vop_reclaim =		crypto_reclaim,
	.vop_remove =		crypto_remove,
	.vop_rename =		crypto_rename,
	.vop_rmdir =		crypto_rmdir,
	.vop_setattr =		crypto_setattr,
	.vop_strategy =		VOP_EOPNOTSUPP,
	.vop_unlock =		crypto_unlock,
	.vop_vptocnp =		crypto_vptocnp,
	.vop_vptofh =		crypto_vptofh,
	.vop_add_writecount =	crypto_add_writecount,
	
	/* TEAM WINNING */
	.vop_read =			crypto_read,
	.vop_write =		crypto_write,
};