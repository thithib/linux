/*
 * Copyright (C) 2017 Docker, Inc.
 * Copyright (C) 2017 Hewlett Packard Enterprise Development, L.P.
 * Copyright (C) 2016 Brown University. All rights reserved.
 *
 * Authors:
 *   Juerg Haefliger <juerg.haefliger@hpe.com>
 *   Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *   Tycho Andersen <tycho@docker.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/xpfo.h>

#include <asm/tlbflush.h>

DEFINE_STATIC_KEY_TRUE(xpfo_inited);
DEFINE_STATIC_KEY_FALSE(xpfo_do_tlb_flush);

static int __init noxpfo_param(char *str)
{
	static_branch_disable(&xpfo_inited);

	return 0;
}

static int __init xpfotlbflush_param(char *str)
{
	static_branch_enable(&xpfo_do_tlb_flush);

	return 0;
}

early_param("noxpfo", noxpfo_param);
early_param("xpfotlbflush", xpfotlbflush_param);

static void xpfo_cond_flush_kernel_tlb(struct page *page, int order)
{
	if (static_branch_unlikely(&xpfo_do_tlb_flush))
		xpfo_flush_kernel_tlb(page, order);
}


void __meminit xpfo_init_single_page(struct page *page)
{
	spin_lock_init(&page->xpfo_lock);
}

void xpfo_alloc_pages(struct page *page, int order, gfp_t gfp)
{
	int i, flush_tlb = 0;

	if (!static_branch_unlikely(&xpfo_inited))
		return;

	for (i = 0; i < (1 << order); i++)  {
#ifdef CONFIG_XPFO_DEBUG
		BUG_ON(PageXpfoUser(page + i));
		BUG_ON(PageXpfoUnmapped(page + i));
		BUG_ON(spin_is_locked(&(page + i)->xpfo_lock));
		BUG_ON(atomic_read(&(page + i)->xpfo_mapcount));
#endif

		if ((gfp & GFP_HIGHUSER) == GFP_HIGHUSER) {
			if (static_branch_unlikely(&xpfo_do_tlb_flush)) {
				/*
				 * Tag the page as a user page and flush the TLB if it
				 * was previously allocated to the kernel.
				 */
				if (!TestSetPageXpfoUser(page + i))
					flush_tlb = 1;
			} else {
				SetPageXpfoUser(page + i);
			}

		} else {
			/* Tag the page as a non-user (kernel) page */
			ClearPageXpfoUser(page + i);
		}
	}

	if (flush_tlb)
		xpfo_cond_flush_kernel_tlb(page, order);
}

void xpfo_free_pages(struct page *page, int order)
{
	int i;

	if (!static_branch_unlikely(&xpfo_inited))
		return;

	for (i = 0; i < (1 << order); i++) {
#ifdef CONFIG_XPFO_DEBUG
		BUG_ON(atomic_read(&(page + i)->xpfo_mapcount));
#endif

		/*
		 * Map the page back into the kernel if it was previously
		 * allocated to user space.
		 */
		if (TestClearPageXpfoUser(page + i)) {
			ClearPageXpfoUnmapped(page + i);
			set_kpte(page_address(page + i), page + i,
				 PAGE_KERNEL);
		}
	}
}

void xpfo_kmap(void *kaddr, struct page *page)
{
	if (!static_branch_unlikely(&xpfo_inited))
		return;

	if (!PageXpfoUser(page))
		return;

	spin_lock(&page->xpfo_lock);

	/*
	 * The page was previously allocated to user space, so map it back
	 * into the kernel. No TLB flush required.
	 */
	if ((atomic_inc_return(&page->xpfo_mapcount) == 1) &&
	    TestClearPageXpfoUnmapped(page))
		set_kpte(kaddr, page, PAGE_KERNEL);

	spin_unlock(&page->xpfo_lock);
}
EXPORT_SYMBOL(xpfo_kmap);

void xpfo_kunmap(void *kaddr, struct page *page)
{
	if (!static_branch_unlikely(&xpfo_inited))
		return;

	if (!PageXpfoUser(page))
		return;

	spin_lock(&page->xpfo_lock);

	/*
	 * The page is to be allocated back to user space, so unmap it from the
	 * kernel, flush the TLB and tag it as a user page.
	 */
	if (atomic_dec_return(&page->xpfo_mapcount) == 0) {
#ifdef CONFIG_XPFO_DEBUG
		BUG_ON(PageXpfoUnmapped(page));
#endif
		SetPageXpfoUnmapped(page);
		set_kpte(kaddr, page, __pgprot(0));
		xpfo_cond_flush_kernel_tlb(page, 0);
	}

	spin_unlock(&page->xpfo_lock);
}
EXPORT_SYMBOL(xpfo_kunmap);

bool xpfo_page_is_unmapped(struct page *page)
{
	return PageXpfoUnmapped(page);
}
EXPORT_SYMBOL(xpfo_page_is_unmapped);
