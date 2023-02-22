#include <hash.h>
#include "vm/page.h"

/* Returns a hash value for page p. */
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->virtual_addr, sizeof p->virtual_addr);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);
  return a->virtual_addr < b->virtual_addr;
}

void init_supplemental_table(struct hash *supplemental_table)
{   
    hash_init(supplemental_table, page_hash, page_less, NULL);
}

// supplemental page table elems -- done
// key physical address/kernel virtual address -- done
// pointer to swap or file on disk -- done
// on swap -- done
// zero page? -- done
// on disk -- done
// process_id or whatever thread it is -- done