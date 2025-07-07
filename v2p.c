#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */

#define OFFSET_MASK 0x1FF // 0x111111111
#define PGD_SHIFT 39
#define PUD_SHIFT 30
#define PMD_SHIFT 21
#define PTE_SHIFT 12
#define PFN_SHIFT 12
#define PG_OFFSET_MASK 0xFFF //0x111111111111
#define PTA 0x1B //for page table pte entries access, we want 0, 1, 3, 4 bit to be 1 i.e., 11011
#define PF_R 0x13   // physical frame only read access
#define PF_W 0x1B   // physical frame write access
#define PFN_MASK 0xFFFFFFFF // 32 1s
#define invalidate_tlb(addr) asm volatile("invlpg (%0)" :: "r" (addr) : "memory");


// checks if a page table is empty or not
// if empty returns 1 else 0 when page_table address is passed as argument
int is_page_table_empty(u64* page_table){
    for(int i = 0; i< 512; i++){
        if(page_table[i] & 0x1){
            return 0;
        }
    }
    return 1;
}

// to deallocate a physical frame if previously allocated with that addr
void deallocate_frame(struct exec_context *current, u64 addr){
    //pgd_level is the virtual address of the PGD level of the page table
    u64* pgd_level = (u64 *)osmap(current->pgd);

    //calculate all the offsets, indexes for each level of the table
    u64 pgd_offset = (addr >> PGD_SHIFT) & OFFSET_MASK;
    u64 pud_offset = (addr >> PUD_SHIFT) & OFFSET_MASK;
    u64 pmd_offset = (addr >> PMD_SHIFT) & OFFSET_MASK;
    u64 pte_offset = (addr >> PTE_SHIFT) & OFFSET_MASK;

    // check if the pud_level page table is present by checking pgd_level pte
    if((pgd_level[pgd_offset] & 0x1) == 0){
        // pud_level not exists
        return ;
    }
    u64 pud_level_frame_no = pgd_level[pgd_offset] >> PFN_SHIFT;
    u64* pud_level = (u64 *)osmap(pud_level_frame_no);

    // check if the pmd_level page table is present by checking pud_level pte
    if((pud_level[pud_offset] & 0x1) == 0){
        // pmd_level not exists
        return ;
    }
    u64 pmd_level_frame_no = pud_level[pud_offset] >> PFN_SHIFT;
    u64* pmd_level = (u64 *)osmap(pmd_level_frame_no);

    // check if the pte_level page table is present by checking pmd_level pte
    if((pmd_level[pmd_offset] & 0x1) == 0){
        // pte_level not exists
        return ;
    }
    u64 pte_level_frame_no = pmd_level[pmd_offset] >> PFN_SHIFT;
    u64* pte_level = (u64 *)osmap(pte_level_frame_no);

    // check if the physical_frame page table is present by checking pte_level pte
    if((pte_level[pte_offset] & 0x1) == 0){
        // physical frame not exists
        return ;
    }
    // extracting physical frame number from pte_level pte
    u64 pfn = pte_level[pte_offset] >> PFN_SHIFT;

    // decrementing reference count for that physical frame
    put_pfn(pfn);
    if(get_pfn_refcount(pfn)==0){
        os_pfn_free(USER_REG, pfn);
    }

    // making pte_level pte present bit as 0, as it cannot access that physical frame now
    pte_level[pte_offset] = 0;   

    // checking if pte_level page table has to be deleted or not

    if(!is_page_table_empty(pte_level))    return ;

    // if empty, that pte_level page table has to be freed
    put_pfn(pte_level_frame_no);
    if(get_pfn_refcount(pte_level_frame_no)==0){
        os_pfn_free(OS_PT_REG, pte_level_frame_no);
    }

    pmd_level[pmd_offset] = 0;

    // checking if pmd_level page table has to be deleted or not
    if(!is_page_table_empty(pmd_level))    return ;
    // if empty, that pmd_level page table has to be freed
    put_pfn(pmd_level_frame_no);
    if(get_pfn_refcount(pmd_level_frame_no)==0){
        os_pfn_free(OS_PT_REG, pmd_level_frame_no);
    }
    pud_level[pud_offset] = 0;

    // checking if pud_level page table has to be deleted or not
    if(!is_page_table_empty(pud_level))    return ;
    // if empty, that pud_level page table has to be freed
    put_pfn(pud_level_frame_no);
    if(get_pfn_refcount(pud_level_frame_no)==0){
        os_pfn_free(OS_PT_REG, pud_level_frame_no);
    }
    pgd_level[pgd_offset] = 0;

    return ;

}

// to modify access of a physical page frame if exists
void modify_access_frame(struct exec_context *current, u64 addr, int prot){
    //pgd_level is the virtual address of the PGD level of the page table
    u64* pgd_level = (u64 *)osmap(current->pgd);

    //calculate all the offsets, indexes for each level of the table
    u64 pgd_offset = (addr >> PGD_SHIFT) & OFFSET_MASK;
    u64 pud_offset = (addr >> PUD_SHIFT) & OFFSET_MASK;
    u64 pmd_offset = (addr >> PMD_SHIFT) & OFFSET_MASK;
    u64 pte_offset = (addr >> PTE_SHIFT) & OFFSET_MASK;

    // check if the pud_level page table is present by checking pgd_level pte
    if((pgd_level[pgd_offset] & 0x1) == 0){
        // pud_level not exists
        return ;
    }
    u64* pud_level = (u64 *)osmap(pgd_level[pgd_offset] >> PFN_SHIFT);

    // check if the pmd_level page table is present by checking pud_level pte
    if((pud_level[pud_offset] & 0x1) == 0){
        // pmd_level not exists
        return ;
    }
    u64* pmd_level = (u64 *)osmap(pud_level[pud_offset] >> PFN_SHIFT);

    // check if the pte_level page table is present by checking pmd_level pte
    if((pmd_level[pmd_offset] & 0x1) == 0){
        // pte_level not exists
        return ;
    }
    u64* pte_level = (u64 *)osmap(pmd_level[pmd_offset] >> PFN_SHIFT);

    // check if the physical_frame page table is present by checking pte_level pte
    if((pte_level[pte_offset] & 0x1) == 0){
        // physical frame not exists
        return ;
    }

    // physical page frame exists
    // modifying access
    
    //if write access to be put in entry, check for potential CoW fault
    u64 pfn = pte_level[pte_offset] >> PFN_SHIFT ;
    pte_level[pte_offset] = pfn << PFN_SHIFT;

    //if write access is there
    if(prot == (PROT_READ|PROT_WRITE)){
        //pfn is shared with other processes
        if(get_pfn_refcount(pfn) > 1){
            long success = handle_cow_fault(current, addr, prot);
            if(success != 1){
                // printk("cow_fault not resolved in mprotect \n");
                return;
            }
            
        }
        //pfn is only for this process, do normally
        else{
            pte_level[pte_offset] |= PF_W;  
        }
    }
    //only read access is there
    if(prot == PROT_READ){
        pte_level[pte_offset] |= PF_R; 
    }

    return ;

}

// returns pte_level pte table entry 
u64* get_pte(u64* pgd_level, u64 addr){
    //calculate all the offsets, indexes for each level of the table
    u64 pgd_offset = (addr >> PGD_SHIFT) & OFFSET_MASK;
    u64 pud_offset = (addr >> PUD_SHIFT) & OFFSET_MASK;
    u64 pmd_offset = (addr >> PMD_SHIFT) & OFFSET_MASK;
    u64 pte_offset = (addr >> PTE_SHIFT) & OFFSET_MASK;

    // check if the pud_level page table is present by checking pgd_level pte
    if((pgd_level[pgd_offset] & 0x1) == 0){
        // pud_level not exists
        return 0;
    }
    u64* pud_level = (u64 *)osmap(pgd_level[pgd_offset] >> PFN_SHIFT);

    // check if the pmd_level page table is present by checking pud_level pte
    if((pud_level[pud_offset] & 0x1) == 0){
        // pmd_level not exists
        return 0;
    }
    u64* pmd_level = (u64 *)osmap(pud_level[pud_offset] >> PFN_SHIFT);

    // check if the pte_level page table is present by checking pmd_level pte
    if((pmd_level[pmd_offset] & 0x1) == 0){
        // pte_level not exists
        return 0;
    }
    u64* pte_level = (u64 *)osmap(pmd_level[pmd_offset] >> PFN_SHIFT);

    // check if the physical_frame page table is present by checking pte_level pte
    if((pte_level[pte_offset] & 0x1) == 0){
        // physical frame not exists
        return 0;
    }

    // if physical frame is present, returns this pte_entry
    return &pte_level[pte_offset];
}

// create pagetables as needed and returns the final pte of pte_level page table
u64* allocate_pte(u64* pgd_level, u64 addr){
    //calculate all the offsets, indexes for each level of the table
    u64 pgd_offset = (addr >> PGD_SHIFT) & OFFSET_MASK;
    u64 pud_offset = (addr >> PUD_SHIFT) & OFFSET_MASK;
    u64 pmd_offset = (addr >> PMD_SHIFT) & OFFSET_MASK;
    u64 pte_offset = (addr >> PTE_SHIFT) & OFFSET_MASK;

    //check if the index of pgd is present by checking the 0th bit
    //if 1 -> present else create a page
    //if index shows no page present then create one
    if((pgd_level[pgd_offset] & 0x1) == 0){
        //assign a page at pud level
        u64 pud_pfn = os_pfn_alloc(OS_PT_REG); 
        if(!pud_pfn) return 0; //error in allocating page
        // fill the pgd entry at pgd_offset
        pgd_level[pgd_offset] = (pud_pfn << PFN_SHIFT) | PTA; 
    }

    u64* pud_level = (u64 *)osmap(pgd_level[pgd_offset] >> PFN_SHIFT);

    //check if the index of pud is present by checking the 0th bit
    //if 1 -> present else create a page
    //if index shows no page present then create one
    if((pud_level[pud_offset] & 0x1) == 0){
        //assign a page at pmd level
        u64 pmd_pfn = os_pfn_alloc(OS_PT_REG); 
        if(!pmd_pfn) return 0; //error in allocating page
        // fill the pgd entry at pgd_offset
        pud_level[pud_offset] = (pmd_pfn << PFN_SHIFT) | PTA; 
    }

    u64* pmd_level = (u64 *)osmap(pud_level[pud_offset] >> PFN_SHIFT);

    //check if the index of pud is present by checking the 0th bit
    //if 1 -> present else create a page
    //if index shows no page present then create one
    if((pmd_level[pmd_offset] & 0x1) == 0){
        //assign a page at pmd level
        u64 pte_pfn = os_pfn_alloc(OS_PT_REG); 
        if(!pte_pfn) return 0; //error in allocating page
        // fill the pgd entry at pgd_offset
        pmd_level[pmd_offset] = (pte_pfn << PFN_SHIFT) | PTA; 
    }

    u64* pte_level = (u64 *)osmap(pmd_level[pmd_offset] >> PFN_SHIFT);

    return &pte_level[pte_offset];
}


/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    // when tried to modify the portion of dummy node or if addr is not page-aligned
    if(addr < MMAP_AREA_START + 4096 || addr > MMAP_AREA_END || (addr-MMAP_AREA_START) % 4096 != 0){
        return -EINVAL;
    }
    if(length <= 0){
        return -EINVAL;
    }
    if(!(prot == PROT_READ || prot == (PROT_READ|PROT_WRITE))){
        return -EINVAL;
    }
    // aligning end_addr with page size, so range of unmapping area [addr, end_addr)
    if(length%4096 != 0){
        length = (length/4096 + 1)*4096;
    }
    u64 end_addr = addr + length;

    if(end_addr > MMAP_AREA_END){
        return -EINVAL;
    }

    // check if physical frames are alloted to them for each virtual page frame, if yes modify them accordingly, modify access if only frame exists
    for(u64 vm_addr = addr; vm_addr < end_addr; vm_addr += 4096){
        modify_access_frame(current, vm_addr, prot);
        invalidate_tlb(vm_addr);
    }

    // c_vm = current vm; p_vm = previous vm; n_vm = next vm
    struct vm_area* c_vm = current -> vm_area;
    struct vm_area* p_vm = NULL;
    struct vm_area* n_vm = c_vm -> vm_next;

    while(c_vm){
        // if the given request area is crossed
        if(c_vm -> vm_start >= end_addr){
            break;
        }
        // case - 1 : given is exactly a vma 
        else if(c_vm -> vm_start == addr &&  c_vm -> vm_end == end_addr){
            // merging on 2 sides (L and R)
            if(p_vm -> vm_end == addr && p_vm -> access_flags == prot && n_vm && n_vm -> vm_start == end_addr && n_vm -> access_flags == prot){
                p_vm -> vm_end = n_vm -> vm_end;
                p_vm -> vm_next = n_vm -> vm_next;
                os_free(c_vm, sizeof(struct vm_area));
                os_free(n_vm, sizeof(struct vm_area));
                stats->num_vm_area -= 2;
            }
            // merging on only L side
            else if(p_vm -> vm_end == addr && p_vm -> access_flags == prot){
                p_vm -> vm_end = end_addr;
                p_vm -> vm_next = n_vm ;
                os_free(c_vm, sizeof(struct vm_area));
                stats->num_vm_area--;
            }
            // merging on R side
            else if(n_vm && n_vm -> vm_start == end_addr && n_vm -> access_flags == prot){
                n_vm -> vm_start = addr;
                p_vm -> vm_next = n_vm ;
                os_free(c_vm, sizeof(struct vm_area));
                stats->num_vm_area--;
            }
            // if merging not possible
            else{
                c_vm -> access_flags = prot;
            }

            break;
        }
        // case - 2 : vma end addr matches with given request end_addr 
        else if(c_vm -> vm_start < addr &&  c_vm -> vm_end == end_addr){
            // if merging with n_vm is possible
            if(n_vm && n_vm -> vm_start == end_addr && n_vm -> access_flags == prot){
                c_vm -> vm_end = addr;
                n_vm -> vm_start = addr;
            }
            else{
                struct vm_area* new_vm = os_alloc(sizeof(struct vm_area));
                if(new_vm == 0)     return -EINVAL; // if os_alloc error
                new_vm -> vm_start = addr;
                new_vm -> vm_end = end_addr;
                new_vm -> access_flags = prot;
                new_vm -> vm_next = c_vm -> vm_next;
                c_vm -> vm_end = addr;
                c_vm -> vm_next = new_vm;

                stats->num_vm_area++;
            }
            break;
        }
        // case - 3 : vma start addr matches with given request addr 
        else if(c_vm -> vm_start == addr &&  c_vm -> vm_end > end_addr){
            // if merging with p_vm is possible
            if(p_vm && p_vm -> vm_end == addr && p_vm -> access_flags == prot){
                p_vm -> vm_end = end_addr;
                c_vm -> vm_start = end_addr;
            }
            else{
                struct vm_area* new_vm = os_alloc(sizeof(struct vm_area));
                if(new_vm == 0)     return -EINVAL; // if os_alloc error
                new_vm -> vm_start = addr;
                new_vm -> vm_end = end_addr;
                new_vm -> access_flags = prot;
                new_vm -> vm_next = c_vm;
                c_vm -> vm_start = end_addr;
                p_vm -> vm_next = new_vm;

                stats->num_vm_area++;
            }
            break;
        }
        // case - 4 : if given area is part of a existing vma (strictly inside, so no merging)
        else if(c_vm -> vm_start < addr &&  end_addr < c_vm -> vm_end){
            struct vm_area* new_vm_1 = os_alloc(sizeof(struct vm_area));
            if(new_vm_1 == 0)     return -EINVAL; // if os_alloc error
            new_vm_1 -> vm_start = addr;
            new_vm_1 -> vm_end = end_addr;
            new_vm_1 -> access_flags = prot;
            struct vm_area* new_vm_2 = os_alloc(sizeof(struct vm_area));
            if(new_vm_2 == 0)     return -EINVAL; // if os_alloc error
            new_vm_2 -> vm_start = end_addr;
            new_vm_2 -> vm_end = c_vm -> vm_end;
            new_vm_2 -> access_flags = c_vm -> access_flags;
            c_vm -> vm_end = addr;

            c_vm -> vm_next = new_vm_1;
            new_vm_1 -> vm_next = new_vm_2;
            new_vm_2 -> vm_next = n_vm;

            stats->num_vm_area += 2;
            
            break;
        }
        
        // multiple under one requested area : change vma's under that 
        // case - 5 : fig - 13.2
        else if(c_vm -> vm_start < addr && addr < c_vm -> vm_end && c_vm -> vm_end < end_addr){
            if(c_vm -> access_flags != prot){
                struct vm_area* new_vm = os_alloc(sizeof(struct vm_area));
                if(new_vm == 0)     return -EINVAL; // if os_alloc error
                new_vm -> vm_start = addr;
                new_vm -> vm_end = c_vm -> vm_end;
                new_vm -> access_flags = prot;
                new_vm -> vm_next = c_vm -> vm_next;
                c_vm -> vm_end = addr;
                c_vm -> vm_next = new_vm;
                stats->num_vm_area++;
                p_vm = new_vm;
                c_vm = p_vm -> vm_next;
                if(c_vm)    n_vm = c_vm -> vm_next;
                addr = new_vm -> vm_end;
            }
            else{
                addr = c_vm -> vm_end;
                p_vm = c_vm;
                c_vm = n_vm;
                if(c_vm)    n_vm = c_vm -> vm_next;
            }
        }
        // case - 6 : fig - 13.3
        else if(addr < c_vm -> vm_start && c_vm -> vm_start < end_addr &&  end_addr < c_vm -> vm_end){
            addr = c_vm -> vm_start;
        }
        // case - 7 : fig - 13.4
        else if(addr < c_vm -> vm_start && c_vm -> vm_end < end_addr){
            c_vm -> access_flags = prot;
            addr = c_vm -> vm_end;
            p_vm = c_vm;
            c_vm = n_vm;
            if(c_vm) n_vm = c_vm -> vm_next;
        }
        // case when vm starts with addr but ends before end_addr
        else if(addr == c_vm -> vm_start && c_vm ->vm_end < end_addr) {
            //case where merged with p_vm
            if(p_vm -> vm_end == addr && p_vm ->access_flags == prot){

                //update p_vm details
                p_vm -> vm_end = c_vm -> vm_end;
                p_vm -> vm_next = c_vm -> vm_next;

                //free c_vm
                os_free(c_vm, sizeof(struct vm_area));

                // update the pointers and addr
                addr = p_vm -> vm_end;
                //p_vm remains same
                c_vm = p_vm->vm_next;
                if(c_vm) n_vm = c_vm -> vm_next;

                //update counter
                stats ->num_vm_area --;

            }
            //case of no merging
            else{
                c_vm->access_flags = prot;

                //update addr and the pointers
                addr = c_vm->vm_end;
                p_vm = c_vm;
                c_vm = p_vm -> vm_next;
                if(c_vm) n_vm = c_vm -> vm_next;
            }
        }
        //addr is not yet reached in vma
        else{
            //update pointers
            p_vm = c_vm;
            c_vm = p_vm -> vm_next;
            if(c_vm) n_vm = c_vm -> vm_next;
        }

    }

    return 0;
}


/**
 * mmap system call implementation.
 */

long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{  
    //simple error handling for length and addr
    if(length < 0 || length > 2097152) return -EINVAL;
    if(addr && (addr < MMAP_AREA_START + 4096 || addr > MMAP_AREA_END)) return -EINVAL;
    if(!(prot == PROT_READ || prot == (PROT_READ|PROT_WRITE))){
        return -EINVAL;
    }
    if (!addr && flags == MAP_FIXED) return -EINVAL;

    //initialize the list of VMA if first call to mmap => create a dummy node as the head
    if(current -> vm_area == NULL){
        struct vm_area *dummy_vm = os_alloc(sizeof(struct vm_area));
        dummy_vm->vm_start = MMAP_AREA_START;
        dummy_vm->vm_end = MMAP_AREA_START + 4096;
        dummy_vm->access_flags = 0x0;
        dummy_vm->vm_next = NULL;
        current->vm_area = dummy_vm;

        //incrementing the counter i.e. making it 1
        stats->num_vm_area ++;
    }

    //c_vma = current vma, n_vma = next vma
    struct vm_area *c_vma = current->vm_area;
    struct vm_area *n_vma = c_vma->vm_next;

    //start address of the new vma
    unsigned long start_addr;

    //making length nearest multiple of 4KB i.e. 4096, if not
    if(length%4096 != 0){
        length = (length/4096 + 1)*4096;
    }

    //if addr is NULL
    if(!addr){

        int allocated = 0; //indicator for allocation
        
        while(!allocated){

            if(!n_vma){

                allocated = 1;
                start_addr = c_vma->vm_end;

                //vma is out of bounds
                if(start_addr + length > MMAP_AREA_END) return -EINVAL;

                //vma in bounds
                //if previous vma has same protection flag then merge
                if(c_vma->access_flags == prot){
                    c_vma->vm_end = start_addr + length;
                }
                //else create new vma
                else{
                    struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                    vm->vm_start = start_addr;
                    vm->vm_end = vm->vm_start + length;
                    vm->vm_next = NULL;
                    vm->access_flags = prot;

                    c_vma->vm_next = vm;
                    //incrementing the counter
                    stats->num_vm_area ++;

                }

            }
            //n_vma is not NULL
            else{

                //if we can have the vma in middle of 2 existing ones
                if((n_vma->vm_start - c_vma->vm_end) >= length){
                    
                    allocated = 1;
                    start_addr = c_vma->vm_end;

                    //when only case of merging with c_vma possible
                    if(n_vma->vm_start > start_addr + length){
                        //case where merged with c_vma
                        if(c_vma->access_flags == prot){
                            c_vma->vm_end = start_addr + length;
                        }
                        //case of no merging i.e. create new vma
                        else{
                            struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                            vm->vm_start = start_addr;
                            vm->vm_end = vm->vm_start + length;
                            vm->vm_next = c_vma->vm_next;
                            vm->access_flags = prot;

                            c_vma->vm_next = vm;
                            //incrementing the counter
                            stats->num_vm_area ++;
                        }

                    }

                    //n_vma->vm_start = start_addr + length
                    //can merge with c_vma, n_vma or both
                    else{
                        //case where before, current and after vma is merged
                        if(c_vma->access_flags == prot && n_vma->access_flags == prot){
                            c_vma->vm_next = n_vma->vm_next;
                            c_vma->vm_end = n_vma->vm_end;

                            //free the n_vma node
                            os_free(n_vma, sizeof(struct vm_area));
                            //decrement the counter
                            stats->num_vm_area--;
                        }
                        //case where merged with c_vma
                        else if(c_vma->access_flags == prot){
                            c_vma->vm_end = start_addr + length;
                        }
                        //case where merged with n_vma
                        else if(n_vma->access_flags == prot){
                            n_vma->vm_start = start_addr;
                        }
                        //case of no merging i.e. create new vma
                        else{
                            struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                            vm->vm_start = start_addr;
                            vm->vm_end = vm->vm_start + length;
                            vm->vm_next = c_vma->vm_next;
                            vm->access_flags = prot;

                            c_vma->vm_next = vm;
                            //incrementing the counter
                            stats->num_vm_area ++;
                        }
                    }
                 
                }
            }
            c_vma = n_vma;
            n_vma = c_vma->vm_next;
        }
    }
    //when addr is given 
    else{

        if((addr - MMAP_AREA_START)%4096 != 0) {
            // printk("addr is not page aligned \n"); 
            return -EINVAL;
        }
        int available = 0; //indicator if the addr is available
        
        while(c_vma->vm_end <= addr){
            //out of bounds vma requested
            if(addr + length > MMAP_AREA_END) return -EINVAL;

            //c_vma is the last vma, if it ends before addr then addr is available
            if(!n_vma ){
                available = 1;
                break;
            }

            //n_vma not NULL and addr and length can fit in the middle of c_vma and n_vma
            else if(n_vma->vm_start >= addr + length){
                available = 1;
                break;
            }
            c_vma = n_vma;
            n_vma = c_vma->vm_next;
        }

        if(flags == MAP_FIXED && available == 0) return -EINVAL;

        if(available){
            start_addr = addr;
            if(!n_vma){
                //case where merged with c_vma
                if(c_vma->vm_end == start_addr && c_vma->access_flags == prot){
                    c_vma->vm_end = start_addr + length;
                }
                else{
                    struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                    vm->vm_start = start_addr;
                    vm->vm_end = vm->vm_start + length;
                    vm->vm_next = NULL;
                    vm->access_flags = prot;

                    c_vma->vm_next = vm;
                    //incrementing the counter
                    stats->num_vm_area ++;
                }
            }
            //n_vma not null 
            //case where merged with both c_vma and n_vma
            else if(c_vma->vm_end == start_addr && c_vma->access_flags == prot && n_vma->vm_start == start_addr + length && n_vma->access_flags == prot){
                c_vma->vm_next = n_vma->vm_next;
                c_vma->vm_end = n_vma->vm_end;

                //free the n_vma node
                os_free(n_vma, sizeof(struct vm_area));
                //decrement the counter
                stats->num_vm_area--;
            }
            //case where merged with c_vma
            else if(c_vma->vm_end == start_addr && c_vma->access_flags == prot){
                c_vma->vm_end = start_addr + length;
            }
            //case where merged with n_vma
            else if(n_vma->vm_start == start_addr + length && n_vma->access_flags == prot){
                n_vma->vm_start = start_addr;
            }
            //case of no merging i.e. create new vma
            else{
                struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                vm->vm_start = start_addr;
                vm->vm_end = vm->vm_start + length;
                vm->vm_next = c_vma->vm_next;
                vm->access_flags = prot;

                c_vma->vm_next = vm;
                //incrementing the counter
                stats->num_vm_area ++;
            }

        }
        //when flag is 0 and addr is not available
        //same logic as when addr is null
        else{

            // re-initializing c_vma and n_vma for allocation
            c_vma = current->vm_area;
            n_vma = c_vma->vm_next;
            int allocated = 0; //indicator for allocation
            
            while(!allocated){

                if(!n_vma){

                    allocated = 1;
                    start_addr = c_vma->vm_end;

                    //vma is out of bounds
                    if(start_addr + length > MMAP_AREA_END) return -EINVAL;

                    //vma in bounds
                    //if previous vma has same protection flag then merge
                    if(c_vma->access_flags == prot){
                        c_vma->vm_end = start_addr + length;
                    }
                    //else create new vma
                    else{
                        struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                        vm->vm_start = start_addr;
                        vm->vm_end = vm->vm_start + length;
                        vm->vm_next = NULL;
                        vm->access_flags = prot;

                        c_vma->vm_next = vm;
                        //incrementing the counter
                        stats->num_vm_area ++;
                    }

                }
                //n_vma is not NULL
                else{

                    //if we can have the vma in middle of 2 existing ones
                    if((n_vma->vm_start - c_vma->vm_end) >= length){
                        
                        allocated = 1;
                        start_addr = c_vma->vm_end;

                        //when only case of merging with c_vma possible
                        if(n_vma->vm_start > start_addr + length){
                            //case where merged with c_vma
                            if(c_vma->access_flags == prot){
                                c_vma->vm_end = start_addr + length;
                            }
                            //case of no merging i.e. create new vma
                            else{
                                struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                                vm->vm_start = start_addr;
                                vm->vm_end = vm->vm_start + length;
                                vm->vm_next = c_vma->vm_next;
                                vm->access_flags = prot;

                                c_vma->vm_next = vm;
                                //incrementing the counter
                                stats->num_vm_area ++;
                            }

                        }

                        //n_vma->vm_start = start_addr + length
                        //can merge with c_vma, n_vma or both
                        else{
                            //case where before, current and after vma is merged
                            if(c_vma->access_flags == prot && n_vma->access_flags == prot){
                                c_vma->vm_next = n_vma->vm_next;
                                c_vma->vm_end = n_vma->vm_end;

                                //free the n_vma node
                                os_free(n_vma, sizeof(struct vm_area));
                                //decrement the counter
                                stats->num_vm_area--;
                            }
                            //case where merged with c_vma
                            else if(c_vma->access_flags == prot){
                                c_vma->vm_end = start_addr + length;
                            }
                            //case where merged with n_vma
                            else if(n_vma->access_flags == prot){
                                n_vma->vm_start = start_addr;
                            }
                            //case of no merging i.e. create new vma
                            else{
                                struct vm_area *vm = os_alloc(sizeof(struct vm_area));
                                vm->vm_start = start_addr;
                                vm->vm_end = vm->vm_start + length;
                                vm->vm_next = c_vma->vm_next;
                                vm->access_flags = prot;

                                c_vma->vm_next = vm;
                                //incrementing the counter
                                stats->num_vm_area ++;
                            }
                        }
                    
                    }
                }
                c_vma = n_vma;
                n_vma = c_vma->vm_next;
            }
        }
    }
    
    return start_addr;
}

/**
 * munmap system call implemenations
 */
/* cases to take care of:
- addr passed will be page aligned.
- length > 0 and need to be multiple of page size : But at start itself while finding end_addr find length as page multiple
- what if the addr, end_addr range doesnot belong to any vma (as long as they are in the range of MMAP_AREA_START and MMAP_AREA_END then no error)
- 4 cases: area is start of vma; end_addr is end of a vma; the specified deletion are might be in middle of some vma which requires splitting; deletion across multiple vma's can occur (those multiple vma's can have holes in b/w OR they can be only holes OR can have diff protections)
- return 0 if success; -1 o/w 
- error when tried to unmap the dummy node
- Decrement the counter stats->num vm area whenever you remove a VMA(in case -4, multiple decrements might happen at once). Note have to increment the counter in case 3. No change in cases-1, 2
- check if vma with that addr exist or not: if vma not present then error
- if present and physical is also alloted ; then remove from physical also
- if present but physical not alloted : not error 
*/
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    // when tried to unmap the portion of dummy node or if addr is not page-aligned
    if(!addr || addr < MMAP_AREA_START + 4096 || addr > MMAP_AREA_END || (addr-MMAP_AREA_START) % 4096 != 0){
        return -EINVAL;
    }
    if(length <= 0){
        return -EINVAL;
    }
    // aligning end_addr with page size, so range of unmapping area [addr, end_addr)
    if(length%4096 != 0){
        length = (length/4096 + 1)*4096;
    }
    u64 end_addr = addr + length;

    if(end_addr > MMAP_AREA_END){
        return -EINVAL;
    }

    // check if physical frames are alloted to them for each virtual page frame, if yes modify them accordingly
    for(u64 vm_addr = addr; vm_addr < end_addr; vm_addr += 4096){
        deallocate_frame(current, vm_addr);
        invalidate_tlb(vm_addr);
    }

    // modify returning statement with that signal SIG...smtg for the ones which access vm areas which are not allocated virtually.

    // c_vm = current vm; p_vm = previous vm; n_vm = next vm
    struct vm_area* c_vm = current -> vm_area;
    struct vm_area* p_vm = NULL;
    struct vm_area* n_vm;

    // to remove unmapped areas from vma's linked list
    while(c_vm){
        n_vm = c_vm -> vm_next;

        // if the given request area is crossed
        if(c_vm -> vm_start >= end_addr){
            break;
        }
        // case - 1 : given area is exactly of a vma
        else if(c_vm -> vm_start == addr &&  c_vm -> vm_end == end_addr){
            p_vm -> vm_next = n_vm;
            os_free(c_vm, sizeof(struct vm_area));
            stats->num_vm_area--;
            break;
        }
        // case - 2 : given area's addr matches with any vma start addr
        else if(c_vm -> vm_start == addr &&  c_vm -> vm_end > end_addr){
            c_vm -> vm_start = end_addr;
            break;
        }
        // case - 3 : given area's end_addr matches with any vma end addr
        else if(c_vm -> vm_start < addr &&  c_vm -> vm_end == end_addr){
            c_vm -> vm_end = addr;
            break;
        }
        // case - 4 : given area is in between a vma which requires a splitting
        else if(c_vm -> vm_start < addr &&  c_vm -> vm_end > end_addr){
            struct vm_area* new_vm = os_alloc(sizeof(struct vm_area));
            if(!new_vm)     return -EINVAL; // if os_alloc error
            new_vm -> vm_start = end_addr;
            new_vm -> vm_end = c_vm -> vm_end;
            new_vm -> access_flags = c_vm -> access_flags;
            new_vm -> vm_next = c_vm -> vm_next;
            c_vm -> vm_end = addr;
            c_vm -> vm_next = new_vm;

            stats->num_vm_area++;
            break;
        }
        // given area is spanned over multiple vma's
        // case - 5 :  fig - 13.2
        else if(c_vm -> vm_start < addr && addr < c_vm -> vm_end &&  c_vm -> vm_end < end_addr){
            unsigned long temp_vm_end_addr = c_vm -> vm_end;
            c_vm -> vm_end = addr;
            addr = temp_vm_end_addr;
            p_vm = c_vm;
            c_vm = n_vm;
        }
        // case - 6 :  fig - 13.3
        else if(addr < c_vm -> vm_start && c_vm -> vm_start < end_addr &&  end_addr < c_vm -> vm_end){
            c_vm -> vm_start = end_addr;
            break;
        }
        // case - 7 :  fig - 13.4
        else if(addr <= c_vm -> vm_start && c_vm -> vm_end <= end_addr){
            p_vm -> vm_next = n_vm;
            unsigned long temp_vm_end_addr = c_vm -> vm_end;
            os_free(c_vm, sizeof(struct vm_area));
            stats->num_vm_area--;
            addr = temp_vm_end_addr;
            c_vm = n_vm;
        }
        // go to next element 
        else{
            p_vm = c_vm;
            c_vm = n_vm;
        }
    }

    return 0;
}



/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */
long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    struct vm_area *c_vm = current->vm_area;
    int exists = 0;
    while(c_vm){
        //addr is in c_vm
        if(addr >= c_vm->vm_start && addr < c_vm->vm_end){
            exists = 1;
            break;
        }

        //go to next vm since addr not present in the current one
        c_vm = c_vm ->vm_next;
    }

    //if addr not part of any vma; invalid access
    if(!exists) return -1;

    //so addr belongs in c_vm 

    //case of write access to a read access vma; invalid access; when error code is 6
    if(c_vm->access_flags == PROT_READ && error_code == 0x6) return -1;

    //case of write access to a read access vma; invalid access; when error code is 7
    if(c_vm->access_flags == PROT_READ && error_code == 0x7) return -1;

    //case of cow fault
    if(error_code == 0x7){
        return handle_cow_fault(current, addr, c_vm->access_flags);
    }

    u32 access = c_vm->access_flags;

    //pgd_level is the virtual address of the PGD level of the page table
    u64* pgd_level = (u64 *)osmap(current->pgd);

    //calculate all the offsets, indexes for each level of the table
    u64 pgd_offset = (addr >> PGD_SHIFT) & OFFSET_MASK;
    u64 pud_offset = (addr >> PUD_SHIFT) & OFFSET_MASK;
    u64 pmd_offset = (addr >> PMD_SHIFT) & OFFSET_MASK;
    u64 pte_offset = (addr >> PTE_SHIFT) & OFFSET_MASK;

    //check if the index of pgd is present by checking the 0th bit
    //if 1 -> present else create a page
    //if index shows no page present then create one
    if((pgd_level[pgd_offset] & 0x1) == 0){
        //assign a page at pud level
        u64 pud_pfn = os_pfn_alloc(OS_PT_REG); 
        if(!pud_pfn) return -1; //error in allocating page
        // fill the pgd entry at pgd_offset
        pgd_level[pgd_offset] = (pud_pfn << PFN_SHIFT) | PTA; 
    }

    u64* pud_level = (u64 *)osmap(pgd_level[pgd_offset] >> PFN_SHIFT);

    //check if the index of pud is present by checking the 0th bit
    //if 1 -> present else create a page
    //if index shows no page present then create one
    if((pud_level[pud_offset] & 0x1) == 0){
        //assign a page at pmd level
        u64 pmd_pfn = os_pfn_alloc(OS_PT_REG); 
        if(!pmd_pfn) return -1; //error in allocating page
        // fill the pgd entry at pgd_offset
        pud_level[pud_offset] = (pmd_pfn << PFN_SHIFT) | PTA; 
    }

    u64* pmd_level = (u64 *)osmap(pud_level[pud_offset] >> PFN_SHIFT);

    //check if the index of pud is present by checking the 0th bit
    //if 1 -> present else create a page
    //if index shows no page present then create one
    if((pmd_level[pmd_offset] & 0x1) == 0){
        //assign a page at pmd level
        u64 pte_pfn = os_pfn_alloc(OS_PT_REG); 
        if(!pte_pfn) return -1; //error in allocating page
        // fill the pgd entry at pgd_offset
        pmd_level[pmd_offset] = (pte_pfn << PFN_SHIFT) | PTA; 
    }

    u64* pte_level = (u64 *)osmap(pmd_level[pmd_offset] >> PFN_SHIFT);


    //check if the index of pte is present by checking the 0th bit
    //if 1 -> present else create a page
    //if index shows no page present then create one
    if((pte_level[pte_offset] & 0x1) == 0){
        //assign a page for the vma
        u64 new_pfn = os_pfn_alloc(USER_REG); 
        if(!new_pfn) return -1; //error in allocating page
        // fill the pte entry at pte_offset
        pte_level[pte_offset] = (new_pfn << PFN_SHIFT); 

        //if write access if there
        if(access == (PROT_READ | PROT_WRITE)){
            pte_level[pte_offset] |= PF_W; 
        }
        //only read access is there
        else if(access == PROT_READ){
            pte_level[pte_offset] |= PF_R; 
        }
    }



    return 1;
}


/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */
long do_cfork(){
    u64 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();

    /* Do not modify above lines
    * 
    * */   
    /*--------------------- Your code [start]---------------*/

    // not assigning value : pid, os_stack_pfn, os_rsp,  

    // ppid of the child is assigned with pid of parent process
    new_ctx -> ppid = ctx -> pid;

    new_ctx -> type = ctx -> type;
    new_ctx -> used_mem = ctx -> used_mem;

    // copying of all memory segment ranges
    for (int i = 0; i < MAX_MM_SEGS; i++) {
        new_ctx->mms[i] = ctx->mms[i];
    }

    
    for(int i = 0; i < CNAME_MAX; i++){
        new_ctx->name[i] = ctx -> name[i];
    }

    new_ctx -> regs = ctx -> regs;

    new_ctx -> pending_signal_bitmap = ctx -> pending_signal_bitmap;

    for(int i = 0; i < MAX_SIGNALS; i++){
        new_ctx->sighandlers[i] = ctx -> sighandlers[i];
    }

    new_ctx -> ticks_to_sleep = ctx -> ticks_to_sleep;
    new_ctx -> alarm_config_time = ctx -> alarm_config_time;
    new_ctx -> ticks_to_alarm = ctx -> ticks_to_alarm;

    for(int i = 0; i < MAX_OPEN_FILES; i++){
        new_ctx->files[i] = ctx -> files[i];
    }

    new_ctx -> ctx_threads = ctx -> ctx_threads;


    //copying the entire page table and updating parent and child pte entries

    //creating the pgd level pg
    u64 c_pgd_pfn = os_pfn_alloc(OS_PT_REG);
    new_ctx->pgd = c_pgd_pfn;

    u64* p_pgd = (u64 *)osmap(ctx->pgd);
    u64* c_pgd = (u64 *)osmap(new_ctx->pgd);



    // copying physical memory pages
    // for each segment except stack
    for (int i = 0; i < MAX_MM_SEGS; i++) {
        if(i == MM_SEG_STACK){
            for(u64 mem_addr = ctx->mms[i].end - 4096; mem_addr >= ctx->mms[i].next_free; mem_addr -= 4096){
            // returns 64-bit pte_entry only if that physical frame is present
                u64* p_pte_entry = get_pte(p_pgd, mem_addr);
                if(p_pte_entry){
                    // printk("PTE ENTRY - %x\n", *p_pte_entry);
                    *p_pte_entry = *p_pte_entry & ~0x8; // making 3rd bit position to have 0(only read-access)
                    invalidate_tlb(mem_addr);
                    u64* c_pte_entry = allocate_pte(c_pgd, mem_addr);
                    // if page table created correctly, then till pte_level all table would have created correctly
                    if(c_pte_entry){
                        *c_pte_entry = *p_pte_entry;
                        u64 pfn = *p_pte_entry >> PFN_SHIFT;
                        get_pfn(pfn);
                    }
                }
            }

        }
        // for each page of a segment
        else{
            for(u64 mem_addr = ctx->mms[i].start; mem_addr < ctx->mms[i].next_free; mem_addr += 4096){
            // returns 64-bit pte_entry only if that physical frame is present
                u64* p_pte_entry = get_pte(p_pgd, mem_addr);
                if(p_pte_entry){
                    *p_pte_entry = *p_pte_entry & ~0x8; // making 3rd bit position to have 0(only read-access)
                    invalidate_tlb(mem_addr);
                    u64* c_pte_entry = allocate_pte(c_pgd, mem_addr);
                    // if page table created correctly, then till pte_level all table would have created correctly
                    if(c_pte_entry){
                        *c_pte_entry = *p_pte_entry;
                        u64 pfn = *p_pte_entry >> PFN_SHIFT;
                        get_pfn(pfn);
                    }
                }
            }
        }
    }


    //copying of physical vma pages
    //copy the vms for the child process
    //parent vma head
    struct vm_area *c_pvm = ctx->vm_area;
    if(c_pvm) c_pvm = c_pvm->vm_next;
    long vm_addr;
    int length;
    new_ctx->vm_area = NULL; // clearly initialize the vm_area of child to be NULL, since it can have garbage value

    while(c_pvm){
        length = c_pvm->vm_end - c_pvm->vm_start;
        // new_ctx vm area will be initialised in the function vm_area_map itself
        vm_addr = vm_area_map(new_ctx,c_pvm->vm_start,length,c_pvm->access_flags,MAP_FIXED);
        //creating copy of the vm_area failed
        if(vm_addr < 0) {
            // printk("copying vm area via vm_area_map failed \n");
            return -1;
        }

        for(u64 addr = vm_addr; addr < vm_addr+length; addr += 4096){
            // returns 64-bit pte_entry only if that physical frame is present
            u64* p_pte_entry = get_pte(p_pgd, addr);
            if(p_pte_entry){
                *p_pte_entry = *p_pte_entry & ~0x8; // making 3rd bit position to have 0(only read-access)
                invalidate_tlb(addr);
                u64* c_pte_entry = allocate_pte(c_pgd, addr);
                // if page table created correctly, then till pte_level all table would have created correctly
                if(c_pte_entry){
                    *c_pte_entry = *p_pte_entry;
                    u64 pfn = *p_pte_entry >> PFN_SHIFT;
                    get_pfn(pfn);
                }
            }
        }

        //go to next vma
        c_pvm =  c_pvm ->vm_next;
    }

    pid = new_ctx ->pid;

    /*--------------------- Your code [end] ----------------*/
    
     /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);

    return pid;
}


/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */
long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    //pgd_level is the virtual address of the PGD level of the page table
    u64* pgd_level = (u64 *)osmap(current->pgd);

    //calculate all the offsets, indexes for each level of the table
    u64 pgd_offset = (vaddr >> PGD_SHIFT) & OFFSET_MASK;
    u64 pud_offset = (vaddr >> PUD_SHIFT) & OFFSET_MASK;
    u64 pmd_offset = (vaddr >> PMD_SHIFT) & OFFSET_MASK;
    u64 pte_offset = (vaddr >> PTE_SHIFT) & OFFSET_MASK;

    // check if the pud_level page table is present by checking pgd_level pte
    if((pgd_level[pgd_offset] & 0x1) == 0){
        // pud_level not exists; thus error
        return -1;
    }
    u64* pud_level = (u64 *)osmap(pgd_level[pgd_offset] >> PFN_SHIFT);

    // check if the pmd_level page table is present by checking pud_level pte
    if((pud_level[pud_offset] & 0x1) == 0){
        // pmd_level not exists; thus error
        return -1;
    }
    u64* pmd_level = (u64 *)osmap(pud_level[pud_offset] >> PFN_SHIFT);

    // check if the pte_level page table is present by checking pmd_level pte
    if((pmd_level[pmd_offset] & 0x1) == 0){
        // pte_level not exists; thus error
        return -1;
    }
    u64* pte_level = (u64 *)osmap(pmd_level[pmd_offset] >> PFN_SHIFT);

    // check if the physical_frame page table is present by checking pte_level pte
    if((pte_level[pte_offset] & 0x1) == 0){
        // physical frame not exists; thus error
        return -1;
    }

    // physical page frame exists
    u64 old_pfn = pte_level[pte_offset] >> PFN_SHIFT ;

    //pfn is referenced by multiple processes
    if(get_pfn_refcount(old_pfn) > 1) {
        u64 new_pfn = os_pfn_alloc(USER_REG);
        if (!new_pfn) return -1; // if os alloc issue
        void* new_pfn_addr = (u64 *)osmap(new_pfn);
        void* old_pfn_addr = (u64 *)osmap(old_pfn);

        //copy data from old pfn to new pfn
        memcpy(new_pfn_addr,old_pfn_addr,4096);

        //update ref counts of both the pfns
        put_pfn(old_pfn);
        //no need for get_pfn of new_pfn since while os_pfn_alloc it is initialized to 1

        //update table
        pte_level[pte_offset] = new_pfn << PFN_SHIFT;
        //if write access is there
        if(access_flags == (PROT_READ|PROT_WRITE)){
            pte_level[pte_offset] |= PF_W;
        }
        //if read access is there
        else if(access_flags == PROT_READ){
            pte_level[pte_offset] |= PF_R;
        }

    }
    //only this process owns it
    //simply change the access to add write access
    else{
        if(access_flags == (PROT_READ | PROT_WRITE))
            pte_level[pte_offset] = (old_pfn << PFN_SHIFT) | PF_W;
    }
    invalidate_tlb(vaddr);

    return 1;
}


