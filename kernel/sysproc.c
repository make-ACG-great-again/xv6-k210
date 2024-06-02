
#include "include/types.h"
#include "include/riscv.h"
#include "include/param.h"
#include "include/memlayout.h"
#include "include/spinlock.h"
#include "include/proc.h"
#include "include/syscall.h"
#include "include/timer.h"
#include "include/kalloc.h"
#include "include/string.h"
#include "include/printf.h"
#include "include/vm.h"

extern int exec(char *path, char **argv);
extern int execve(char *path, char **argv, char** envp);

uint64
sys_exec(void)
{
  char path[FAT32_MAX_PATH], *argv[MAXARG];
  int i;
  uint64 uargv, uarg;

  if(argstr(0, path, FAT32_MAX_PATH) < 0 || argaddr(1, &uargv) < 0){
    return -1;
  }
  memset(argv, 0, sizeof(argv));
  for(i=0;; i++){
    if(i >= NELEM(argv)){
      goto bad;
    }
    if(fetchaddr(uargv+sizeof(uint64)*i, (uint64*)&uarg) < 0){
      goto bad;
    }
    if(uarg == 0){
      argv[i] = 0;
      break;
    }
    argv[i] = kalloc();
    if(argv[i] == 0)
      goto bad;
    if(fetchstr(uarg, argv[i], PGSIZE) < 0)
      goto bad;
  }

  int ret = exec(path, argv);

  for(i = 0; i < NELEM(argv) && argv[i] != 0; i++)
    kfree(argv[i]);

  return ret;

 bad:
  for(i = 0; i < NELEM(argv) && argv[i] != 0; i++)
    kfree(argv[i]);
  return -1;
}

uint64
sys_exit(void)
{
  int n;
  if(argint(0, &n) < 0)
    return -1;
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64 sys_getppid(void){
  struct proc* p = myproc();
  if(p->parent == NULL){
    printf("root\n");
    return -1;
  }
  return p->parent->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64 sys_clone(void){
  int flags, ptid, ctid;
  uint64 stack, tls;

  if(argint(0, &flags) < 0 || argaddr(1, &stack) < 0
      || argint(2, &ptid) < 0 || argaddr(3, &tls) < 0
        || argint(4, &ctid) < 0){
    printf("wrong input\n");
    return -1;
  }

return clone(flags, stack, ptid, tls, ctid);
}

uint64
sys_wait(void)
{
  uint64 p;
  if(argaddr(0, &p) < 0)
    return -1;
  return wait(p);
}

uint64 sys_wait4(void)
{
  int pid;
  uint64 p;
  int options;
  if(argint(0, &pid) < 0 || argaddr(1, &p) < 0 || argint(2, &options) < 0){
    printf("wrong input\n");
    return -1;
  }

  return wait4(pid, p, options);
}

uint64
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_trace(void)
{
  int mask;
  if(argint(0, &mask) < 0) {
    return -1;
  }
  myproc()->tmask = mask;
  return 0;
}

uint64 sys_sched_yield(void){
  yield();
  return 0;
}

uint64 sys_execve(void){
  char path[FAT32_MAX_PATH], *argv[MAXARG], *envp[MAXARG];
  int i;
  uint64 uargv, uarg, uenvp;

  if(argstr(0, path, FAT32_MAX_FILENAME) < 0 || argaddr(1, &uargv) < 0 || argaddr(2, &uenvp) < 0){
    return -1;
  }

  memset(argv, 0, sizeof(argv));
  for(i=0;; i++){
    if(i >= NELEM(argv)){
      goto bad;
    }
    if(fetchaddr(uargv+sizeof(uint64)*i, (uint64*)&uarg) < 0){
      goto bad;
    }
    if(uarg == 0){
      argv[i] = 0;
      break;
    }
    argv[i] = kalloc();
    if(argv[i] == 0)
      goto bad;
    if(fetchstr(uarg, argv[i], PGSIZE) < 0)
      goto bad;
  }

  memset(envp, 0, sizeof(envp));
  for(i=0;; i++){
    if(i >= NELEM(envp)){
      goto bad;
    }
    if(fetchaddr(uenvp+sizeof(uint64)*i, (uint64*)&uenvp) < 0){
      goto bad;
    }
    if(uenvp == 0){
      envp[i] = 0;
      break;
    }
    envp[i] = kalloc();
    if(envp[i] == 0)
      goto bad;
    if(fetchstr(uenvp, envp[i], PGSIZE) < 0)
      goto bad;
  }

  int ret = execve(path, argv, envp);

  for(i = 0; i < NELEM(argv) && argv[i] != 0; i++)
    kfree(argv[i]);

  return ret;

 bad:
  for(i = 0; i < NELEM(argv) && argv[i] != 0; i++)
    kfree(argv[i]);
  return -1;
}

uint64 sys_brk(void){
  uint64 addr;
  if(argaddr(0, &addr) < 0)
    return -1;
  return brk(addr);
}

uint64 sys_munmap(void){
  uint64 addr;
  int len;

  if(argaddr(0, &addr) < 0 || argint(1, &len) < 0){
    return -1;
  }

  struct proc* p = myproc();
  vmunmap(p->pagetable, addr, (len/PGSIZE), 0);
  return 0;
}

uint64 sys_mmap(void){
  uint64 addr;
  int len, prot, flags, fd, off;

  if(argaddr(0, &addr) < 0 || argint(1, &len) < 0 || argint(2, &prot) < 0
      || argint(3, &flags) < 0 || argint(4, &fd) < 0 || argint(5, &off))
      return -1;

  struct proc* p = myproc();
  struct file* f = p->ofile[fd];
  int n = len;

  if(addr == 0){
    // pte_t* t;
    // if((t = walk(p->pagetable, PGROUNDUP(p->sz), 1)) == NULL)
    //   return -1;
    // addr = PTE2PA(*t);
    // printf("alloc new page at %d\n", addr);
    addr = p->sz;
    // printf("oldsz = %d; n = %d\n", addr, n);
    p->sz = uvmalloc(p->pagetable, p->kpagetable, p->sz, p->sz + n);
    // printf("alloc new page at %d\n", addr);
    // mappages(p->pagetable, addr, len, (uint64)kalloc(), prot);
    // printf("alloc new page at %d\n", addr);
  }
  elock(f->ep);
  if(n > f->ep->file_size - off)
    n = f->ep->file_size - off;
  if((n = eread(f->ep, 1, addr, off, n)) < 0){
    eunlock(f->ep);
    return -1;
  }
  // copyout2(addr + n, "\0", 1);
  eunlock(f->ep);
  return addr;
}