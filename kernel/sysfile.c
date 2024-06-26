//
// File-system system calls.
// Mostly argument checking, since we don't trust
// user code, and calls into file.c and fs.c.
//


#include "include/types.h"
#include "include/riscv.h"
#include "include/param.h"
#include "include/stat.h"
#include "include/spinlock.h"
#include "include/proc.h"
#include "include/sleeplock.h"
#include "include/file.h"
#include "include/pipe.h"
#include "include/fcntl.h"
#include "include/fat32.h"
#include "include/syscall.h"
#include "include/string.h"
#include "include/printf.h"
#include "include/vm.h"


// Fetch the nth word-sized system call argument as a file descriptor
// and return both the descriptor and the corresponding struct file.
static int
argfd(int n, int *pfd, struct file **pf)
{
  int fd;
  struct file *f;

  if(argint(n, &fd) < 0)
    return -1;
  
  if(fd < 0 || fd >= NOFILE || (f=myproc()->ofile[fd]) == NULL)
    return -1;
  if(pfd)
    *pfd = fd;
  if(pf)
    *pf = f;
  return 0;
}

int get_abspath(struct dirent* cwd, char* path){
  if(path == NULL) return -1;
  strncpy(path, cwd->filename, FAT32_MAX_FILENAME + 1);
  char temp[FAT32_MAX_FILENAME];
  while(cwd->parent != NULL){
    cwd = cwd->parent;
    strncpy(temp, cwd->filename, FAT32_MAX_FILENAME);
    if(temp == NULL) return -1;
    str_mycat(temp, "/", FAT32_MAX_FILENAME);
    str_mycat(temp, path, FAT32_MAX_FILENAME);
    strncpy(path, temp, FAT32_MAX_FILENAME);
    if(path == NULL) return -1;
  }
  return 0;
}

int get_path(char* path, int fd){
  if(path == NULL){
    printf("path == null\n");
    return -1;
  }

  if(path[0] == '/' ){
    return 0;
  }
  else if(fd == AT_FDCWD){
    struct proc* current_proc = myproc();
    struct dirent *cwd = current_proc->cwd;
    char parent_name[FAT32_MAX_FILENAME + 1];
    if(get_abspath(cwd, parent_name) < 0){
      printf("wrong path\n");
      return -1;
    }
    str_mycat(parent_name, "/", FAT32_MAX_FILENAME);
    str_mycat(parent_name, path, FAT32_MAX_FILENAME);
    strncpy(path, parent_name, FAT32_MAX_FILENAME);
    return 0;
  }
  else{
    if(fd < 0)
      return -1;

    struct proc* current_proc = myproc();
    struct file *f = current_proc->ofile[fd];
    if(f == 0)
      return -1;

    struct dirent* cwd = f->ep;
    char dirname[FAT32_MAX_FILENAME + 1];
    if(get_abspath(cwd, dirname) < 0){
      printf("wrong path\n");
      return -1;
    }
    str_mycat(dirname, "/", FAT32_MAX_FILENAME);
    str_mycat(dirname, path, FAT32_MAX_FILENAME);
    strncpy(path, dirname, FAT32_MAX_FILENAME);
    return 0;
  }
}

// Allocate a file descriptor for the given file.
// Takes over file reference from caller on success.
static int
fdalloc(struct file *f)
{
  int fd;
  struct proc *p = myproc();

  for(fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd] == 0){
      p->ofile[fd] = f;
      return fd;
    }
  }
  return -1;
}

uint64
sys_dup(void)
{
  struct file *f;
  int fd;

  if(argfd(0, 0, &f) < 0)
    return -1;
  if((fd=fdalloc(f)) < 0)
    return -1;
  filedup(f);
  return fd;
}

uint64
sys_dup3(void)
{
  struct file *f;
  int fd;

  if(argfd(0, 0, &f) < 0 || argint(1, &fd) < 0){
    printf("wrong input");
    return -1;
  }
  myproc()->ofile[fd] = f;
  filedup(f);
  return fd;
}

uint64
sys_read(void)
{
  struct file *f;
  int n;
  uint64 p;

  if(argfd(0, 0, &f) < 0 || argint(2, &n) < 0 || argaddr(1, &p) < 0)
    return -1;
  f->ep->atime = r_time();
  return fileread(f, p, n);
}

uint64
sys_write(void)
{
  struct file *f;
  int n;
  uint64 p;

  if(argfd(0, 0, &f) < 0 || argint(2, &n) < 0 || argaddr(1, &p) < 0){
    return -1;
  }
  f->ep->mtime = r_time();
  return filewrite(f, p, n);
}

uint64
sys_close(void)
{
  int fd;
  struct file *f;

  if(argfd(0, &fd, &f) < 0)
    return -1;
  myproc()->ofile[fd] = 0;
  fileclose(f);
  return 0;
}

// uint64
// sys_fstat(void)
// {
//   struct file *f;
//   uint64 st; // user pointer to struct stat

//   if(argfd(0, 0, &f) < 0 || argaddr(1, &st) < 0)
//     return -1;
//   return filestat(f, st);
// }

static struct dirent*
create(char *path, short type, int mode)
{
  struct dirent *ep, *dp;
  char name[FAT32_MAX_FILENAME + 1];

  if((dp = enameparent(path, name)) == NULL){
    printf("path:%s has no dir\n", path);
    return NULL;
  }

  if (type == T_DIR) {
    mode = ATTR_DIRECTORY;
  } else if (mode & O_RDONLY) {
    mode = ATTR_READ_ONLY;
  } else {
    mode = 0;  
  }

  elock(dp);
  if ((ep = ealloc(dp, name, mode)) == NULL) {
    eunlock(dp);
    eput(dp);
    return NULL;
  }
  
  if ((type == T_DIR && !(ep->attribute & ATTR_DIRECTORY)) ||
      (type == T_FILE && (ep->attribute & ATTR_DIRECTORY))) {
    eunlock(dp);
    eput(ep);
    eput(dp);
    return NULL;
  }

  eunlock(dp);
  eput(dp);
  ep->ctime = r_time();
  elock(ep);
  return ep;
}

uint64
sys_open(void)
{
  char path[FAT32_MAX_PATH];
  int fd, omode;
  struct file *f;
  struct dirent *ep;

  if(argstr(0, path, FAT32_MAX_PATH) < 0 || argint(1, &omode) < 0){
    printf("%s\n %d\n", path, omode);
    return -1;
  }

  if(omode & O_CREATE){
    ep = create(path, T_FILE, omode);
    if(ep == NULL){
      printf("creat null: %d\n", omode);
      return -1;
    }
  } else {
    if((ep = ename(path)) == NULL){
      printf("open null: %d\n",omode);
      return -1;
    }
    elock(ep);
    if((ep->attribute & ATTR_DIRECTORY) && (omode != O_RDONLY && omode != O_DIRECTORY)){
      printf("show O_DIRECTORY: %d \n", omode);
      eunlock(ep);
      eput(ep);
      return -1;
    }
  }

  if((f = filealloc()) == NULL || (fd = fdalloc(f)) < 0){
    if (f) {
      fileclose(f);
    }
    eunlock(ep);
    eput(ep);
    printf("unable to open: %d\n", omode);
    return -1;
  }

  if(!(ep->attribute & ATTR_DIRECTORY) && (omode & O_TRUNC)){
    etrunc(ep);
  }

  f->type = FD_ENTRY;
  f->off = (omode & O_APPEND) ? ep->file_size : 0;
  f->ep = ep;
  f->readable = !(omode & O_WRONLY);
  f->writable = (omode & O_WRONLY) || (omode & O_RDWR);

  eunlock(ep);
  return fd;
}

uint64 sys_openat(void){
  int fd;
  char path[FAT32_MAX_PATH];
  int flags;
  int mode;
  struct dirent *ep;
  struct file *f;
  if(argint(0, &fd) < 0 || argstr(1, path, FAT32_MAX_PATH) < 0
      || argint(2, &flags) < 0 || argint(3, &mode) < 0)
    return -1;
  if(*path == '\0')
    return -1;

  if(get_path(path, fd) < 0){
    printf("error in openat\n");
    return -1;
  }

  int new_fd;
  if(flags & O_CREATE){
    ep = create(path, T_FILE, flags);
    if(ep == NULL){
      printf("creat null: %d\n", flags);
      return -1;
    }
  } else {
    if((ep = ename(path)) == NULL){
      // printf("open null: %d\n", flags);
      // printf("path=%s\n",path);
      // printf("flags=%d\n", flags);
      return -1;
    }
    elock(ep);
    if((ep->attribute & ATTR_DIRECTORY) && (flags & O_WRONLY)){
      eunlock(ep);
      eput(ep);
      printf("show O_DIRECTORY: %d \n", flags);
      printf("abs_path=%s\n",path);
      return -1;
    }
  }

  if((f = filealloc()) == NULL || (new_fd = fdalloc(f)) < 0){
    if (f) {
      fileclose(f);
    }
    eunlock(ep);
    eput(ep);
    printf("unable to open: %d\n", flags);
    return -1;
  }

  if(!(ep->attribute & ATTR_DIRECTORY) && (flags & O_TRUNC)){
    etrunc(ep);
  }

  f->type = FD_ENTRY;
  f->off = (flags & O_APPEND) ? ep->file_size : 0;
  f->ep = ep;
  f->readable = !(flags & O_WRONLY);
  f->writable = (flags & O_WRONLY) || (flags & O_RDWR);

  eunlock(ep);

  return new_fd;
}

uint64
sys_mkdir(void)
{
  char path[FAT32_MAX_PATH];
  struct dirent *ep;

  if(argstr(0, path, FAT32_MAX_PATH) < 0 || (ep = create(path, T_DIR, 0)) == 0){
    return -1;
  }
  eunlock(ep);
  eput(ep);
  ep->ctime = r_time();
  return 0;
}

uint64
sys_mkdirat(void)
{
  int dirfd;
  char path[FAT32_MAX_PATH];
  int mode;
  if(argint(0, &dirfd) < 0 || argstr(1, path, FAT32_MAX_PATH) < 0 || argint(2, &mode) < 0){
    printf("wrong input\n");
    return -1;
  }
  
  if(*path == '\0')
    return -1;

  if(get_path(path, dirfd) < 0){
    printf("error in mkdirat\n");
    return -1;
  }

  struct dirent *ep;
  ep = create(path, T_DIR, 0);
  eunlock(ep);
  eput(ep);
  return 0;
}

uint64
sys_chdir(void)
{
  char path[FAT32_MAX_PATH];
  struct dirent *ep;
  struct proc *p = myproc();
  
  if(argstr(0, path, FAT32_MAX_PATH) < 0 || (ep = ename(path)) == NULL){
    return -1;
  }
  elock(ep);
  if(!(ep->attribute & ATTR_DIRECTORY)){
    eunlock(ep);
    eput(ep);
    return -1;
  }
  eunlock(ep);
  eput(p->cwd);
  p->cwd = ep;
  return 0;
}

uint64
sys_pipe(void)
{
  uint64 fdarray; // user pointer to array of two integers
  struct file *rf, *wf;
  int fd0, fd1;
  struct proc *p = myproc();

  if(argaddr(0, &fdarray) < 0)
    return -1;
  if(pipealloc(&rf, &wf) < 0)
    return -1;
  fd0 = -1;
  if((fd0 = fdalloc(rf)) < 0 || (fd1 = fdalloc(wf)) < 0){
    if(fd0 >= 0)
      p->ofile[fd0] = 0;
    fileclose(rf);
    fileclose(wf);
    return -1;
  }
  // if(copyout(p->pagetable, fdarray, (char*)&fd0, sizeof(fd0)) < 0 ||
  //    copyout(p->pagetable, fdarray+sizeof(fd0), (char *)&fd1, sizeof(fd1)) < 0){
  if(copyout2(fdarray, (char*)&fd0, sizeof(fd0)) < 0 ||
     copyout2(fdarray+sizeof(fd0), (char *)&fd1, sizeof(fd1)) < 0){
    p->ofile[fd0] = 0;
    p->ofile[fd1] = 0;
    fileclose(rf);
    fileclose(wf);
    return -1;
  }
  return 0;
}

uint64
sys_pipe2(void)
{
  uint64 fdarray; // user pointer to array of two integers
  struct file *rf, *wf;
  int fd0, fd1;
  struct proc *p = myproc();

  if(argaddr(0, &fdarray) < 0)
    return -1;
  if(pipealloc(&rf, &wf) < 0)
    return -1;
  fd0 = -1;
  if((fd0 = fdalloc(rf)) < 0 || (fd1 = fdalloc(wf)) < 0){
    if(fd0 >= 0)
      p->ofile[fd0] = 0;
    fileclose(rf);
    fileclose(wf);
    return -1;
  }
  if(copyout2(fdarray, (char*)&fd0, sizeof(fd0)) < 0 ||
     copyout2(fdarray+sizeof(fd0), (char *)&fd1, sizeof(fd1)) < 0){
    p->ofile[fd0] = 0;
    p->ofile[fd1] = 0;
    fileclose(rf);
    fileclose(wf);
    return -1;
  }
  return 0;
}

// To open console device.
uint64
sys_dev(void)
{
  int fd, omode;
  int major, minor;
  struct file *f;

  if(argint(0, &omode) < 0 || argint(1, &major) < 0 || argint(2, &minor) < 0){
    return -1;
  }

  if(omode & O_CREATE){
    panic("dev file on FAT");
  }

  if(major < 0 || major >= NDEV)
    return -1;

  if((f = filealloc()) == NULL || (fd = fdalloc(f)) < 0){
    if(f)
      fileclose(f);
    return -1;
  }

  f->type = FD_DEVICE;
  f->off = 0;
  f->ep = 0;
  f->major = major;
  f->readable = !(omode & O_WRONLY);
  f->writable = (omode & O_WRONLY) || (omode & O_RDWR);

  return fd;
}

// To support ls command
uint64
sys_readdir(void)
{
  struct file *f;
  uint64 p;

  if(argfd(0, 0, &f) < 0 || argaddr(1, &p) < 0)
    return -1;
  return dirnext(f, p);
}

// get absolute cwd string
uint64
sys_getcwd(void)
{
  uint64 buf;
  int size;
  if(argaddr(0, &buf) < 0 || argint(1, &size) < 0){
    printf("wrong input\n");
    return NULL;
  }

  // uint64 addr;
  // if (argaddr(0, &addr) < 0)
  //   return -1;

  struct proc* p = myproc();
  if(buf == 0){
    buf = p->sz;
    p->sz = uvmalloc(p->pagetable, p->kpagetable, p->sz, p->sz + size);
  }

  struct dirent *de = myproc()->cwd;
  char path[FAT32_MAX_PATH];
  char *s;
  int len;

  if (de->parent == NULL) {
    s = "/";
  } else {
    s = path + FAT32_MAX_PATH - 1;
    *s = '\0';
    while (de->parent) {
      len = strlen(de->filename);
      s -= len;
      if (s <= path)          // can't reach root "/"
        return -1;
      strncpy(s, de->filename, len);
      *--s = '/';
      de = de->parent;
    }
  }

  if(strlen(s) + 1 > size){
    printf("too long to copy\n");
    return NULL;
  }

  // if (copyout(myproc()->pagetable, addr, s, strlen(s) + 1) < 0)
  if (copyout2(buf, s, strlen(s) + 1) < 0){
    printf("unable to copy\n");
    return NULL;
  }
  
  return buf;

}

// Is the directory dp empty except for "." and ".." ?
static int
isdirempty(struct dirent *dp)
{
  struct dirent ep;
  int count;
  int ret;
  ep.valid = 0;
  ret = enext(dp, &ep, 2 * 32, &count);   // skip the "." and ".."
  return ret == -1;
}

uint64
sys_remove(void)
{
  char path[FAT32_MAX_PATH];
  struct dirent *ep;
  int len;
  if((len = argstr(0, path, FAT32_MAX_PATH)) <= 0)
    return -1;

  char *s = path + len - 1;
  while (s >= path && *s == '/') {
    s--;
  }
  if (s >= path && *s == '.' && (s == path || *--s == '/')) {
    return -1;
  }
  
  if((ep = ename(path)) == NULL){
    return -1;
  }
  elock(ep);
  if((ep->attribute & ATTR_DIRECTORY) && !isdirempty(ep)){
      eunlock(ep);
      eput(ep);
      return -1;
  }
  elock(ep->parent);      // Will this lead to deadlock?
  eremove(ep);
  eunlock(ep->parent);
  eunlock(ep);
  eput(ep);

  return 0;
}

// Must hold too many locks at a time! It's possible to raise a deadlock.
// Because this op takes some steps, we can't promise
uint64
sys_rename(void)
{
  char old[FAT32_MAX_PATH], new[FAT32_MAX_PATH];
  if (argstr(0, old, FAT32_MAX_PATH) < 0 || argstr(1, new, FAT32_MAX_PATH) < 0) {
      return -1;
  }

  struct dirent *src = NULL, *dst = NULL, *pdst = NULL;
  int srclock = 0;
  char *name;
  if ((src = ename(old)) == NULL || (pdst = enameparent(new, old)) == NULL
      || (name = formatname(old)) == NULL) {
    goto fail;          // src doesn't exist || dst parent doesn't exist || illegal new name
  }
  for (struct dirent *ep = pdst; ep != NULL; ep = ep->parent) {
    if (ep == src) {    // In what universe can we move a directory into its child?
      goto fail;
    }
  }

  uint off;
  elock(src);     // must hold child's lock before acquiring parent's, because we do so in other similar cases
  srclock = 1;
  elock(pdst);
  dst = dirlookup(pdst, name, &off);
  if (dst != NULL) {
    eunlock(pdst);
    if (src == dst) {
      goto fail;
    } else if (src->attribute & dst->attribute & ATTR_DIRECTORY) {
      elock(dst);
      if (!isdirempty(dst)) {    // it's ok to overwrite an empty dir
        eunlock(dst);
        goto fail;
      }
      elock(pdst);
    } else {                    // src is not a dir || dst exists and is not an dir
      goto fail;
    }
  }

  if (dst) {
    eremove(dst);
    eunlock(dst);
  }
  memmove(src->filename, name, FAT32_MAX_FILENAME);
  emake(pdst, src, off);
  if (src->parent != pdst) {
    eunlock(pdst);
    elock(src->parent);
  }
  eremove(src);
  eunlock(src->parent);
  struct dirent *psrc = src->parent;  // src must not be root, or it won't pass the for-loop test
  src->parent = edup(pdst);
  src->off = off;
  src->valid = 1;
  eunlock(src);

  eput(psrc);
  if (dst) {
    eput(dst);
  }
  eput(pdst);
  eput(src);

  return 0;

fail:
  if (srclock)
    eunlock(src);
  if (dst)
    eput(dst);
  if (pdst)
    eput(pdst);
  if (src)
    eput(src);
  return -1;
}

uint64 sys_linkat(void){
  int olddirfd, newdirfd, flags;
  char oldpath[FAT32_MAX_PATH];
  char newpath[FAT32_MAX_PATH];

  if(argint(0, &olddirfd) < 0 || argstr(1, oldpath, FAT32_MAX_PATH) < 0
      || argint(2, &newdirfd) < 0 || argstr(3, newpath, FAT32_MAX_PATH) < 0
        || argint(4, &flags) < 0)
    return -1;

  get_path(oldpath, olddirfd);
  get_path(newpath, newdirfd);

  struct dirent* oldfile;
  struct dirent* ep;
  if((oldfile = ename(oldpath)) == NULL){
    printf("linkat null: %s\n",oldfile);
    return -1;
  }
  elock(oldfile);
  if(oldfile->attribute & ATTR_DIRECTORY){
    eunlock(oldfile);
    eput(oldfile);
    printf("cannot linkat O_DIRECTORY\n");
    return -1;
  }
  ep = create(newpath, T_FILE, oldfile->attribute);
  if(ep == NULL){
    printf("creat null: %d\n", oldfile->attribute);
    return -1;
  }
  elock(oldfile);
  ep->attribute = oldfile->attribute;
  ep->first_clus = oldfile->first_clus;
  ep->file_size = oldfile->file_size;
  ep->cur_clus = oldfile->cur_clus;
  ep->clus_cnt = oldfile->clus_cnt;
  ep->dev = oldfile->dev;
  ep->valid = oldfile->valid;

  eunlock(oldfile);
  eunlock(ep);
  return 0;
}

uint64 sys_unlinkat(void){
  int dirfd, flags;
  char path[FAT32_MAX_PATH];

  if(argint(0, &dirfd) < 0 || argstr(1, path, FAT32_MAX_PATH) < 0
      || argint(2, &flags) < 0){
    printf("error in unlinkat\n");
    return -1;
  }

  if(get_path(path, dirfd) < 0){
    printf("wrong path\n");
    return -1;
  }

  struct dirent* ep;
  if((ep = ename(path)) == NULL){
    return -1;
  }
  elock(ep);
  if((ep->attribute & ATTR_DIRECTORY) && ((!isdirempty(ep) && (flags & AT_REMOVEDIR) != 0) || (flags & AT_REMOVEDIR) == 0)){
      eunlock(ep);
      eput(ep);
      return -1;
  }
  elock(ep->parent);      // Will this lead to deadlock?
  eremove(ep);
  eunlock(ep->parent);
  eunlock(ep);
  eput(ep);

  return 0;
}

uint64 sys_mount(void){
  char special[FAT32_MAX_PATH], dir[FAT32_MAX_PATH], fstype[FAT32_MAX_PATH];
  uint64 flags, data;
  //struct dirent* sp;
  struct dirent* di;

  if(argstr(0, special, FAT32_MAX_PATH) < 0 || argstr(1, dir, FAT32_MAX_PATH) < 0
      || argstr(2, fstype, FAT32_MAX_PATH) < 0 || argaddr(3, &flags) < 0 || argaddr(4, &data))
    return -1;

  if(strncmp((char*)fstype, "vfat", 5)){
    printf("wrong file type\n");
    return -1;
  }
  
  if((di = ename(dir)) == NULL){
    return -1;
  }
  
  return 0;
}

uint64 sys_umount2(void){
  char special[FAT32_MAX_PATH];
  uint64 flags;
  struct dirent* sp;
  //struct dirent* di;

  if(argstr(0, special, FAT32_MAX_PATH) < 0 || argaddr(1, &flags) < 0)
    return -1;
  
  if((sp = ename(special)) == NULL){
    return -1;
  }
  
  return 0;
}

uint64 sys_getdents64(void){
  int fd, len;
  uint64 buf;

  if(argint(0, &fd) < 0 || argaddr(1, &buf) < 0 || argint(2, &len) < 0)
    return -1;

  struct proc* p = myproc();
  struct file* f = p->ofile[fd];
  struct dirent *ep = f->ep;

  return getdents64(ep, buf, len);
}

uint64 sys_fstat(void){
  int fd;
  uint64 addr;
  if(argint(0, &fd) < 0 || argaddr(1, &addr) < 0 )
    return -1;
  struct proc* p = myproc();
  struct file* f = p->ofile[fd];
  struct dirent *ep = f->ep;
  struct kstat* st = {0};
  st->st_dev = ep->dev;
  st->st_ino = 0;
  st->st_mode = (ep->attribute & ATTR_DIRECTORY) ? T_DIR : T_FILE;
  st->st_nlink = f->ref;
  st->st_size = ep->file_size;
  st->st_atime_sec = ep->atime / 10000000;
  st->st_mtime_sec = ep->mtime / 10000000;
  st->st_ctime_sec = ep->ctime / 10000000;
  *(struct kstat*)addr = *st;
  return 0;
}