#ifndef FILE_LOCK_H
#define FILE_LOCK_H

extern int open_lock_file(const char *file);
extern int write_pid(int fd);
extern int close_lock_file(int fd);

#endif	/* FILE_LOCK_H */

