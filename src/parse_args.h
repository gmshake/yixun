#ifndef PARSE_ARGS_H
#define PARSE_ARGS_H

extern const char *arg_conf_file;
extern const char *arg_username;
extern const char *arg_password;
extern const char *arg_authserver;
extern const char *arg_regip;
extern const char *arg_hwaddr;

extern void parse_args(int argc, char *const argv[]);

#endif
