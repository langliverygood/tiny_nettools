#ifndef _LSHELL_H_
#define _LSHELL_H_

#define RUN_AT_NEW_THREAD  0 /* 在新线程中执行命令 */
#define RUN_AT_MAIN_THREAD 1 /* 在主线程中执行命令 */

/* 说明：lshell初始化 */
void lshell_init();

/* 说明：设置命令提示符 */
void lshell_set_promt(const char *str);

/* 说明：设置错误提示开关 */
/* 参数：0 关闭错误提示 */
/*      1 打开错误提示 */
void lshell_set_errmsg_swtich(int flag);

/* 说明：注册用户的命令 */
/* 参数：parent 父命令id，若无父命令，则为-1 */
/* 参数：cmd 命令 */
/* 参数：tip 命令的说明 */
/* 参数：func 函数指针 */
/* 返回值：该命令的id，若出错则返回-1 */
int lshell_register(int parent, const char *cmd, const char *tip, void (* func)(int argc, char **argv), int mode);

/* 说明：lshell启动 */
void lshell_start();

#endif
