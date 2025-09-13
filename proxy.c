//09J23122-何辰玮-东南大学
 #include "csapp.h"
 #include <pthread.h>
 #include <ctype.h>
 #include <string.h>
 
/* Recommended max cache and object sizes */
 #define MAX_CACHE_SIZE 1049000      
 #define MAX_OBJECT_SIZE 102400      //单对象最大可缓存字节
 #define REQLINE_BUFSZ 8192  
 
 //固定 UA字符串
 static const char *user_agent_hdr =
     "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) "
     "Gecko/20120305 Firefox/10.0.3\r\n";

 // 缓存结构（读写锁 + 近似 LRU） head 为 MRU，tail 为 LRU命中时提升到头部；超出时从尾部pop
 typedef struct cache_obj {
     char *key;               //规范化后的 URI 作为键
     char *data;              //缓存的完整响应
     size_t size; 
     struct cache_obj *prev;  
     struct cache_obj *next;  
 } cache_obj_t;
 typedef struct {
     cache_obj_t *head;       // MRU
     cache_obj_t *tail;       // LRU（
     size_t total;           
     pthread_rwlock_t rwlock; // 写独占 
 } cache_t;
 
 static cache_t g_cache;
 
 // 缓存相关函数
 static void cache_init(cache_t *c);
 static cache_obj_t *cache_lookup(cache_t *c, const char *key);
 static void cache_promote(cache_t *c, cache_obj_t *obj);
 static void cache_insert(cache_t *c, const char *key, const char *data, size_t n);
 static void cache_evict_if_needed(cache_t *c, size_t need);
 static void cache_remove_tail(cache_t *c);
 static void cache_free_obj(cache_obj_t *o);
 
// 线程与请求处理工具
 typedef struct {
     int connfd;
     struct sockaddr_storage clientaddr;
 } thread_args_t;
 
 // 主流程与解析、转发
 static void *thread_main(void *vargp);
 static void handle_client(int connfd, struct sockaddr_storage *caddr);
 static int  parse_request_line(const char *line, char *method, char *uri, char *version);
 static int  parse_uri(const char *uri, char *host, char *port, char *path);
 static void build_and_forward(int clientfd, rio_t *crio,const char *method, const char *uri,const char *host_from_uri, const char *port_from_uri, const char *path_from_uri);
 static void to_lower_str(char *s);
 static void normalize_uri(const char *host, const char *port, const char *path, char *out_uri, size_t outsz);
 
 int main(int argc, char **argv) {
     int listenfd;
     signal(SIGPIPE, SIG_IGN);
     if (argc != 2) {
         fprintf(stderr, "Usage: %s <port>\n", argv[0]);
         exit(1);
     }
 
     cache_init(&g_cache);
 
     listenfd = Open_listenfd(argv[1]);
     if (listenfd < 0) {
         unix_error("Open_listenfd failed");
     }
 
     while (1) {
         socklen_t clientlen;
         thread_args_t *targs = (thread_args_t *)Malloc(sizeof(thread_args_t));
         clientlen = sizeof(targs->clientaddr);
         // 阻塞等待
         targs->connfd = Accept(listenfd, (SA *)&targs->clientaddr, &clientlen);
         // 每个连接新建一个线程处理
         pthread_t tid;
         Pthread_create(&tid, NULL, thread_main, targs);
         Pthread_detach(tid);
     }
     return 0;
 }
 
 // 线程入口，复制必要参数，释放堆上参数，处理完请求后关闭 fd
 static void *thread_main(void *vargp) {
     thread_args_t *targs = (thread_args_t *)vargp;
     int connfd = targs->connfd;
     struct sockaddr_storage clientaddr = targs->clientaddr;
     Free(targs);
     handle_client(connfd, &clientaddr);
     Close(connfd);
     return NULL;
 }
 
 // 读取请求首行与头部，规范化并转发，写回响应；如果是相对 URI，则从 Host 头解析出主机与端口
 static void handle_client(int connfd, struct sockaddr_storage *caddr) {
     rio_t crio;
     char reqline[REQLINE_BUFSZ];
     Rio_readinitb(&crio, connfd);
     // 读取请求首行：METHOD URI VERSION\r\n
     if (Rio_readlineb(&crio, reqline, sizeof(reqline)) <= 0) {
         return; // 失败
     }
     char method[16], uri[8192], version[32];
     if (!parse_request_line(reqline, method, uri, version)) {
         const char *msg =
             "HTTP/1.0 400 Bad Request\r\n"
             "Connection: close\r\n"
             "Content-Length: 11\r\n\r\nBad Request";
         Rio_writen(connfd, (void*)msg, strlen(msg));
         return;
     }
     if (strcasecmp(method, "GET") != 0) {
         // 非 GET 直接 501
         const char *msg =
             "HTTP/1.0 501 Not Implemented\r\n"
             "Connection: close\r\n"
             "Content-Length: 15\r\n\r\nNot Implemented";
         Rio_writen(connfd, (void*)msg, strlen(msg));
         return;
     }
     // 解析 URI（优先绝对 URI），若是相对 URI 则稍后从 Host 头补齐
     char host[256] = "", port[16] = "80", path[4096] = "/";
     int absok = parse_uri(uri, host, port, path);
     // 转发与缓存逻辑封装在 build_and_forward 里
     build_and_forward(connfd, &crio, method, uri,
                       absok ? host : NULL, absok ? port : NULL, path);
 }
 
 // "METHOD <uri> HTTP/x.y"，仅做基本健壮性解析，格式错误返回 0
 static int parse_request_line(const char *line, char *method, char *uri, char *version) {
     if (sscanf(line, "%15s %8191s %31s", method, uri, version) != 3) {
         return 0;
     }
     return 1;
 }
 
 // http://host[:port]/path，返回 1 表示解析到绝对 http URI，返回 0 表示相对 URI 或非 http
 static int parse_uri(const char *uri, char *host, char *port, char *path) {
     const char *p = NULL;
     if (!strncasecmp(uri, "http://", 7)) {
         p = uri + 7;
     } else if (!strncasecmp(uri, "https://", 8)) {
         // 不管CONNECT/HTTPS，直接当相对路径处理（后续走 Host 头）
         strncpy(path, uri, 4095);
         path[4095] = '\0';
         return 0;
     } else {
         strncpy(path, uri, 4095);
         path[4095] = '\0';
         return 0;
     }
     // 提取 host[:port] 与 /path
     const char *hostbeg = p;
     const char *slash = strchr(hostbeg, '/');
     const char *hostend = slash ? slash : uri + strlen(uri);
     const char *colon = memchr(hostbeg, ':', hostend - hostbeg);
     if (colon) {
         size_t hlen = (size_t)(colon - hostbeg);
         size_t plen = (size_t)(hostend - colon - 1);
         if (hlen >= 255) hlen = 255;
         if (plen >= 15)  plen = 15;
         memcpy(host, hostbeg, hlen); host[hlen] = '\0';
         memcpy(port, colon + 1, plen); port[plen] = '\0';
     } else {
         size_t hlen = (size_t)(hostend - hostbeg);
         if (hlen >= 255) hlen = 255;
         memcpy(host, hostbeg, hlen); host[hlen] = '\0';
         strcpy(port, "80");
     }
     if (slash) {
         strncpy(path, slash, 4095);
         path[4095] = '\0';
     } else {
         strcpy(path, "/");
     }
     return 1;
 }
 
 // 构造并发送规范化请求，读取并处理客户端请求头
  * ===================================================== */
 static void build_and_forward(int clientfd, rio_t *crio,
                               const char *method, const char *uri,
                               const char *host_from_uri, const char *port_from_uri, const char *path_from_uri) {
     char host[256] = "";
     char port[16]  = "80";
     char path[4096] = "/";
     if (host_from_uri) strncpy(host, host_from_uri, sizeof(host)-1);
     if (port_from_uri) strncpy(port, port_from_uri, sizeof(port)-1);
     if (path_from_uri) strncpy(path, path_from_uri, sizeof(path)-1);
     // 读取客户端请求头，
     char buf[MAXLINE];
     int  saw_host = (host[0] != '\0');  // 若首行解析到主机，就认为已有 Host
     char other_hdrs[65536]; other_hdrs[0] = '\0';
     char host_hdr_line[512]; host_hdr_line[0] = '\0';
     while (1) {
         ssize_t n = Rio_readlineb(crio, buf, sizeof(buf));
         if (n <= 0) return;                
         if (!strcmp(buf, "\r\n")) break;    
         // 若没获得主机信息，尝试从Host头解析host[:port]
         if (!strncasecmp(buf, "Host:", 5)) {
             if (!saw_host) {
                 char h[256]; int pc = 0;
                 if (sscanf(buf + 5, " %255[^:\r\n]:%d", h, &pc) == 2) {
                     strncpy(host, h, sizeof(host)-1);
                     snprintf(port, sizeof(port), "%d", pc);
                     saw_host = 1;
                 } else if (sscanf(buf + 5, " %255[^\r\n]", h) == 1) {
                     strncpy(host, h, sizeof(host)-1);
                     // 端口仍保持已有（
                     saw_host = 1;
                 }
             }
             continue;
         }
         if (!strncasecmp(buf, "Connection:", 11))        continue;
         if (!strncasecmp(buf, "Proxy-Connection:", 17))  continue;
         if (!strncasecmp(buf, "User-Agent:", 11))        continue;
         // 其它头部原样追加
         size_t remain = sizeof(other_hdrs) - strlen(other_hdrs) - 1;
         strncat(other_hdrs, buf, remain);
     }
     if (!saw_host) {
         // 相对URI且没有Host头，规范要求 400
         const char *msg =
             "HTTP/1.0 400 Bad Request\r\n"
             "Connection: close\r\n"
             "Content-Length: 23\r\n\r\nMissing Host header";
         Rio_writen(clientfd, (void*)msg, strlen(msg));
         return;
     }
     // 生成标准Host头（默认端口 80 时不带:80）
     if (!strcmp(port, "80")) {
         snprintf(host_hdr_line, sizeof(host_hdr_line), "Host: %s\r\n", host);
     } else {
         snprintf(host_hdr_line, sizeof(host_hdr_line), "Host: %s:%s\r\n", host, port);
     }
     // 规范化URI作为缓存键
     char cache_key[8192];
     normalize_uri(host, port, path, cache_key, sizeof(cache_key));
     // 先查缓存，读锁 - 命中后用写锁提升LRU -  回写客户端
     pthread_rwlock_rdlock(&g_cache.rwlock);
     cache_obj_t *hit = cache_lookup(&g_cache, cache_key);
     if (hit) {
         pthread_rwlock_unlock(&g_cache.rwlock);
 
         pthread_rwlock_wrlock(&g_cache.rwlock);
         cache_promote(&g_cache, hit);
         pthread_rwlock_unlock(&g_cache.rwlock);
 
         Rio_writen(clientfd, hit->data, hit->size);
         return;
     }
     pthread_rwlock_unlock(&g_cache.rwlock);
     // 未命中：连上目标服务器
     int serverfd = Open_clientfd(host, port);
     if (serverfd < 0) {
         const char *msg =
             "HTTP/1.0 502 Bad Gateway\r\n"
             "Connection: close\r\n"
             "Content-Length: 11\r\n\r\nBad Gateway";
         Rio_writen(clientfd, (void*)msg, strlen(msg));
         return;
     }
     rio_t srio;
     Rio_readinitb(&srio, serverfd);
     // 构造并发送下游请求
     char req[MAXLINE];
     int m = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.0\r\n"
                      "%s"
                      "%s"
                      "Connection: close\r\n"
                      "Proxy-Connection: close\r\n"
                      "%s"
                      "\r\n",
                      path, host_hdr_line, user_agent_hdr, other_hdrs);
     Rio_writen(serverfd, req, m);
     // 回传响应，边读边写，同时在内存中累计
     char *objbuf = (char *)Malloc(MAX_OBJECT_SIZE);
     size_t objn = 0;
     ssize_t n;
     while ((n = Rio_readnb(&srio, buf, sizeof(buf))) > 0) {
         Rio_writen(clientfd, buf, n);
 
         if (objn + (size_t)n <= MAX_OBJECT_SIZE) {
             memcpy(objbuf + objn, buf, (size_t)n);
             objn += (size_t)n;
         }
     }
     Close(serverfd);
     // 当对象完整且不超过阈值，才写入缓存
     if (objn > 0 && objn <= MAX_OBJECT_SIZE) {
         pthread_rwlock_wrlock(&g_cache.rwlock);
         cache_insert(&g_cache, cache_key, objbuf, objn);
         pthread_rwlock_unlock(&g_cache.rwlock);
     }
     Free(objbuf);
 }

 // 小写化
 static void to_lower_str(char *s) {
     for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
 }
 
 // host/port/path规范化为缓存键
 static void normalize_uri(const char *host, const char *port, const char *path, char *out_uri, size_t outsz) {
     char h[256];
     strncpy(h, host, sizeof(h)-1);
     h[sizeof(h)-1] = '\0';
     to_lower_str(h);
     if (!strcmp(port, "80")) {
         snprintf(out_uri, outsz, "http://%s%s", h, path);
     } else {
         snprintf(out_uri, outsz, "http://%s:%s%s", h, port, path);
     }
 }
 
 // 初始化缓存
 static void cache_init(cache_t *c) {
     c->head = c->tail = NULL;
     c->total = 0;
     pthread_rwlock_init(&c->rwlock, NULL);
 }
 
 // 顺序查找
 static cache_obj_t *cache_lookup(cache_t *c, const char *key) {
     for (cache_obj_t *p = c->head; p; p = p->next) {
         if (!strcmp(p->key, key)) return p;
     }
     return NULL;
 }
 
 // 将命中的对象提升为 MRU
 static void cache_promote(cache_t *c, cache_obj_t *o) {
     if (o == c->head) return;
     if (o->prev) o->prev->next = o->next;
     if (o->next) o->next->prev = o->prev;
     if (o == c->tail) c->tail = o->prev;
     // 插入头部
     o->prev = NULL;
     o->next = c->head;
     if (c->head) c->head->prev = o;
     c->head = o;
     if (!c->tail) c->tail = o;
 }
 
 // 插入或更新对象
 static void cache_insert(cache_t *c, const char *key, const char *data, size_t n) {
     if (n > MAX_OBJECT_SIZE) return;
     cache_obj_t *old = cache_lookup(c, key);
     if (old) {
         // 更新已有对象，并提升为MRU
         c->total -= old->size;
         Free(old->data);
         old->data = (char *)Malloc(n);
         memcpy(old->data, data, n);
         old->size = n;
         c->total += n;
         cache_promote(c, old);
         cache_evict_if_needed(c, 0);
         return;
     }
     cache_evict_if_needed(c, n);
     // 新建节点并插入头部
     cache_obj_t *o = (cache_obj_t *)Malloc(sizeof(cache_obj_t));
     o->key  = Malloc(strlen(key) + 1);
     strcpy(o->key, key);
     o->data = (char *)Malloc(n);
     memcpy(o->data, data, n);
     o->size = n;
     o->prev = NULL;
     o->next = c->head;
     if (c->head) c->head->prev = o;
     c->head = o;
     if (!c->tail) c->tail = o;
     c->total += n;
 }
 
 // total+need超过上限，就pop
 static void cache_evict_if_needed(cache_t *c, size_t need) {
     while (c->tail && c->total + need > MAX_CACHE_SIZE) {
         cache_remove_tail(c);
     }
 }
 
 // 删除尾节点
 static void cache_remove_tail(cache_t *c) {
     cache_obj_t *o = c->tail;
     if (!o) return;
 
     if (o->prev) o->prev->next = NULL;
     c->tail = o->prev;
     if (c->head == o) c->head = NULL;
 
     c->total -= o->size;
     cache_free_obj(o);
 }
 
 // 释放对象内存
 static void cache_free_obj(cache_obj_t *o) {
     if (!o) return;
     Free(o->key);
     Free(o->data);
     Free(o);
 }
 