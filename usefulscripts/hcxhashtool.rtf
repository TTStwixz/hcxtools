{\rtf1\ansi\deff0\nouicompat{\fonttbl{\f0\fnil\fcharset0 Courier New;}}
{\*\generator Riched20 10.0.19041}\viewkind4\uc1 
\pard\f0\fs22\lang1053 #define _GNU_SOURCE\par
#include <fcntl.h>\par
#include <errno.h>\par
#include <getopt.h>\par
#include <stdarg.h>\par
#include <stdint.h>\par
#include <stdio.h>\par
#include <stdlib.h>\par
#include <stdbool.h>\par
#include <string.h>\par
#include <ctype.h>\par
#include <unistd.h>\par
#include <time.h>\par
#include <limits.h>\par
#include <inttypes.h>\par
#include <pwd.h>\par
#include <sys/types.h>\par
#include <sys/stat.h>\par
#include <curl/curl.h>\par
#include <arpa/inet.h>  \par
#include <openssl/conf.h>\par
#include <openssl/err.h>\par
#include <openssl/crypto.h>\par
#include <openssl/evp.h>\par
#include <openssl/ssl.h>\par
#if defined (__APPLE__) || defined(__OpenBSD__)\par
#include <libgen.h>\par
#include <sys/socket.h>\par
#else\par
#include <stdio_ext.h>\par
#endif\par
#ifdef __linux__\par
#include <linux/limits.h>\par
#endif\par
#include "include/hcxhashtool.h"\par
#include "include/strings.c"\par
#include "include/fileops.c"\par
#include "include/ieee80211.h"\par
#include "include/byteops.c"\par
\par
/*===========================================================================*/\par
/* global var */\par
\par
static const char *usedoui;\par
static int ouicount;\par
static int ouilistcount;\par
static ouilist_t *ouilist;\par
static hashlist_t *hashlist;\par
static long int hashlistcount;\par
static long int readcount;\par
static long int readerrorcount;\par
static long int pmkideapolcount;\par
static long int pmkidcount;\par
static long int eapolcount;\par
static long int pmkidwrittencount;\par
static long int eapolwrittencount;\par
static long int essidwrittencount;\par
static long int hccapxwrittencount;\par
static long int hccapwrittencount;\par
static long int johnwrittencount;\par
\par
static int hashtype;\par
static int essidlen;\par
static int essidlenmin;\par
static int essidlenmax;\par
static int filteressidlen;\par
static char *filteressidptr;\par
static int filteressidpartlen;\par
static char *filteressidpartptr;\par
\par
static char *filtervendorptr;\par
\par
static bool flagpsk;\par
static bool flagpmk;\par
static bool flagessidgroup;\par
static bool flagmacapgroup;\par
static bool flagmacclientgroup;\par
static bool flagouigroup;\par
static bool flagvendorout;\par
static bool flaghccapsingleout;\par
\par
static bool flagfiltermacap;\par
static uint8_t filtermacap[6];\par
\par
static bool flagfiltermacclient;\par
static uint8_t filtermacclient[6];\par
\par
static bool flagfilterouiap;\par
static uint8_t filterouiap[3];\par
\par
static bool flagfilterouiclient;\par
static uint8_t filterouiclient[3];\par
\par
static bool flagfilterauthorized;\par
static bool flagfilternotauthorized;\par
static bool flagfilterrcchecked;\par
static bool flagfilterapless;\par
\par
static int pskptrlen;\par
static char *pskptr;\par
static uint8_t pmk[32];\par
/*===========================================================================*/\par
static void closelists()\par
\{\par
if(hashlist != NULL) free(hashlist);\par
if(ouilist != NULL) free(ouilist);\par
EVP_cleanup();\par
CRYPTO_cleanup_all_ex_data();\par
ERR_free_strings();\par
return;\par
\}\par
/*===========================================================================*/\par
static bool initlists()\par
\{\par
ouicount = 0;\par
ouilistcount = OUILIST_MAX;\par
hashlistcount = HASHLIST_MAX;\par
readcount = 0;\par
readerrorcount = 0;\par
pmkideapolcount = 0;\par
pmkidcount = 0;\par
eapolcount = 0;\par
pmkidwrittencount = 0;\par
eapolwrittencount = 0;\par
essidwrittencount = 0;\par
hccapxwrittencount = 0;\par
hccapwrittencount = 0;\par
ERR_load_crypto_strings();\par
OpenSSL_add_all_algorithms();\par
if((hashlist = (hashlist_t*)calloc(hashlistcount, HASHLIST_SIZE)) == NULL) return false;\par
if((ouilist = (ouilist_t*)calloc(ouilistcount, OUILIST_SIZE)) == NULL) return false;\par
return true;\par
\}\par
/*===========================================================================*/\par
static char *getvendor(uint8_t *mac)\par
\{\par
static ouilist_t * zeiger;\par
static char *unknown = "unknown";\par
\par
for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++)\par
\tab\{\par
\tab if(memcmp(zeiger->oui, mac, 3) == 0) return zeiger->vendor;\par
\tab if(memcmp(zeiger->oui, mac, 3) > 0) return unknown;\par
\tab\}\par
return unknown;\par
\}\par
/*===========================================================================*/\par
static void printstatus()\par
\{\par
static char *vendor;\par
\par
\par
printf("\\nOUI information file...: %s\\n", usedoui);\par
if(ouicount > 0)\tab\tab printf("OUI entires............: %d\\n", ouicount);\par
if(readcount > 0)\tab\tab printf("total lines read.......: %ld\\n", readcount);\par
if(flagvendorout == true)\par
\tab\{\par
\tab printf("\\n");\par
\tab return;\par
\tab\}\par
if(readerrorcount > 0)\tab\tab\tab printf("read errors............: %ld\\n", readerrorcount);\par
if(pmkideapolcount > 0)\tab\tab\tab printf("valid hash lines.......: %ld\\n", pmkideapolcount);\par
if(pmkidcount > 0)\tab\tab\tab printf("PMKID hash lines.......: %ld\\n", pmkidcount);\par
if(eapolcount > 0)\tab\tab\tab printf("EAPOL hash lines.......: %ld\\n", eapolcount);\par
if(essidlenmin != 0)\tab\tab\tab printf("filter by ESSID len min: %d\\n", essidlenmin);\par
if(essidlenmax != 32)\tab\tab\tab printf("filter by ESSID len max: %d\\n", essidlenmax);\par
if(filteressidptr != NULL)\tab\tab printf("filter by ESSID........: %s\\n", filteressidptr);\par
if(filteressidpartptr != NULL)\tab\tab printf("filter by part of ESSID: %s\\n", filteressidpartptr);\par
if(flagfiltermacap == true)\par
\tab\{\par
\tab vendor = getvendor(filtermacap);\par
\tab printf("filter by MAC..........: %02x%02x%02x%02x%02x%02x (%s)\\n", filtermacap[0], filtermacap[1], filtermacap[2], filtermacap[3], filtermacap[4], filtermacap[5], vendor);\par
\tab\}\par
if(flagfiltermacclient == true)\par
\tab\{\par
\tab vendor = getvendor(filtermacclient);\par
\tab printf("filter by MAC..........: %02x%02x%02x%02x%02x%02x (%s)\\n", filtermacclient[0], filtermacclient[1], filtermacclient[2], filtermacclient[3], filtermacclient[4], filtermacclient[5], vendor);\par
\tab\}\par
\par
if(flagfilterouiap == true)\par
\tab\{\par
\tab vendor = getvendor(filterouiap);\par
\tab printf("filter AP by OUI.......: %02x%02x%02x (%s)\\n", filterouiap[0], filterouiap[1], filterouiap[2], vendor);\par
\tab\}\par
if(filtervendorptr != NULL)\tab\tab printf("filter AP by VENDOR....: %s\\n", filtervendorptr);\par
if(flagfilterouiclient == true)\par
\tab\{\par
\tab vendor = getvendor(filterouiclient);\par
\tab printf("filter CLIENT by OUI...: %02x%02x%02x (%s)\\n", filterouiclient[0], filterouiclient[1], filterouiclient[2], vendor);\par
\tab\}\par
if(flagfilterapless == true)\tab\tab printf("filter by M2...........: requested from client (AP-LESS)\\n");\par
if(flagfilterrcchecked == true)\tab\tab printf("filter by replaycount..: checked\\n");\par
if(flagfilterauthorized == true)\tab printf("filter by status.......: authorized (M1M4, M2M3 or M3M4)\\n");\par
if(flagfilternotauthorized == true)\tab printf("filter by status.......: challenge (M1M2)\\n");\par
if(pmkidwrittencount > 0)\tab\tab printf("PMKID written..........: %ld\\n", pmkidwrittencount);\par
if(eapolwrittencount > 0)\tab\tab printf("EAPOL written..........: %ld\\n", eapolwrittencount);\par
if(hccapxwrittencount > 0)\tab\tab printf("EAPOL written to hccapx: %ld\\n", hccapxwrittencount);\par
if(hccapwrittencount > 0)\tab\tab printf("EAPOL written to hccap.: %ld\\n", hccapwrittencount);\par
if(johnwrittencount > 0)\tab\tab printf("EAPOL written to john..: %ld\\n", johnwrittencount);\par
if(essidwrittencount > 0)\tab\tab printf("ESSID (unique) written.: %ld\\n", essidwrittencount);\par
printf("\\n");\par
return;\par
\}\par
/*===========================================================================*/\par
static void testeapolpmk(hashlist_t *zeiger)\par
\{\par
static int keyver;\par
static int p;\par
static wpakey_t *wpak;\par
static uint8_t *pkeptr;\par
static size_t testptklen;\par
static size_t testmiclen;\par
static EVP_MD_CTX *mdctx;\par
static EVP_PKEY *pkey;\par
\par
static uint8_t pkedata[102];\par
static uint8_t testptk[EVP_MAX_MD_SIZE];\par
static uint8_t testmic[EVP_MAX_MD_SIZE];\par
\par
wpak = (wpakey_t*)&zeiger->eapol[EAPAUTH_SIZE];\par
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;\par
if(keyver == 2)\par
\tab\{\par
\tab memset(&pkedata, 0, sizeof(pkedata));\par
\tab memset(&testptk, 0, sizeof(testptk));\par
\tab memset(&testmic, 0, sizeof(testptk));\par
\tab pkeptr = pkedata;\par
\tab memcpy(pkeptr, "Pairwise key expansion", 23);\par
\tab if(memcmp(zeiger->ap, zeiger->client, 6) < 0)\par
\tab\tab\{\par
\tab\tab memcpy(pkeptr +23, zeiger->ap, 6);\par
\tab\tab memcpy(pkeptr +29, zeiger->client, 6);\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab memcpy(pkeptr +23, zeiger->client, 6);\par
\tab\tab memcpy(pkeptr +29, zeiger->ap, 6);\par
\tab\tab\}\par
\tab if(memcmp(zeiger->nonce, wpak->nonce, 32) < 0)\par
\tab\tab\{\par
\tab\tab memcpy (pkeptr +35, zeiger->nonce, 32);\par
\tab\tab memcpy (pkeptr +67, wpak->nonce, 32);\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab memcpy (pkeptr +35, wpak->nonce, 32);\par
\tab\tab memcpy (pkeptr +67, zeiger->nonce, 32);\par
\tab\tab\}\par
\tab testptklen = 32;\par
\tab mdctx = EVP_MD_CTX_new();\par
\tab if(mdctx == 0) return;\par
\tab pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);\par
\tab if(pkey == NULL)\par
\tab\tab\{\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignUpdate(mdctx, pkedata, 100) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_reset(mdctx);\par
\tab testmiclen = 16;\par
\tab pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testptk, 16);\par
\tab if(pkey == NULL)\par
\tab\tab\{\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignUpdate(mdctx, zeiger->eapol, zeiger->eapauthlen) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignFinal(mdctx, testmic, &testmiclen) <= 0)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_free(mdctx);\par
\tab if(memcmp(zeiger->hash, &testmic, 16) == 0)\par
\tab\tab\{\par
\tab\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->client[p]);\par
\tab\tab fprintf(stdout, ":");\par
\tab\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->ap[p]);\par
\tab\tab if(zeiger->essidlen != 0)\par
\tab\tab\tab\{\par
\tab\tab\tab if(ispotfilestring(zeiger->essidlen, (char*)zeiger->essid) == true) fprintf(stdout, ":%.*s", zeiger->essidlen, zeiger->essid);\par
\tab\tab\tab else\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab\tab for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);\par
\tab\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab else fprintf(stdout, ":");\par
\tab\tab fprintf(stdout, ":%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", \par
\tab\tab\tab pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],\par
\tab\tab\tab pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],\par
\tab\tab\tab pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],\par
\tab\tab\tab pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);\par
\tab\tab if(pskptr != NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s", pskptr);\par
\tab\tab\tab else\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab\tab for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);\par
\tab\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab fprintf(stdout, "\\n");\par
\tab\tab\}\par
\tab return;\par
\tab\}\par
else if(keyver == 1)\par
\tab\{\par
\tab memset(&pkedata, 0, sizeof(pkedata));\par
\tab memset(&testptk, 0, sizeof(testptk));\par
\tab memset(&testmic, 0, sizeof(testptk));\par
\tab pkeptr = pkedata;\par
\tab memcpy(pkeptr, "Pairwise key expansion", 23);\par
\tab if(memcmp(zeiger->ap, zeiger->client, 6) < 0)\par
\tab\tab\{\par
\tab\tab memcpy(pkeptr +23, zeiger->ap, 6);\par
\tab\tab memcpy(pkeptr +29, zeiger->client, 6);\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab memcpy(pkeptr +23, zeiger->client, 6);\par
\tab\tab memcpy(pkeptr +29, zeiger->ap, 6);\par
\tab\tab\}\par
\tab if(memcmp(zeiger->nonce, wpak->nonce, 32) < 0)\par
\tab\tab\{\par
\tab\tab memcpy (pkeptr +35, zeiger->nonce, 32);\par
\tab\tab memcpy (pkeptr +67, wpak->nonce, 32);\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab memcpy (pkeptr +35, wpak->nonce, 32);\par
\tab\tab memcpy (pkeptr +67, zeiger->nonce, 32);\par
\tab\tab\}\par
\tab testptklen = 32;\par
\tab mdctx = EVP_MD_CTX_new();\par
\tab if(mdctx == 0) return;\par
\tab pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);\par
\tab if(pkey == NULL)\par
\tab\tab\{\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignUpdate(mdctx, pkedata, 100) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_reset(mdctx);\par
\tab testmiclen = 16;\par
\tab pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testptk, 16);\par
\tab if(pkey == NULL)\par
\tab\tab\{\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignInit(mdctx, NULL, EVP_md5(), NULL, pkey) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignUpdate(mdctx, zeiger->eapol, zeiger->eapauthlen) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignFinal(mdctx, testmic, &testmiclen) <= 0)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_free(mdctx);\par
\tab if(memcmp(zeiger->hash, &testmic, 16) == 0)\par
\tab\tab\{\par
\tab\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->client[p]);\par
\tab\tab fprintf(stdout, ":");\par
\tab\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->ap[p]);\par
\tab\tab if(zeiger->essidlen != 0)\par
\tab\tab\tab\{\par
\tab\tab\tab if(ispotfilestring(zeiger->essidlen, (char*)zeiger->essid) == true) fprintf(stdout, ":%.*s", zeiger->essidlen, zeiger->essid);\par
\tab\tab\tab else\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab\tab for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);\par
\tab\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab else fprintf(stdout, ":");\par
\tab\tab fprintf(stdout, ":%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", \par
\tab\tab\tab pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],\par
\tab\tab\tab pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],\par
\tab\tab\tab pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],\par
\tab\tab\tab pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);\par
\tab\tab if(pskptr != NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s", pskptr);\par
\tab\tab\tab else\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab\tab for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);\par
\tab\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab fprintf(stdout, "\\n");\par
\tab\tab\}\par
\tab return;\par
\tab\}\par
else if(keyver == 3)\par
\tab\{\par
\tab memset(&pkedata, 0, sizeof(pkedata));\par
\tab memset(&testptk, 0, sizeof(testptk));\par
\tab memset(&testmic, 0, sizeof(testptk));\par
\tab pkedata[0] = 1;\par
\tab pkedata[1] = 0;\par
\tab pkeptr = pkedata +2;\par
\tab memcpy(pkeptr, "Pairwise key expansion", 22);\par
\tab if(memcmp(zeiger->ap, zeiger->client, 6) < 0)\par
\tab\tab\{\par
\tab\tab memcpy(pkeptr +22, zeiger->ap, 6);\par
\tab\tab memcpy(pkeptr +28, zeiger->client, 6);\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab memcpy(pkeptr +22, zeiger->client, 6);\par
\tab\tab memcpy(pkeptr +28, zeiger->ap, 6);\par
\tab\tab\}\par
\tab if(memcmp(zeiger->nonce, wpak->nonce, 32) < 0)\par
\tab\tab\{\par
\tab\tab memcpy (pkeptr +34, zeiger->nonce, 32);\par
\tab\tab memcpy (pkeptr +66, wpak->nonce, 32);\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab memcpy (pkeptr +34, wpak->nonce, 32);\par
\tab\tab memcpy (pkeptr +66, zeiger->nonce, 32);\par
\tab\tab\}\par
\tab pkedata[100] = 0x80;\par
\tab pkedata[101] = 1;\par
\tab testptklen = 32;\par
\tab mdctx = EVP_MD_CTX_new();\par
\tab if(mdctx == 0) return;\par
\tab pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);\par
\tab if(pkey == NULL)\par
\tab\tab\{\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignUpdate(mdctx, pkedata, 102) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_reset(mdctx);\par
\tab testmiclen = 16;\par
\tab pkey = EVP_PKEY_new_CMAC_key(NULL, testptk, 16, EVP_aes_128_cbc());\par
\tab if(pkey == NULL)\par
\tab\tab\{\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignUpdate(mdctx, zeiger->eapol, zeiger->eapauthlen) != 1)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab if(EVP_DigestSignFinal(mdctx, testmic, &testmiclen) <= 0)\par
\tab\tab\{\par
\tab\tab EVP_PKEY_free(pkey);\par
\tab\tab EVP_MD_CTX_free(mdctx);\par
\tab\tab return;\par
\tab\tab\}\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_free(mdctx);\par
\tab if(memcmp(zeiger->hash, &testmic, 16) == 0)\par
\tab\tab\{\par
\tab\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->client[p]);\par
\tab\tab fprintf(stdout, ":");\par
\tab\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->ap[p]);\par
\tab\tab if(zeiger->essidlen != 0)\par
\tab\tab\tab\{\par
\tab\tab\tab if(ispotfilestring(zeiger->essidlen, (char*)zeiger->essid) == true) fprintf(stdout, ":%.*s", zeiger->essidlen, zeiger->essid);\par
\tab\tab\tab else\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab\tab for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);\par
\tab\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab else fprintf(stdout, ":");\par
\tab\tab fprintf(stdout, ":%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", \par
\tab\tab\tab pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],\par
\tab\tab\tab pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],\par
\tab\tab\tab pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],\par
\tab\tab\tab pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);\par
\tab\tab if(pskptr != NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s", pskptr);\par
\tab\tab\tab else\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab\tab for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);\par
\tab\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab fprintf(stdout, "\\n");\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void testpmkidpmk(hashlist_t *zeiger)\par
\{\par
static int p;\par
static size_t testpmkidlen;\par
static EVP_MD_CTX *mdctx;\par
static EVP_PKEY *pkey;\par
static char *pmkname = "PMK Name";\par
\par
static uint8_t message[32];\par
static uint8_t testpmkid[EVP_MAX_MD_SIZE];\par
\par
memcpy(&message, pmkname, 8);\par
memcpy(&message[8], zeiger->ap, 6);\par
memcpy(&message[14], zeiger->client, 6);\par
testpmkidlen = 16;\par
mdctx = EVP_MD_CTX_new();\par
if(mdctx == 0) return;\par
pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);\par
if(pkey == NULL)\par
\tab\{\par
\tab EVP_MD_CTX_free(mdctx);\par
\tab return;\par
\tab\}\par
if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)\par
\tab\{\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_free(mdctx);\par
\tab return;\par
\tab\}\par
if(EVP_DigestSignUpdate(mdctx, message, 20) != 1)\par
\tab\{\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_free(mdctx);\par
\tab return;\par
\tab\}\par
if(EVP_DigestSignFinal(mdctx, testpmkid, &testpmkidlen) <= 0)\par
\tab\{\par
\tab EVP_PKEY_free(pkey);\par
\tab EVP_MD_CTX_free(mdctx);\par
\tab return;\par
\tab\}\par
EVP_PKEY_free(pkey);\par
EVP_MD_CTX_free(mdctx);\par
if(memcmp(&testpmkid, zeiger->hash, 16) == 0)\par
\tab\{\par
\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->client[p]);\par
\tab fprintf(stdout, ":");\par
\tab for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->ap[p]);\par
\tab if(zeiger->essidlen != 0)\par
\tab\tab\{\par
\tab\tab if(ispotfilestring(zeiger->essidlen, (char*)zeiger->essid) == true) fprintf(stdout, ":%.*s", zeiger->essidlen, zeiger->essid);\par
\tab\tab else\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);\par
\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\}\par
\tab\tab\}\par
\tab else fprintf(stdout, ":");\par
\tab fprintf(stdout, ":%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", \par
\tab\tab pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],\par
\tab\tab pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],\par
\tab\tab pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],\par
\tab\tab pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);\par
\tab if(pskptr != NULL)\par
\tab\tab\{\par
\tab\tab if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s", pskptr);\par
\tab\tab else\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stdout, ":$HEX[");\par
\tab\tab\tab for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);\par
\tab\tab\tab fprintf(stdout, "]");\par
\tab\tab\tab\}\par
\tab\tab\}\par
\tab fprintf(stdout, "\\n");\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void testhashfilepmk()\par
\{\par
static hashlist_t *zeiger;\par
\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab if(zeiger->type == HCX_TYPE_PMKID) testpmkidpmk(zeiger);\par
\tab else if (zeiger->type == HCX_TYPE_EAPOL) testeapolpmk(zeiger);\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static bool dopbkdf2(int psklen, char *psk, int essidlen, uint8_t *essid)\par
\{\par
if(PKCS5_PBKDF2_HMAC_SHA1(psk, psklen, essid, essidlen, 4096, 32, pmk) == 0) return false;\par
return true;\par
\}\par
/*===========================================================================*/\par
static void testhashfilepsk()\par
\{\par
static hashlist_t *zeiger, *zeigerold;\par
\par
zeigerold = hashlist;\par
if(dopbkdf2(pskptrlen, pskptr, zeigerold->essidlen, zeigerold->essid) == true)\par
\tab\{\par
\tab if(zeigerold->type == HCX_TYPE_PMKID) testpmkidpmk(zeigerold);\par
\tab if(zeigerold->type == HCX_TYPE_EAPOL) testeapolpmk(zeigerold);\par
\tab\}\par
for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab if((zeigerold->essidlen == zeiger->essidlen) && (memcmp(zeigerold->essid, zeiger->essid, zeigerold->essidlen) == 0))\par
\tab\tab\{\par
\tab\tab if(zeiger->type == HCX_TYPE_PMKID) testpmkidpmk(zeiger);\par
\tab\tab if(zeiger->type == HCX_TYPE_EAPOL) testeapolpmk(zeiger);\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab if(dopbkdf2(pskptrlen, pskptr, zeiger->essidlen, zeiger->essid) == true)\par
\tab\tab\tab\{\par
\tab\tab\tab if(zeiger->type == HCX_TYPE_PMKID) testpmkidpmk(zeiger);\par
\tab\tab\tab if(zeiger->type == HCX_TYPE_EAPOL) testeapolpmk(zeiger);\par
\tab\tab\tab\}\par
\tab\tab\}\par
\tab zeigerold = zeiger;\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static bool isoui(uint8_t *mac)\par
\{\par
static ouilist_t *zeiger;\par
\par
for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++)\par
\tab\{\par
\tab if(memcmp(mac, zeiger->oui, 3) == 0) return true;\par
\tab\}\par
return false;\par
\}\par
/*===========================================================================*/\par
static bool ispartof(int plen, uint8_t *pbuff, int slen, uint8_t *sbuff)\par
\{\par
static int p;\par
if(plen > slen) return false;\par
\par
for(p = 0; p <= slen -plen; p++)\par
\tab\{\par
\tab if(memcmp(&sbuff[p], pbuff, plen) == 0) return true;\par
\tab\}\par
return false;\par
\}\par
/*===========================================================================*/\par
static void hccap2base(unsigned char *in, unsigned char b, FILE *fh_john)\par
\{\par
static const char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";\par
\par
fprintf(fh_john, "%c", (itoa64[in[0] >> 2]));\par
fprintf(fh_john, "%c", (itoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)]));\par
if(b)\par
\tab\{\par
\tab fprintf(fh_john, "%c", (itoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)]));\par
\tab fprintf(fh_john, "%c", (itoa64[in[2] & 0x3f]));\par
\tab\}\par
else fprintf(fh_john, "%c", (itoa64[((in[1] & 0x0f) << 2)]));\par
return;\par
\}\par
/*===========================================================================*/\par
static void writejohnrecord(FILE *fh_john, hashlist_t *zeiger)\par
\{\par
struct hccap_s\par
\{\par
  char essid[36];\par
  unsigned char ap[6];\par
  unsigned char client[6];\par
  unsigned char snonce[32];\par
  unsigned char anonce[32];\par
  unsigned char eapol[256];\par
  int eapol_size;\par
  int keyver;\par
  unsigned char keymic[16];\par
\};\par
typedef struct hccap_s hccap_t;\par
#define\tab HCCAP_SIZE (sizeof(hccap_t))\par
\par
static wpakey_t *wpak;\par
static int i;\par
static unsigned char *hcpos;\par
static hccap_t hccap;\par
\par
if(zeiger->type == HCX_TYPE_PMKID) return;\par
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;\par
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;\par
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;\par
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;\par
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;\par
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;\par
if(filteressidptr != NULL)\par
\tab\{\par
\tab if(zeiger->essidlen != filteressidlen) return;\par
\tab if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;\par
\tab\}\par
if(filteressidpartptr != NULL)\par
\tab\{\par
\tab if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;\par
\tab\}\par
if(filtervendorptr != 0)\par
\tab\{\par
\tab if(isoui(zeiger->ap) == false) return;\par
\tab\}\par
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;\par
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;\par
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;\par
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;\par
\par
wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);\par
memset(&hccap, 0, sizeof(hccap_t));\par
memcpy(&hccap.essid, zeiger->essid, zeiger->essidlen);\par
memcpy(&hccap.ap, zeiger->ap, 6);\par
memcpy(&hccap.client, zeiger->client, 6);\par
memcpy(&hccap.anonce, zeiger->nonce, 32);\par
memcpy(&hccap.snonce, wpak->nonce, 32);\par
memcpy(&hccap.keymic, zeiger->hash, 16);\par
hccap.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;\par
hccap.eapol_size = zeiger->eapauthlen;\par
memcpy(&hccap.eapol, zeiger->eapol, zeiger->eapauthlen);\par
#ifdef BIG_ENDIAN_HOST\par
hccap.eapol_size = byte_swap_16(hccap.eapol_size);\par
#endif\par
\par
fprintf(fh_john, "%.*s:$WPAPSK$%.*s#", zeiger->essidlen, zeiger->essid, zeiger->essidlen, zeiger->essid);\par
hcpos = (unsigned char*)&hccap;\par
for (i = 36; i + 3 < (int)HCCAP_SIZE; i += 3) hccap2base(&hcpos[i], 1, fh_john);\par
hccap2base(&hcpos[i], 0, fh_john);\par
fprintf(fh_john, ":%02x-%02x-%02x-%02x-%02x-%02x:%02x-%02x-%02x-%02x-%02x-%02x:%02x%02x%02x%02x%02x%02x",\par
zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],\par
zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],\par
zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5]);\par
if(hccap.keyver == 1) fprintf(fh_john, "::WPA");\par
else fprintf(fh_john, "::WPA2");\par
if((zeiger->mp &0x7) == 0) fprintf(fh_john, ":not verified");\par
else fprintf(fh_john, ":verified");\par
fprintf(fh_john, ":converted by hcxhastool\\n");\par
johnwrittencount++;\par
return;\par
\}\par
/*===========================================================================*/\par
static void writejohnfile(char *johnoutname)\par
\{\par
static FILE *fh_john;\par
static hashlist_t *zeiger;\par
static struct stat statinfo;\par
\par
if(johnoutname != NULL)\par
\tab\{\par
\tab if((fh_john = fopen(johnoutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", johnoutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab\}\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writejohnrecord(fh_john, zeiger);\par
if(fh_john != NULL) fclose(fh_john);\par
if(johnoutname != NULL)\par
\tab\{\par
\tab if(stat(johnoutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(johnoutname);\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writehccaprecord(FILE *fh_hccap, hashlist_t *zeiger)\par
\{\par
struct hccap_s\par
\{\par
  char essid[36];\par
  unsigned char ap[6];\par
  unsigned char client[6];\par
  unsigned char snonce[32];\par
  unsigned char anonce[32];\par
  unsigned char eapol[256];\par
  int eapol_size;\par
  int keyver;\par
  unsigned char keymic[16];\par
\};\par
typedef struct hccap_s hccap_t;\par
#define\tab HCCAP_SIZE (sizeof(hccap_t))\par
\par
static wpakey_t *wpak;\par
static hccap_t hccap;\par
\par
if(zeiger->type == HCX_TYPE_PMKID) return;\par
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;\par
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;\par
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;\par
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;\par
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;\par
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;\par
if(filteressidptr != NULL)\par
\tab\{\par
\tab if(zeiger->essidlen != filteressidlen) return;\par
\tab if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;\par
\tab\}\par
if(filteressidpartptr != NULL)\par
\tab\{\par
\tab if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;\par
\tab\}\par
if(filtervendorptr != 0)\par
\tab\{\par
\tab if(isoui(zeiger->ap) == false) return;\par
\tab\}\par
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;\par
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;\par
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;\par
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;\par
\par
wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);\par
memset(&hccap, 0, sizeof(hccap_t));\par
memcpy(&hccap.essid, zeiger->essid, zeiger->essidlen);\par
memcpy(&hccap.ap, zeiger->ap, 6);\par
memcpy(&hccap.client, zeiger->client, 6);\par
memcpy(&hccap.anonce, zeiger->nonce, 32);\par
memcpy(&hccap.snonce, wpak->nonce, 32);\par
memcpy(&hccap.keymic, zeiger->hash, 16);\par
hccap.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;\par
hccap.eapol_size = zeiger->eapauthlen;\par
memcpy(&hccap.eapol, zeiger->eapol, zeiger->eapauthlen);\par
#ifdef BIG_ENDIAN_HOST\par
hccap.eapol_size = byte_swap_16(hccap.eapol_size);\par
#endif\par
fwrite(&hccap, HCCAP_SIZE, 1, fh_hccap);\par
hccapwrittencount++;\par
return;\par
\}\par
/*===========================================================================*/\par
static void writehccapsinglefile()\par
\{\par
static int c;\par
static FILE *fh_hccap;\par
static hashlist_t *zeiger;\par
static struct stat statinfo;\par
\par
static char groupoutname[PATH_MAX];\par
\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab c = 0;\par
\tab do\par
\tab\tab\{\par
\tab\tab snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x-%04d.hccap", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], c);\par
\tab\tab c++;\par
\tab\tab\}\par
\tab while (stat(groupoutname, &statinfo) == 0); \par
\tab if((fh_hccap = fopen(groupoutname, "a")) == NULL) continue;\par
\tab writehccaprecord(fh_hccap, zeiger);\par
\tab if(fh_hccap != NULL) fclose(fh_hccap);\par
\tab if(stat(groupoutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(groupoutname);\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writehccapfile(char *hccapoutname)\par
\{\par
static FILE *fh_hccap;\par
static hashlist_t *zeiger;\par
static struct stat statinfo;\par
\par
if(hccapoutname != NULL)\par
\tab\{\par
\tab if((fh_hccap = fopen(hccapoutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", hccapoutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab\}\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writehccaprecord(fh_hccap, zeiger);\par
if(fh_hccap != NULL) fclose(fh_hccap);\par
if(hccapoutname != NULL)\par
\tab\{\par
\tab if(stat(hccapoutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(hccapoutname);\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writehccapxrecord(FILE *fh_hccapx, hashlist_t *zeiger)\par
\{\par
struct hccapx_s\par
\{\par
 uint32_t\tab signature;\par
#define HCCAPX_SIGNATURE 0x58504348\par
 uint32_t\tab version;\par
#define HCCAPX_VERSION 4\par
 uint8_t\tab message_pair;\par
 uint8_t\tab essid_len;\par
 uint8_t\tab essid[32];\par
 uint8_t\tab keyver;\par
 uint8_t\tab keymic[16];\par
 uint8_t\tab ap[6];\par
 uint8_t\tab anonce[32];\par
 uint8_t\tab client[6];\par
 uint8_t\tab snonce[32];\par
 uint16_t\tab eapol_len;\par
 uint8_t\tab eapol[256];\par
\} __attribute__((packed));\par
typedef struct hccapx_s hccapx_t;\par
#define\tab HCCAPX_SIZE (sizeof(hccapx_t))\par
\par
static wpakey_t *wpak;\par
static hccapx_t hccapx;\par
\par
if(zeiger->type == HCX_TYPE_PMKID) return;\par
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;\par
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;\par
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;\par
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;\par
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;\par
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;\par
if(filteressidptr != NULL)\par
\tab\{\par
\tab if(zeiger->essidlen != filteressidlen) return;\par
\tab if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;\par
\tab\}\par
if(filteressidpartptr != NULL)\par
\tab\{\par
\tab if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;\par
\tab\}\par
if(filtervendorptr != 0)\par
\tab\{\par
\tab if(isoui(zeiger->ap) == false) return;\par
\tab\}\par
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;\par
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;\par
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;\par
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;\par
\par
wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);\par
memset (&hccapx, 0, sizeof(hccapx_t));\par
hccapx.signature = HCCAPX_SIGNATURE;\par
hccapx.version = HCCAPX_VERSION;\par
hccapx.message_pair = zeiger->mp;\par
hccapx.essid_len = zeiger->essidlen;\par
memcpy(&hccapx.essid, zeiger->essid, zeiger->essidlen);\par
memcpy(&hccapx.ap, zeiger->ap, 6);\par
memcpy(&hccapx.client, zeiger->client, 6);\par
memcpy(&hccapx.anonce, zeiger->nonce, 32);\par
memcpy(&hccapx.snonce, wpak->nonce, 32);\par
hccapx.eapol_len = zeiger->eapauthlen;\par
memcpy(&hccapx.eapol, zeiger->eapol, zeiger->eapauthlen);\par
hccapx.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;\par
memcpy(&hccapx.keymic, zeiger->hash, 16);\par
#ifdef BIG_ENDIAN_HOST\par
hccapx.signature = byte_swap_32(hccapx.signature);\par
hccapx.version = byte_swap_32(hccapx.version);\par
hccapx.eapol_len = byte_swap_16(hccapx.eapol_len);\par
#endif\par
fwrite (&hccapx, sizeof(hccapx_t), 1, fh_hccapx);\par
hccapxwrittencount++;\par
return;\par
\}\par
/*===========================================================================*/\par
static void writehccapxfile(char *hccapxoutname)\par
\{\par
static FILE *fh_hccapx;\par
static hashlist_t *zeiger;\par
static struct stat statinfo;\par
\par
if(hccapxoutname != NULL)\par
\tab\{\par
\tab if((fh_hccapx = fopen(hccapxoutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", hccapxoutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab\}\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writehccapxrecord(fh_hccapx, zeiger);\par
if(fh_hccapx != NULL) fclose(fh_hccapx);\par
if(hccapxoutname != NULL)\par
\tab\{\par
\tab if(stat(hccapxoutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(hccapxoutname);\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void processessid(char *essidoutname)\par
\{\par
static long int pc;\par
static hashlist_t *zeiger, *zeigerold;\par
static FILE *fh_essid;\par
static struct stat statinfo;\par
\par
if((fh_essid = fopen(essidoutname, "a")) == NULL)\par
\tab\{\par
\tab printf("error opening file %s: %s\\n", essidoutname, strerror(errno));\par
\tab return;\par
\tab\}\par
zeigerold = NULL;\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);\par
for(pc = 0; pc < pmkideapolcount; pc++)\par
\tab\{\par
\tab zeiger = hashlist +pc;\par
\tab if(zeigerold != NULL)\par
\tab\tab\{\par
\tab\tab if(memcmp(zeiger->essid, zeigerold->essid, ESSID_LEN_MAX) == 0) continue;\par
\tab\tab\}\par
\tab fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_essid);\par
\tab essidwrittencount++;\par
\tab zeigerold = zeiger;\par
\tab\}\par
fclose(fh_essid);\par
if(stat(essidoutname, &statinfo) == 0)\par
\tab\{\par
\tab if(statinfo.st_size == 0) remove(essidoutname);\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writepmkideapolhashline(FILE *fh_pmkideapol, hashlist_t *zeiger)\par
\{\par
static int p;\par
\par
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;\par
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;\par
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;\par
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;\par
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;\par
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;\par
if(filteressidptr != NULL)\par
\tab\{\par
\tab if(zeiger->essidlen != filteressidlen) return;\par
\tab if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;\par
\tab\}\par
if(filteressidpartptr != NULL)\par
\tab\{\par
\tab if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;\par
\tab\}\par
if(filtervendorptr != 0)\par
\tab\{\par
\tab if(isoui(zeiger->ap) == false) return;\par
\tab\}\par
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;\par
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x00)) return;\par
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;\par
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;\par
if(zeiger->type == HCX_TYPE_PMKID)\par
\tab\{\par
\tab fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",\par
\tab\tab zeiger->type,\par
\tab\tab zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],\par
\tab\tab zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15],\par
\tab\tab zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],\par
\tab\tab zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);\par
\tab for(p = 0; p < zeiger->essidlen; p++) fprintf(fh_pmkideapol, "%02x", zeiger->essid[p]);\par
\tab fprintf(fh_pmkideapol, "***\\n");\par
\tab pmkidwrittencount++;\par
\tab return;\par
\tab\}\par
if(zeiger->type == HCX_TYPE_EAPOL)\par
\tab\{\par
\tab fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",\par
\tab\tab zeiger->type,\par
\tab\tab zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],\par
\tab\tab zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15],\par
\tab\tab zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],\par
\tab\tab zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);\par
\tab for(p = 0; p < zeiger->essidlen; p++) fprintf(fh_pmkideapol, "%02x", zeiger->essid[p]);\par
\tab fprintf(fh_pmkideapol, "*");\par
\tab fprintf(fh_pmkideapol, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*",\par
\tab\tab zeiger->nonce[0], zeiger->nonce[1], zeiger->nonce[2], zeiger->nonce[3], zeiger->nonce[4], zeiger->nonce[5], zeiger->nonce[6], zeiger->nonce[7],\par
\tab\tab zeiger->nonce[8], zeiger->nonce[9], zeiger->nonce[10], zeiger->nonce[11], zeiger->nonce[12], zeiger->nonce[13], zeiger->nonce[14], zeiger->nonce[15],\par
\tab\tab zeiger->nonce[16], zeiger->nonce[17], zeiger->nonce[18], zeiger->nonce[19], zeiger->nonce[20], zeiger->nonce[21], zeiger->nonce[22], zeiger->nonce[23],\par
\tab\tab zeiger->nonce[24], zeiger->nonce[25], zeiger->nonce[26], zeiger->nonce[27], zeiger->nonce[28], zeiger->nonce[29], zeiger->nonce[30], zeiger->nonce[31]);\par
\tab for(p = 0; p < zeiger->eapauthlen; p++) fprintf(fh_pmkideapol, "%02x", zeiger->eapol[p]);\par
\tab fprintf(fh_pmkideapol, "*%02x\\n", zeiger->mp);\par
\tab eapolwrittencount++;\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writeeapolpmkidessidgroups()\par
\{\par
static int cei;\par
static int ceo;\par
static hashlist_t *zeiger;\par
static FILE *fh_pmkideapol;\par
static struct stat statinfo;\par
\par
static const char digit[16] = \{'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'\};\par
\par
static char groupoutname[PATH_MAX];\par
\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab groupoutname[0] = 0;\par
\tab if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) continue;\par
\tab if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) continue;\par
\tab ceo = 0;\par
\tab for (cei = 0; cei < zeiger->essidlen; cei++)\par
\tab\tab\{\par
\tab\tab groupoutname[ceo] = digit[(zeiger->essid[cei] & 0xff) >> 4];\par
\tab\tab ceo++;\par
\tab\tab groupoutname[ceo] = digit[zeiger->essid[cei] & 0x0f];\par
\tab\tab ceo++;\par
\tab\tab\}\par
\tab groupoutname[ceo] = 0;\par
\tab strcat(&groupoutname[ceo], ".22000");\par
\tab if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", groupoutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab writepmkideapolhashline(fh_pmkideapol, zeiger);\par
\tab if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
\tab if(groupoutname[0] != 0)\par
\tab\tab\{\par
\tab\tab if(stat(groupoutname, &statinfo) == 0)\par
\tab\tab\tab\{\par
\tab\tab\tab if(statinfo.st_size == 0) remove(groupoutname);\par
\tab\tab\tab\}\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writeeapolpmkidouigroups()\par
\{\par
static hashlist_t *zeiger;\par
static FILE *fh_pmkideapol;\par
static struct stat statinfo;\par
\par
static char groupoutname[PATH_MAX];\par
\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x.22000", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2]);\par
\tab if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", groupoutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab writepmkideapolhashline(fh_pmkideapol, zeiger);\par
\tab if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
\tab if(groupoutname[0] != 0)\par
\tab\tab\{\par
\tab\tab if(stat(groupoutname, &statinfo) == 0)\par
\tab\tab\tab\{\par
\tab\tab\tab if(statinfo.st_size == 0) remove(groupoutname);\par
\tab\tab\tab\}\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writeeapolpmkidmacapgroups()\par
\{\par
static hashlist_t *zeiger;\par
static FILE *fh_pmkideapol;\par
static struct stat statinfo;\par
\par
static char groupoutname[PATH_MAX];\par
\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x.22000", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5]);\par
\tab if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", groupoutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab writepmkideapolhashline(fh_pmkideapol, zeiger);\par
\tab if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
\tab if(groupoutname[0] != 0)\par
\tab\tab\{\par
\tab\tab if(stat(groupoutname, &statinfo) == 0)\par
\tab\tab\tab\{\par
\tab\tab\tab if(statinfo.st_size == 0) remove(groupoutname);\par
\tab\tab\tab\}\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writeeapolpmkidmacclientgroups()\par
\{\par
static hashlist_t *zeiger;\par
static FILE *fh_pmkideapol;\par
static struct stat statinfo;\par
\par
static char groupoutname[PATH_MAX];\par
\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x.22000", zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);\par
\tab if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", groupoutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab writepmkideapolhashline(fh_pmkideapol, zeiger);\par
\tab if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
\tab if(groupoutname[0] != 0)\par
\tab\tab\{\par
\tab\tab if(stat(groupoutname, &statinfo) == 0)\par
\tab\tab\tab\{\par
\tab\tab\tab if(statinfo.st_size == 0) remove(groupoutname);\par
\tab\tab\tab\}\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writelceapolpmkidfile(char *pmkideapoloutname, long int lcmin, long int lcmax)\par
\{\par
static long int lc;\par
static FILE *fh_pmkideapol;\par
static hashlist_t *zeiger;\par
static hashlist_t *zeiger2;\par
static hashlist_t *zeigerbegin;\par
static hashlist_t *zeigerend;\par
static struct stat statinfo;\par
\par
if(lcmax == 0) lcmax = pmkideapolcount;\par
if(lcmin > lcmax) return;\par
\par
if(pmkideapoloutname != NULL)\par
\tab\{\par
\tab if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", pmkideapoloutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab\}\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);\par
\par
zeigerbegin = hashlist;\par
lc = 0;\par
for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)\par
\tab\{\par
\tab if(memcmp(zeigerbegin->essid, zeiger->essid, ESSID_LEN_MAX) == 0)\par
\tab\tab\{\par
\tab\tab zeigerend = zeiger;\par
\tab\tab lc++;\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab if(((zeigerend -zeigerbegin) >= lcmin) && ((zeigerend -zeigerbegin) <= lcmax))\par
\tab\tab\tab\{\par
\tab\tab\tab for(zeiger2 = zeigerbegin; zeiger2 <= zeigerend; zeiger2++) writepmkideapolhashline(fh_pmkideapol, zeiger2);\par
\tab\tab\tab\}\par
\tab\tab lc = 0;\par
\tab\tab zeigerbegin = zeiger;\par
\tab\tab\}\par
\tab\}\par
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
if(pmkideapoloutname != NULL)\par
\tab\{\par
\tab if(stat(pmkideapoloutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(pmkideapoloutname);\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writeeapolpmkidfile(char *pmkideapoloutname)\par
\{\par
static FILE *fh_pmkideapol;\par
static hashlist_t *zeiger;\par
static struct stat statinfo;\par
\par
if(pmkideapoloutname != NULL)\par
\tab\{\par
\tab if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", pmkideapoloutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab\}\par
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writepmkideapolhashline(fh_pmkideapol, zeiger);\par
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
if(pmkideapoloutname != NULL)\par
\tab\{\par
\tab if(stat(pmkideapoloutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(pmkideapoloutname);\par
\tab\tab\}\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static void writepmkideapolhashlineinfo(FILE *fh_pmkideapol, hashlist_t *zeiger)\par
\{\par
static eapauth_t *eapa;\par
static wpakey_t *wpak;\par
static uint8_t keyver;\par
static uint64_t rc;\par
static char *vendor;\par
\par
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;\par
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;\par
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;\par
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;\par
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;\par
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;\par
if(filteressidptr != NULL)\par
\tab\{\par
\tab if(zeiger->essidlen != filteressidlen) return;\par
\tab if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;\par
\tab\}\par
if(filteressidpartptr != NULL)\par
\tab\{\par
\tab if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;\par
\tab\}\par
if(filtervendorptr != 0)\par
\tab\{\par
\tab if(isoui(zeiger->ap) == false) return;\par
\tab\}\par
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;\par
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x00)) return;\par
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;\par
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;\par
\par
fprintf(fh_pmkideapol, "SSID.......: %.*s\\n", zeiger->essidlen, zeiger->essid);\par
vendor = getvendor(zeiger->ap);\par
fprintf(fh_pmkideapol, "MAC_AP.....: %02x%02x%02x%02x%02x%02x (%s)\\n", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], vendor);\par
vendor = getvendor(zeiger->client);\par
fprintf(fh_pmkideapol, "MAC_CLIENT.: %02x%02x%02x%02x%02x%02x (%s)\\n", zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5], vendor);\par
if(zeiger->type == HCX_TYPE_PMKID)\par
\tab\{\par
\tab fprintf(fh_pmkideapol, "PMKID......: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\\n",\par
\tab\tab zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],\par
\tab\tab zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15]);\par
\tab\}\par
if(zeiger->type == HCX_TYPE_EAPOL)\par
\tab\{\par
\tab eapa = (eapauth_t*)zeiger->eapol;\par
\tab wpak = (wpakey_t*)&zeiger->eapol[EAPAUTH_SIZE];\par
\tab if(eapa->version == 1) fprintf(fh_pmkideapol, "VERSION....: 802.1X-2001 (1)\\n");\par
\tab if(eapa->version == 2) fprintf(fh_pmkideapol, "VERSION....: 802.1X-2004 (2)\\n");\par
\tab keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;\par
\tab if(keyver == 1) fprintf(fh_pmkideapol, "KEY VERSION: WPA1\\n");\par
\tab if(keyver == 2) fprintf(fh_pmkideapol, "KEY VERSION: WPA2\\n");\par
\tab if(keyver == 3) fprintf(fh_pmkideapol, "KEY VERSION: WPA2 key version 3\\n");\par
\tab #ifndef BIG_ENDIAN_HOST\par
\tab rc = byte_swap_64(wpak->replaycount);\par
\tab #else\par
\tab rc = wpak->replaycount;\par
\tab #endif\par
\tab fprintf(fh_pmkideapol, "REPLAYCOUNT: %" PRIu64 "\\n", rc);\par
\tab if((zeiger->mp & 0x10) == 0x10) fprintf(fh_pmkideapol, "RC INFO....: ROGUE attack / NC not required\\n");\par
\tab else if((zeiger->mp & 0x80) == 0x00) fprintf(fh_pmkideapol, "RC INFO....: NC not required\\n");\par
\tab else if((zeiger->mp & 0x80) == 0x80) fprintf(fh_pmkideapol, "RC INFO....: NC suggested\\n");\par
\tab if((zeiger->mp & 0xe0) == 0x20) fprintf(fh_pmkideapol, "RC INFO....: little endian router / NC LE suggested\\n");\par
\tab if((zeiger->mp & 0xe0) == 0x40) fprintf(fh_pmkideapol, "RC INFO....: big endian router / NC BE suggested\\n");\par
\tab if((zeiger->mp & 0x07) == 0x00) fprintf(fh_pmkideapol, "MP M1M2 E2.: challenge\\n");\par
\tab if((zeiger->mp & 0x07) == 0x01) fprintf(fh_pmkideapol, "MP M1M4 E4.: authorized\\n");\par
\tab if((zeiger->mp & 0x07) == 0x02) fprintf(fh_pmkideapol, "MP M2M3 E2.: authorized\\n");\par
\tab if((zeiger->mp & 0x07) == 0x03) fprintf(fh_pmkideapol, "MP M2M3 E3.: authorized\\n");\par
\tab if((zeiger->mp & 0x07) == 0x04) fprintf(fh_pmkideapol, "MP M3M4 E3.: authorized\\n");\par
\tab if((zeiger->mp & 0x07) == 0x05) fprintf(fh_pmkideapol, "MP M3M4 E4.: authorized\\n");\par
\tab fprintf(fh_pmkideapol, "MIC........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\\n",\par
\tab\tab zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],\par
\tab\tab zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15]);\par
\tab\}\par
fprintf(fh_pmkideapol, "HASHLINE...: ");\par
writepmkideapolhashline(fh_pmkideapol, zeiger);\par
fprintf(fh_pmkideapol, "\\n");\par
return;\par
\}\par
/*===========================================================================*/\par
static void writeinfofile(char *infooutname)\par
\{\par
static hashlist_t *zeiger;\par
static FILE *fh_info;\par
\par
if(strcmp(infooutname, "stdout") != 0)\par
\tab\{\par
\tab if((fh_info = fopen(infooutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", infooutname, strerror(errno));\par
\tab\tab return;\par
\tab\tab\}\par
\tab for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writepmkideapolhashlineinfo(fh_info, zeiger);\par
\tab fclose(fh_info);\par
\tab\}\par
else\par
\tab\{\par
\tab for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writepmkideapolhashlineinfo(stdout, zeiger);\par
\tab\}\par
return;\par
\}\par
/*===========================================================================*/\par
static uint16_t getfield(char *lineptr, size_t bufflen, uint8_t *buff)\par
\{\par
static size_t p;\par
static uint8_t idx0;\par
static uint8_t idx1;\par
\par
static const uint8_t hashmap[] =\par
\{\par
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567\par
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?\par
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG\par
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO\par
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW\par
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\\]^_\par
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg\par
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno\par
\};\par
\par
memset(buff, 0, bufflen);\par
p = 0;\par
while((lineptr[p] != '*') && (lineptr[p] != 0) && (p /2 <= bufflen))\par
\tab\{\par
\tab if(!isxdigit(lineptr[p +0])) return 0;\par
\tab if(!isxdigit(lineptr[p +1])) return 0;\par
\tab if((lineptr[p +1] == '*') && (lineptr[p +1] == 0)) return 0;\par
\tab idx0 = ((uint8_t)lineptr[p +0] &0x1F) ^0x10;\par
\tab idx1 = ((uint8_t)lineptr[p +1] &0x1F) ^0x10;\par
\tab buff[p /2] = (uint8_t)(hashmap[idx0] <<4) | hashmap[idx1];\par
\tab p += 2;\par
\tab if((p /2) > PMKIDEAPOL_BUFFER_LEN) return 0;\par
\tab\}\par
return p /2;\par
\}\par
/*===========================================================================*/\par
static size_t chop(char *buffer, size_t len)\par
\{\par
static char *ptr;\par
\par
ptr = buffer +len -1;\par
while(len)\par
\tab\{\par
\tab if (*ptr != '\\n') break;\par
\tab *ptr-- = 0;\par
\tab len--;\par
\tab\}\par
while(len)\par
\tab\{\par
\tab if (*ptr != '\\r') break;\par
\tab *ptr-- = 0;\par
\tab len--;\par
\tab\}\par
return len;\par
\}\par
/*---------------------------------------------------------------------------*/\par
static int fgetline(FILE *inputstream, size_t size, char *buffer)\par
\{\par
static size_t len;\par
static char *buffptr;\par
\par
if(feof(inputstream)) return -1;\par
buffptr = fgets (buffer, size, inputstream);\par
if(buffptr == NULL) return -1;\par
len = strlen(buffptr);\par
len = chop(buffptr, len);\par
return len;\par
\}\par
/*===========================================================================*/\par
static void removepmkideapol(char *macskipname)\par
\{\par
static int len;\par
static int p1, p2;\par
static FILE *fh_maclistin;\par
static long int i, f, r;\par
\par
static int maclistskipcount, maclistskipmax;\par
static maclist_t *maclistskip, *zeiger, *maclistskipnew;\par
static hashlist_t *zeigerhash;\par
\par
static char linein[PMKIDEAPOL_BUFFER_LEN];\par
\par
maclistskipmax = 1000;\par
if((maclistskip = (maclist_t*)calloc(maclistskipmax, MACLIST_SIZE)) == NULL) return;\par
if((fh_maclistin = fopen(macskipname, "rb")) == NULL)\par
\tab\{\par
\tab printf("error opening file %s: %s\\n", macskipname, strerror(errno));\par
\tab return;\par
\tab\}\par
\par
zeiger = maclistskip;\par
maclistskipcount = 0;\par
while(1)\par
\tab\{\par
\tab if((len = fgetline(fh_maclistin, PMKIDEAPOL_BUFFER_LEN, linein)) == -1) break;\par
\tab if(len == 17)\par
\tab\tab\{\par
\tab\tab p2 = 0;\par
\tab\tab for(p1 = 0; p1 < 17; p1++)\par
\tab\tab\tab\{\par
\tab\tab\tab if(isxdigit(linein[p1]))\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab linein[p2] = linein[p1];\par
\tab\tab\tab\tab p2++;\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab linein[p2] = 0;\par
\tab\tab len = p2;\par
\tab\tab\}\par
\tab if(len != 12) continue;\par
\tab if(getfield(linein, 6, zeiger->mac) != 6) continue;\par
\tab maclistskipcount++;\par
\tab if(maclistskipcount >= maclistskipmax)\par
\tab\tab\{\par
\tab\tab maclistskipmax += 1000;\par
\tab\tab maclistskipnew = realloc(maclistskip, maclistskipmax *MACLIST_SIZE);\par
\tab\tab if(maclistskipnew == NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab printf("failed to allocate memory for internal list\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab maclistskip = maclistskipnew;\par
\tab\tab\}\par
\tab zeiger = maclistskip +maclistskipcount;\par
\tab\}\par
if(fh_maclistin != NULL) fclose(fh_maclistin);\par
qsort(maclistskip, maclistskipcount, MACLIST_SIZE, sort_maclistin);\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macap);\par
zeigerhash = hashlist;\par
zeiger = maclistskip;\par
f = 0;\par
r = 0;\par
for(i = 0; i < pmkideapolcount; i++)\par
\tab\{\par
\tab if(memcmp((zeigerhash +i)->ap, (zeiger +f)->mac, 6) > 0)\par
\tab while(f < maclistskipcount)\par
\tab\tab\{\par
\tab\tab if(memcmp((zeiger +f)->mac, (zeigerhash +i)->ap, 6) >= 0) break;\par
\tab\tab f++;\par
\tab\tab\}\par
\tab if(memcmp((zeigerhash +i)->ap, (zeiger +f)->mac, 6) == 0)\par
\tab\tab\{\par
\tab\tab (zeigerhash +i)->type = HS_REMOVED;\par
\tab\tab r++;\par
\tab\tab\}\par
\tab\}\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_type);\par
pmkidcount -= r;\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macclient);\par
zeigerhash = hashlist;\par
zeiger = maclistskip;\par
f = 0;\par
r = 0;\par
for(i = 0; i < pmkideapolcount; i++)\par
\tab\{\par
\tab if(memcmp((zeigerhash +i)->client, (zeiger +f)->mac, 6) > 0)\par
\tab while(f < maclistskipcount)\par
\tab\tab\{\par
\tab\tab if(memcmp((zeiger +f)->mac, (zeigerhash +i)->client, 6) >= 0) break;\par
\tab\tab f++;\par
\tab\tab\}\par
\tab if(memcmp((zeigerhash +i)->client, (zeiger +f)->mac, 6) == 0)\par
\tab\tab\{\par
\tab\tab (zeigerhash +i)->type = HS_REMOVED;\par
\tab\tab r++;\par
\tab\tab\}\par
\tab\}\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_type);\par
pmkidcount -= r;\par
if(maclistskip != NULL) free(maclistskip);\par
return;\par
\}\par
/*===========================================================================*/\par
static void processmacfile(char *maclistinname, char *pmkideapoloutname)\par
\{\par
static int len;\par
static int p1, p2;\par
static FILE *fh_maclistin;\par
static FILE *fh_pmkideapol;\par
static struct stat statinfo;\par
\par
static int maclistincount, maclistinmax;\par
static maclist_t *maclistin, *zeiger, *maclistinnew;\par
static hashlist_t *zeigerhash;\par
static int i, o;\par
\par
static char linein[PMKIDEAPOL_BUFFER_LEN];\par
\par
maclistinmax = 1000;\par
if((maclistin = (maclist_t*)calloc(maclistinmax, MACLIST_SIZE)) == NULL) return;\par
if((fh_maclistin = fopen(maclistinname, "rb")) == NULL)\par
\tab\{\par
\tab printf("error opening file %s: %s\\n", maclistinname, strerror(errno));\par
\tab return;\par
\tab\}\par
zeiger = maclistin;\par
maclistincount = 0;\par
while(1)\par
\tab\{\par
\tab if((len = fgetline(fh_maclistin, PMKIDEAPOL_BUFFER_LEN, linein)) == -1) break;\par
\tab if(len == 17)\par
\tab\tab\{\par
\tab\tab p2 = 0;\par
\tab\tab for(p1 = 0; p1 < 17; p1++)\par
\tab\tab\tab\{\par
\tab\tab\tab if(isxdigit(linein[p1]))\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab linein[p2] = linein[p1];\par
\tab\tab\tab\tab p2++;\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab linein[p2] = 0;\par
\tab\tab len = p2;\par
\tab\tab\}\par
\tab if(len != 12) continue;\par
\tab if(getfield(linein, 6, zeiger->mac) != 6) continue;\par
\tab maclistincount++;\par
\tab if(maclistincount >= maclistinmax)\par
\tab\tab\{\par
\tab\tab maclistinmax += 1000;\par
\tab\tab maclistinnew = realloc(maclistin, maclistinmax *MACLIST_SIZE);\par
\tab\tab if(maclistinnew == NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab printf("failed to allocate memory for internal list\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab maclistin = maclistinnew;\par
\tab\tab\}\par
\tab zeiger = maclistin +maclistincount;\par
\tab\}\par
if(fh_maclistin != NULL) fclose(fh_maclistin);\par
qsort(maclistin, maclistincount, MACLIST_SIZE, sort_maclistin);\par
\par
if(pmkideapoloutname != NULL)\par
\tab\{\par
\tab if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", pmkideapoloutname, strerror(errno));\par
\tab\tab free(maclistin);\par
\tab\tab return;\par
\tab\tab\}\par
\tab\}\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macap);\par
zeiger = maclistin;\par
zeigerhash = hashlist;\par
o = 0;\par
for(i = 0; i < maclistincount; i++)\par
\tab\{\par
\tab while(o < pmkideapolcount)\par
\tab\tab\{\par
\tab\tab if(memcmp((zeigerhash +o)->ap, (zeiger +i)->mac, 6) > 0) break;\par
\tab\tab if(memcmp((zeigerhash +o)->ap, (zeiger +i)->mac, 6) == 0) writepmkideapolhashline(fh_pmkideapol, zeigerhash +o);\par
\tab\tab o++;\par
\tab\tab\}\par
\tab\}\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macclient);\par
zeiger = maclistin;\par
zeigerhash = hashlist;\par
o = 0;\par
for(i = 0; i < maclistincount; i++)\par
\tab\{\par
\tab while(o < pmkideapolcount)\par
\tab\tab\{\par
\tab\tab if(memcmp((zeigerhash +o)->client, (zeiger +i)->mac, 6) > 0) break;\par
\tab\tab if(memcmp((zeigerhash +o)->client, (zeiger +i)->mac, 6) == 0) writepmkideapolhashline(fh_pmkideapol, zeigerhash +o);\par
\tab\tab o++;\par
\tab\tab\}\par
\tab\}\par
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
if(pmkideapoloutname != NULL)\par
\tab\{\par
\tab if(stat(pmkideapoloutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(pmkideapoloutname);\par
\tab\tab\}\par
\tab\}\par
if(maclistin != NULL) free(maclistin);\par
return;\par
\}\par
/*===========================================================================*/\par
static void processessidfile(char *essidlistinname, char *pmkideapoloutname)\par
\{\par
static int len;\par
static int i, o;\par
static FILE *fh_essidlistin;\par
static FILE *fh_pmkideapol;\par
static struct stat statinfo;\par
static int essidlistincount, essidlistinmax;\par
static essidlist_t *essidlistin, *zeiger, *essidlistinnew;\par
static hashlist_t *zeigerhash;\par
static char hexpfx[] = \{ "$HEX[" \};\par
\par
static char linein[PMKIDEAPOL_BUFFER_LEN];\par
\par
essidlistinmax = 1000;\par
if((essidlistin = (essidlist_t*)calloc(essidlistinmax, ESSIDLIST_SIZE)) == NULL) return;\par
if((fh_essidlistin = fopen(essidlistinname, "rb")) == NULL)\par
\tab\{\par
\tab printf("error opening file %s: %s\\n", essidlistinname, strerror(errno));\par
\tab return;\par
\tab\}\par
\par
zeiger = essidlistin;\par
essidlistincount = 0;\par
while(1)\par
\tab\{\par
\tab if((len = fgetline(fh_essidlistin, PMKIDEAPOL_BUFFER_LEN, linein)) == -1) break;\par
\tab if((len < 1) || (len > 70)) continue;\par
\tab memset(zeiger->essid, 0, 33);\par
\tab if((len >= 8) && ((len %2) == 0) && (linein[len -1] == ']') && (memcmp(linein, hexpfx, 5) == 0))\par
\tab\tab\{\par
\tab\tab linein[len -1] = 0;\par
\tab\tab zeiger->essidlen = getfield(&linein[5], 32, zeiger->essid);\par
\tab\tab\}\par
\tab else if(len <= 32)\par
\tab\tab\{\par
\tab\tab zeiger->essidlen = len;\par
\tab\tab memcpy(zeiger->essid, linein, len);\par
\tab\tab\}\par
\tab else continue;\par
\tab essidlistincount++;\par
\tab if(essidlistincount >= essidlistinmax)\par
\tab\tab\{\par
\tab\tab essidlistinmax += 1000;\par
\tab\tab essidlistinnew = realloc(essidlistin, essidlistinmax *ESSIDLIST_SIZE);\par
\tab\tab if(essidlistinnew == NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab printf("failed to allocate memory for internal list\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab essidlistin = essidlistinnew;\par
\tab\tab\}\par
\tab zeiger = essidlistin +essidlistincount;\par
\tab\}\par
if(fh_essidlistin != NULL) fclose(fh_essidlistin);\par
qsort(essidlistin, essidlistincount, ESSIDLIST_SIZE, sort_essidlistin);\par
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essidlen);\par
if(pmkideapoloutname == NULL)\par
\tab\{\par
\tab if(essidlistin != NULL) free(essidlistin);\par
\tab return;\par
\tab\}\par
if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)\par
\tab\{\par
\tab printf("error opening file %s: %s\\n", pmkideapoloutname, strerror(errno));\par
\tab free(essidlistin);\par
\tab return;\par
\tab\}\par
zeiger = essidlistin;\par
zeigerhash = hashlist;\par
\par
o = 0;\par
for(i = 0; i < essidlistincount; i++)\par
\tab\{\par
\tab while(o < pmkideapolcount)\par
\tab\tab\{\par
\tab\tab if((zeigerhash +o)->essidlen < (zeiger +i)->essidlen)\par
\tab\tab\tab\{\par
\tab\tab\tab o++;\par
\tab\tab\tab continue;\par
\tab\tab\tab\}\par
\tab\tab if((zeigerhash +o)->essidlen > (zeiger +i)->essidlen) break;\par
\tab\tab if((memcmp((zeigerhash +o)->essid, (zeiger +i)->essid, (zeigerhash +o)->essidlen)) > 0) break;\par
\tab\tab if((memcmp((zeigerhash +o)->essid, (zeiger +i)->essid, (zeigerhash +o)->essidlen)) == 0) writepmkideapolhashline(fh_pmkideapol, zeigerhash +o);\par
\tab\tab o++;\par
\tab\tab\}\par
\tab\}\par
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
if(pmkideapoloutname != NULL)\par
\tab\{\par
\tab if(stat(pmkideapoloutname, &statinfo) == 0)\par
\tab\tab\{\par
\tab\tab if(statinfo.st_size == 0) remove(pmkideapoloutname);\par
\tab\tab\}\par
\tab\}\par
if(essidlistin != NULL) free(essidlistin);\par
return;\par
\}\par
/*===========================================================================*/\par
static bool readpmkideapolfile(FILE *fh_pmkideapol)\par
\{\par
static int len;\par
static int oflen;\par
static uint16_t essidlen;\par
static uint16_t noncelen;\par
static uint16_t eapauthlen;\par
static uint16_t mplen;\par
static hashlist_t *zeiger, *hashlistnew;\par
\par
static const char wpa01[] = \{ "WPA*01*" \};\par
static const char wpa02[] = \{ "WPA*02*" \};\par
\par
static char linein[PMKIDEAPOL_LINE_LEN +1];\par
static uint8_t buffer[PMKIDEAPOL_LINE_LEN +1];\par
\par
zeiger = hashlist;\par
while(1)\par
\tab\{\par
\tab if((len = fgetline(fh_pmkideapol, PMKIDEAPOL_LINE_LEN, linein)) == -1) break;\par
\tab readcount++;\par
\tab if(len < 68)\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab if((memcmp(&linein, &wpa01, 7) != 0) && (memcmp(&linein, &wpa02, 7) != 0))\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab if((linein[39] != '*') && (linein[52] != '*') && (linein[65] != '*'))\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab if(getfield(&linein[7], PMKIDEAPOL_LINE_LEN, buffer) != 16)\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab memcpy(zeiger->hash, &buffer, 16);\par
\par
\tab if(getfield(&linein[40], PMKIDEAPOL_LINE_LEN, buffer) != 6)\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab memcpy(zeiger->ap, &buffer, 6);\par
\par
\tab if(getfield(&linein[53], PMKIDEAPOL_LINE_LEN, buffer) != 6)\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab memcpy(zeiger->client, &buffer, 6);\par
\tab essidlen = getfield(&linein[66], PMKIDEAPOL_LINE_LEN, buffer);\par
\tab if(essidlen > 32)\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab memcpy(zeiger->essid, &buffer, essidlen);\par
\tab zeiger->essidlen = essidlen;\par
\tab if(memcmp(&linein, &wpa01, 7) == 0)\par
\tab\tab\{\par
\tab\tab zeiger->type = HS_PMKID;\par
\tab\tab pmkidcount++;\par
\tab\tab\}\par
\tab else if(memcmp(&linein, &wpa02, 7) == 0)\par
\tab\tab\{\par
\tab\tab oflen = 66 +essidlen *2 +1;\par
\tab\tab noncelen = getfield(&linein[oflen], PMKIDEAPOL_LINE_LEN, buffer);\par
\tab\tab if(noncelen > 32)\par
\tab\tab\tab\{\par
\tab\tab\tab readerrorcount++;\par
\tab\tab\tab continue;\par
\tab\tab\tab\}\par
\tab\tab memcpy(zeiger->nonce, &buffer, 32);\par
\tab\tab oflen += 65;\par
\tab\tab eapauthlen = getfield(&linein[oflen], PMKIDEAPOL_LINE_LEN, buffer);\par
\tab\tab if(eapauthlen > EAPOL_AUTHLEN_MAX)\par
\tab\tab\tab\{\par
\tab\tab\tab readerrorcount++;\par
\tab\tab\tab continue;\par
\tab\tab\tab\}\par
\tab\tab memcpy(zeiger->eapol, &buffer, eapauthlen);\par
\tab\tab zeiger->eapauthlen = eapauthlen;\par
\tab\tab oflen += eapauthlen *2 +1;\par
\tab\tab mplen = getfield(&linein[oflen], PMKIDEAPOL_LINE_LEN, buffer);\par
\tab\tab if(mplen > 1)\par
\tab\tab\tab\{\par
\tab\tab\tab readerrorcount++;\par
\tab\tab\tab continue;\par
\tab\tab\tab\}\par
\tab\tab zeiger->mp = buffer[0];\par
\tab\tab zeiger->type = HS_EAPOL;\par
\tab\tab eapolcount++;\par
\tab\tab\}\par
\tab else\par
\tab\tab\{\par
\tab\tab readerrorcount++;\par
\tab\tab continue;\par
\tab\tab\}\par
\tab pmkideapolcount = pmkidcount +eapolcount;\par
\tab if(pmkideapolcount >= hashlistcount)\par
\tab\tab\{\par
\tab\tab hashlistcount += HASHLIST_MAX;\par
\tab\tab hashlistnew = realloc(hashlist, hashlistcount *HASHLIST_SIZE);\par
\tab\tab if(hashlistnew == NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab printf("failed to allocate memory for internal list\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab hashlist = hashlistnew;\par
\tab\tab\}\par
\tab zeiger = hashlist +pmkideapolcount;\par
\tab\}\par
return true;\par
\}\par
/*===========================================================================*/\par
static void showvendorlist()\par
\{\par
static ouilist_t *zeiger;\par
fprintf(stdout, "\\n");\par
for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++) fprintf(stdout, "%02x%02x%02x %s\\n", zeiger->oui[0], zeiger->oui[1], zeiger->oui[2], zeiger->vendor); \par
return;\par
\}\par
/*===========================================================================*/\par
static void readoui()\par
\{\par
static int len;\par
static uid_t uid;\par
static struct passwd *pwd;\par
static struct stat statinfo;\par
static ouilist_t *zeiger, *ouilistnew;\par
static FILE *fh_oui;\par
static char *vendorptr;\par
static const char *ouinameuser = "/.hcxtools/oui.txt";\par
static const char *ouinamesystemwide = "/usr/share/ieee-data/oui.txt";\par
static const char *ouina = "N/A";\par
\par
static char ouinameuserpath[PATH_MAX +1];\par
static char linein[OUI_LINE_LEN +1];\par
\par
usedoui = ouina;\par
uid = getuid();\par
pwd = getpwuid(uid);\par
if(pwd == NULL) return;\par
strncpy(ouinameuserpath, pwd->pw_dir, PATH_MAX -1);\par
strncat(ouinameuserpath, ouinameuser, PATH_MAX -1);\par
if(stat(ouinameuserpath, &statinfo) == 0) usedoui = ouinameuserpath;\par
else if(stat(ouinameuser, &statinfo) == 0) usedoui = ouinamesystemwide;\par
else return;\par
if((fh_oui = fopen(usedoui, "r")) == NULL) return;\par
zeiger = ouilist;\par
while(1)\par
\tab\{\par
\tab if((len = fgetline(fh_oui, OUI_LINE_LEN, linein)) == -1) break;\par
\tab if(len < 20) continue;\par
\tab linein[6] = 0;\par
\tab if(getfield(linein, OUI_LINE_LEN, zeiger->oui) != 3) continue;\par
\tab if(strstr(&linein[7], "(base 16)") == NULL) continue;\par
\tab if(filtervendorptr != NULL)\par
\tab\tab\{\par
\tab\tab if(strstr(&linein[7], filtervendorptr) == NULL) continue;\par
\tab\tab\}\par
\tab vendorptr = strrchr(&linein[7], '\\t');\par
\tab if(vendorptr == NULL) continue;\par
\tab if(vendorptr++ == 0) continue;\par
\tab strncpy(zeiger->vendor, vendorptr, VENDOR_LEN_MAX -1);\par
\tab ouicount++;\par
\tab if(ouicount >= ouilistcount)\par
\tab\tab\{\par
\tab\tab ouilistcount += OUILIST_MAX;\par
\tab\tab ouilistnew = realloc(ouilist, ouilistcount *OUILIST_SIZE);\par
\tab\tab if(ouilistnew == NULL)\par
\tab\tab\tab\{\par
\tab\tab\tab printf("failed to allocate memory for internal list\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab ouilist = ouilistnew;\par
\tab\tab\}\par
\tab zeiger = ouilist +ouicount;\par
\tab\}\par
fclose(fh_oui);\par
qsort(ouilist, ouicount, OUILIST_SIZE, sort_ouilist_by_oui);\par
return;\par
\}\par
/*===========================================================================*/\par
static void downloadoui()\par
\{\par
static uid_t uid;\par
static struct passwd *pwd;\par
static CURLcode ret;\par
static CURL *hnd;\par
static FILE* fhoui;\par
static struct stat statinfo;\par
static const char *ouipath = "/.hcxtools";\par
static const char *ouiname = "/oui.txt";\par
static char ouinameuserpath[PATH_MAX];\par
\par
uid = getuid();\par
pwd = getpwuid(uid);\par
if(pwd == NULL) return;\par
strncpy(ouinameuserpath, pwd->pw_dir, PATH_MAX -1);\par
strncat(ouinameuserpath, ouipath, PATH_MAX -1);\par
if(stat(ouinameuserpath, &statinfo) == -1)\par
\tab\{\par
\tab if(mkdir(ouinameuserpath, 0755) == -1)\par
\tab\tab\{\par
\tab\tab fprintf(stderr, "failed to create conf dir\\n");\par
\tab\tab return;\par
\tab\tab\}\par
\tab\}\par
strncat(ouinameuserpath, ouiname, PATH_MAX -1);\par
printf("start downloading oui from http://standards-oui.ieee.org to: %s\\n", ouinameuserpath);\par
if((fhoui = fopen(ouinameuserpath, "w")) == NULL)\par
\tab\{\par
\tab fprintf(stderr, "error creating file %s", ouiname);\par
\tab return;\par
\tab\}\par
hnd = curl_easy_init ();\par
curl_easy_setopt(hnd, CURLOPT_URL, "http://standards-oui.ieee.org/oui/oui.txt");\par
curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);\par
curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 5L);\par
curl_easy_setopt(hnd, CURLOPT_WRITEDATA, fhoui) ;\par
ret = curl_easy_perform(hnd);\par
curl_easy_cleanup(hnd);\par
fclose(fhoui);\par
if(ret != 0)\par
\tab\{\par
\tab fprintf(stderr, "download not successful");\par
\tab return;\par
\tab\}\par
printf("download finished\\n");\par
return;\par
\}\par
/*===========================================================================*/\par
__attribute__ ((noreturn))\par
static void version(char *eigenname)\par
\{\par
printf("%s %s (C) %s ZeroBeat\\n", eigenname, VERSION_TAG, VERSION_YEAR);\par
exit(EXIT_SUCCESS);\par
\}\par
/*---------------------------------------------------------------------------*/\par
__attribute__ ((noreturn))\par
static void usage(char *eigenname)\par
\{\par
printf("%s %s (C) %s ZeroBeat\\n"\par
\tab "usage:\\n"\par
\tab "%s <options>\\n"\par
\tab "\\n"\par
\tab "options:\\n"\par
\tab "-i <file>   : input PMKID/EAPOL hash file\\n"\par
\tab "-o <file>   : output PMKID/EAPOL hash file\\n"\par
\tab "-E <file>   : output ESSID list (autohex enabled)\\n"\par
\tab "-d          : download http://standards-oui.ieee.org/oui.txt\\n"\par
\tab "              and save to ~/.hcxtools/oui.txt\\n"\par
\tab "              internet connection required\\n"\par
\tab "-h          : show this help\\n"\par
\tab "-v          : show version\\n"\par
\tab "\\n"\par
\tab "--essid-group                : convert to ESSID groups in working directory\\n"\par
\tab "                               full advantage of reuse of PBKDF2\\n"\par
\tab "                               not on old hash formats\\n"\par
\tab "--oui-group                  : convert to OUI groups in working directory\\n"\par
\tab "                               not on old hash formats\\n"\par
\tab "--mac-group-ap               : convert APs to MAC groups in working directory\\n"\par
\tab "                               not on old hash formats\\n"\par
\tab "--mac-group-client           : convert CLIENTs to MAC groups in working directory\\n"\par
\tab "                               not on old hash formats\\n"\par
\tab "--type=<digit>               : filter by hash type\\n"\par
\tab "                               bitmask:\\n"\par
\tab "                                1 = PMKID\\n"\par
\tab "                                2 = EAPOL\\n"\par
\tab "                               default PMKID and EAPOL (1+2=3)\\n"\par
\tab "--hcx-min=<digit>            : disregard hashes with occurrence lower than hcx-min/ESSID\\n"\par
\tab "--hcx-max=<digit>            : disregard hashes with occurrence higher than hcx-min/ESSID\\n"\par
\tab "--essid-len                  : filter by ESSID length\\n"\par
\tab "                               default ESSID length: %d...%d\\n"\par
\tab "--essid-min                  : filter by ESSID minimum length\\n"\par
\tab "                               default ESSID minimum length: %d\\n"\par
\tab "--essid-max                  : filter by ESSID maximum length\\n"\par
\tab "                               default ESSID maximum length: %d\\n"\par
\tab "--essid=<ESSID>              : filter by ESSID\\n"\par
\tab "--essid-part=<part of ESSID> : filter by part of ESSID\\n"\par
\tab "--essid-list=<file>          : filter by ESSID file\\n"\par
\tab "--mac-ap=<MAC>               : filter AP by MAC\\n"\par
\tab "                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\\n"\par
\tab "--mac-client=<MAC>           : filter CLIENT by MAC\\n"\par
\tab "                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\\n"\par
\tab "--mac-list=<file>            : filter by MAC file\\n"\par
\tab "                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\\n"\par
\tab "--mac-skiplist=<file>        : exclude MAC from file\\n"\par
\tab "                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\\n"\par
\tab "--oui-ap=<OUI>               : filter AP by OUI\\n"\par
\tab "                               format: 001122, 00:11:22, 00-11-22 (hex)\\n"\par
\tab "--oui-client=<OUI>           : filter CLIENT by OUI\\n"\par
\tab "                               format: 001122, 00:11:22, 00-11-22 (hex)\\n"\par
\tab "--vendor=<VENDOR>            : filter by (part of) VENDOR name\\n"\par
\tab "--authorized                 : filter EAPOL pairs by status authorized\\n"\par
\tab "--notauthorized              : filter EAPOL pairs by status CHALLENGE (not authorized)\\n"\par
\tab "--rc                         : filter EAPOL pairs by replaycount status checked\\n"\par
\tab "--apless                     : filter EAPOL pairs by status M1M2ROGUE (M2 requested from CLIENT)\\n"\par
\tab "--info=<file>                : output detailed information about content of hash file\\n"\par
\tab "--info=stdout                : stdout output detailed information about content of hash file\\n"\par
\tab "--vendorlist                 : stdout output VENDOR list sorted by OUI\\n"\par
\tab "--psk=<PSK>                  : pre-shared key to test\\n"\par
\tab "                               due to PBKDF2 calculation this is a very slow process\\n"\par
\tab "                               no nonce error corrections\\n"\par
\tab "--pmk=<PMK>                  : plain master key to test\\n"\par
\tab "                               no nonce error corrections\\n"\par
\tab "--hccapx=<file>              : output to deprecated hccapx file\\n"\par
\tab "--hccap=<file>               : output to ancient hccap file\\n"\par
\tab "--hccap-single               : output to ancient hccap single files (MAC + count)\\n"\par
\tab "--john=<file>                : output to deprecated john file\\n"\par
\tab "--help                       : show this help\\n"\par
\tab "--version                    : show version\\n"\par
\tab "\\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname, ESSID_LEN_MIN, ESSID_LEN_MAX, ESSID_LEN_MIN, ESSID_LEN_MAX);\par
exit(EXIT_SUCCESS);\par
\}\par
/*---------------------------------------------------------------------------*/\par
__attribute__ ((noreturn))\par
static void usageerror(char *eigenname)\par
\{\par
printf("%s %s (C) %s by ZeroBeat\\n"\par
\tab "usage: %s -h for help\\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);\par
exit(EXIT_FAILURE);\par
\}\par
/*===========================================================================*/\par
int main(int argc, char *argv[])\par
\{\par
static int auswahl;\par
static int index;\par
static int l;\par
static int lcmin;\par
static int lcmax;\par
static int p1, p2;\par
static int hashtypein;\par
static int essidlenin;\par
static FILE *fh_pmkideapol;\par
static char *pmkideapolinname;\par
static char *pmkideapoloutname;\par
static char *essidoutname;\par
static char *essidinname;\par
static char *macinname;\par
static char *macskipname;\par
static char *hccapxoutname;\par
static char *hccapoutname;\par
static char *johnoutname;\par
static char *infooutname;\par
static char *ouiinstring;\par
static char *macinstring;\par
static char *pmkinstring;\par
\par
static const char *short_options = "i:o:E:dhv";\par
static const struct option long_options[] =\par
\{\par
\tab\{"type",\tab\tab\tab required_argument,\tab NULL,\tab HCX_HASH_TYPE\},\par
\tab\{"hcx-min",\tab\tab\tab required_argument,\tab NULL,\tab HCX_HASH_MIN\},\par
\tab\{"hcx-max",\tab\tab\tab required_argument,\tab NULL,\tab HCX_HASH_MAX\},\par
\tab\{"essid-min",\tab\tab\tab required_argument,\tab NULL,\tab HCX_ESSID_MIN\},\par
\tab\{"essid-group",\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_ESSID_GROUP\},\par
\tab\{"essid-len",\tab\tab\tab required_argument,\tab NULL,\tab HCX_ESSID_LEN\},\par
\tab\{"essid-min",\tab\tab\tab required_argument,\tab NULL,\tab HCX_ESSID_MIN\},\par
\tab\{"essid-max",\tab\tab\tab required_argument,\tab NULL,\tab HCX_ESSID_MAX\},\par
\tab\{"essid",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_ESSID\},\par
\tab\{"essid-part",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_ESSID_PART\},\par
\tab\{"essid-list",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_ESSID_LIST_IN\},\par
\tab\{"mac-ap",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_MAC_AP\},\par
\tab\{"mac-client",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_MAC_CLIENT\},\par
\tab\{"mac-list",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_MAC_LIST_IN\},\par
\tab\{"mac-skiplist",\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_MAC_LIST_SKIP\},\par
\tab\{"mac-group-ap",\tab\tab no_argument,\tab\tab NULL,\tab HCX_MAC_GROUP_AP\},\par
\tab\{"mac-group-client",\tab\tab no_argument,\tab\tab NULL,\tab HCX_MAC_GROUP_CLIENT\},\par
\tab\{"oui-group",\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_OUI_GROUP\},\par
\tab\{"oui-ap",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_OUI_AP\},\par
\tab\{"vendor",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_VENDOR\},\par
\tab\{"oui-client",\tab\tab\tab required_argument,\tab NULL,\tab HCX_FILTER_OUI_CLIENT\},\par
\tab\{"rc",\tab\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_FILTER_RC\},\par
\tab\{"authorized",\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_FILTER_M12\},\par
\tab\{"notauthorized",\tab\tab no_argument,\tab\tab NULL,\tab HCX_FILTER_M1234\},\par
\tab\{"apless",\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_FILTER_M1M2ROGUE\},\par
\tab\{"psk",\tab\tab\tab\tab required_argument,\tab NULL,\tab HCX_PSK\},\par
\tab\{"pmk",\tab\tab\tab\tab required_argument,\tab NULL,\tab HCX_PMK\},\par
\tab\{"vendorlist",\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_VENDOR_OUT\},\par
\tab\{"info",\tab\tab\tab required_argument,\tab NULL,\tab HCX_INFO_OUT\},\par
\tab\{"hccapx",\tab\tab\tab required_argument,\tab NULL,\tab HCX_HCCAPX_OUT\},\par
\tab\{"hccap",\tab\tab\tab required_argument,\tab NULL,\tab HCX_HCCAP_OUT\},\par
\tab\{"hccap-single",\tab\tab no_argument,\tab\tab NULL,\tab HCX_HCCAP_SINGLE_OUT\},\par
\tab\{"john",\tab\tab\tab required_argument,\tab NULL,\tab HCX_JOHN_OUT\},\par
\tab\{"version",\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_VERSION\},\par
\tab\{"help",\tab\tab\tab no_argument,\tab\tab NULL,\tab HCX_HELP\},\par
\tab\{NULL,\tab\tab\tab\tab 0,\tab\tab\tab NULL,\tab 0\}\par
\};\par
\par
auswahl = -1;\par
index = 0;\par
optind = 1;\par
optopt = 0;\par
fh_pmkideapol = NULL;\par
pmkideapolinname = NULL;\par
pmkideapoloutname = NULL;\par
essidoutname = NULL;\par
essidinname = NULL;\par
macinname = NULL;\par
macskipname = NULL;\par
infooutname = NULL;\par
hccapxoutname = NULL;\par
hccapoutname = NULL;\par
johnoutname = NULL;\par
ouiinstring = NULL;\par
macinstring = NULL;\par
pmkinstring = NULL;\par
filteressidptr = NULL;\par
filteressidpartptr = NULL;\par
filtervendorptr = NULL;\par
flagfiltermacap = false;\par
flagfiltermacclient = false;\par
flagfilterouiap = false;\par
flagfilterouiclient = false;\par
flagfilterauthorized = false;\par
flagfilternotauthorized = false;\par
flagfilterrcchecked = false;\par
flagfilterapless = false;\par
flagpsk = false;\par
flagpmk = false;\par
flagessidgroup = false;\par
flagmacapgroup = false;\par
flagmacclientgroup = false;\par
flagouigroup = false;\par
flagvendorout = false;\par
flaghccapsingleout = false;\par
hashtypein = 0;\par
hashtype = HCX_TYPE_PMKID | HCX_TYPE_EAPOL;\par
essidlenin = ESSID_LEN_MAX;\par
essidlen = ESSID_LEN_MAX;\par
essidlenmin = ESSID_LEN_MIN;\par
essidlenmax = ESSID_LEN_MAX;\par
lcmin = 0;\par
lcmax = 0;\par
\par
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)\par
\tab\{\par
\tab switch (auswahl)\par
\tab\tab\{\par
\tab\tab case HCX_PMKIDEAPOL_IN:\par
\tab\tab pmkideapolinname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_PMKIDEAPOL_OUT:\par
\tab\tab pmkideapoloutname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_ESSID_OUT:\par
\tab\tab essidoutname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_VENDOR_OUT:\par
\tab\tab flagvendorout = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_INFO_OUT:\par
\tab\tab infooutname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_ESSID_GROUP:\par
\tab\tab flagessidgroup = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_HASH_TYPE:\par
\tab\tab hashtypein |= strtol(optarg, NULL, 10);\par
\tab\tab if((hashtypein < HCX_TYPE_PMKID) || (hashtypein < HCX_TYPE_EAPOL))\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "only hash types 1 and 2 allowed\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab break;\par
\par
\tab\tab case HCX_ESSID_LEN:\par
\tab\tab essidlenin = strtol(optarg, NULL, 10);\par
\tab\tab if((essidlenin < 0) || (essidlenin > ESSID_LEN_MAX))\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "only values 0...32 allowed\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab essidlenmin = essidlenin;\par
\tab\tab essidlenmax = essidlenin;\par
\tab\tab break;\par
\par
\tab\tab case HCX_ESSID_MIN:\par
\tab\tab essidlenin = strtol(optarg, NULL, 10);\par
\tab\tab if((essidlenin < 0) || (essidlenin > ESSID_LEN_MAX))\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "only values 0...32 allowed\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab essidlenmin = essidlenin;\par
\tab\tab break;\par
\par
\tab\tab case HCX_ESSID_MAX:\par
\tab\tab essidlenin = strtol(optarg, NULL, 10);\par
\tab\tab if((essidlenin < 0) || (essidlenin > ESSID_LEN_MAX))\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "only values 0...32 allowed\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab essidlenmax = essidlenin;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_ESSID:\par
\tab\tab filteressidptr = optarg;\par
\tab\tab filteressidlen = strlen(filteressidptr);\par
\tab\tab if((filteressidlen  < 1) || (filteressidlen > ESSID_LEN_MAX))\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "only values 0...32 allowed\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_ESSID_PART:\par
\tab\tab filteressidpartptr = optarg;\par
\tab\tab filteressidpartlen = strlen(filteressidpartptr);\par
\tab\tab if((filteressidpartlen  < 1) || (filteressidpartlen > ESSID_LEN_MAX))\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "only values 0...32 allowed\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_ESSID_LIST_IN:\par
\tab\tab essidinname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_HASH_MIN:\par
\tab\tab lcmin = strtol(optarg, NULL, 10);\par
\tab\tab break;\par
\par
\tab\tab case HCX_HASH_MAX:\par
\tab\tab lcmax = strtol(optarg, NULL, 10);\par
\tab\tab break;\par
\par
\tab\tab case HCX_MAC_GROUP_AP:\par
\tab\tab flagmacapgroup = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_MAC_GROUP_CLIENT:\par
\tab\tab flagmacclientgroup = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_OUI_GROUP:\par
\tab\tab flagouigroup = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_OUI_AP:\par
\tab\tab l= strlen(optarg);\par
\tab\tab p2 = 0;\par
\tab\tab for(p1 = 0; p1 < l; p1++)\par
\tab\tab\tab\{\par
\tab\tab\tab if(isxdigit(optarg[p1]))\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab optarg[p2] = optarg[p1];\par
\tab\tab\tab\tab p2++;\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab optarg[6] = 0;\par
\tab\tab ouiinstring = optarg;\par
\tab\tab if(getfield(ouiinstring, 3, filterouiap) != 3)\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "wrong OUI format\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab flagfilterouiap = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_MAC_AP:\par
\tab\tab l= strlen(optarg);\par
\tab\tab p2 = 0;\par
\tab\tab for(p1 = 0; p1 < l; p1++)\par
\tab\tab\tab\{\par
\tab\tab\tab if(isxdigit(optarg[p1]))\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab optarg[p2] = optarg[p1];\par
\tab\tab\tab\tab p2++;\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab optarg[12] = 0;\par
\tab\tab macinstring = optarg;\par
\tab\tab if(getfield(macinstring, 6, filtermacap) != 6)\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "wrong MAC format $\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab flagfiltermacap = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_MAC_CLIENT:\par
\tab\tab l= strlen(optarg);\par
\tab\tab p2 = 0;\par
\tab\tab for(p1 = 0; p1 < l; p1++)\par
\tab\tab\tab\{\par
\tab\tab\tab if(isxdigit(optarg[p1]))\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab optarg[p2] = optarg[p1];\par
\tab\tab\tab\tab p2++;\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab optarg[12] = 0;\par
\tab\tab macinstring = optarg;\par
\tab\tab if(getfield(macinstring, 6, filtermacclient) != 6)\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "wrong MAC format\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab flagfiltermacclient = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_MAC_LIST_IN:\par
\tab\tab macinname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_MAC_LIST_SKIP:\par
\tab\tab macskipname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_OUI_CLIENT:\par
\tab\tab l= strlen(optarg);\par
\tab\tab p2 = 0;\par
\tab\tab for(p1 = 0; p1 < l; p1++)\par
\tab\tab\tab\{\par
\tab\tab\tab if(isxdigit(optarg[p1]))\par
\tab\tab\tab\tab\{\par
\tab\tab\tab\tab optarg[p2] = optarg[p1];\par
\tab\tab\tab\tab p2++;\par
\tab\tab\tab\tab\}\par
\tab\tab\tab\}\par
\tab\tab optarg[6] = 0;\par
\tab\tab ouiinstring = optarg;\par
\tab\tab if(getfield(ouiinstring, 3, filterouiclient) != 3)\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "wrong OUI format\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab flagfilterouiclient = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_VENDOR:\par
\tab\tab filtervendorptr = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_RC:\par
\tab\tab flagfilterrcchecked = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_M12:\par
\tab\tab flagfilterauthorized = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_M1234:\par
\tab\tab flagfilternotauthorized = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_FILTER_M1M2ROGUE:\par
\tab\tab flagfilterapless = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_PSK:\par
\tab\tab pskptr = optarg;\par
\tab\tab pskptrlen = strlen(pskptr);\par
\tab\tab if((pskptrlen < 0) || (pskptrlen > 63))\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "only 0...63 characters allowed\\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab flagpsk = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_PMK:\par
\tab\tab pmkinstring = optarg;\par
\tab\tab if(getfield(pmkinstring, 32, pmk) != 32)\par
\tab\tab\tab\{\par
\tab\tab\tab fprintf(stderr, "wrong PMK length \\n");\par
\tab\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\tab\}\par
\tab\tab flagpmk = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_DOWNLOAD_OUI:\par
\tab\tab downloadoui();\par
\tab\tab break;\par
\par
\tab\tab case HCX_HCCAPX_OUT:\par
\tab\tab hccapxoutname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_HCCAP_OUT:\par
\tab\tab hccapoutname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_HCCAP_SINGLE_OUT:\par
\tab\tab flaghccapsingleout = true;\par
\tab\tab break;\par
\par
\tab\tab case HCX_JOHN_OUT:\par
\tab\tab johnoutname = optarg;\par
\tab\tab break;\par
\par
\tab\tab case HCX_HELP:\par
\tab\tab usage(basename(argv[0]));\par
\tab\tab break;\par
\par
\tab\tab case HCX_VERSION:\par
\tab\tab version(basename(argv[0]));\par
\tab\tab break;\par
\par
\tab\tab case '?':\par
\tab\tab usageerror(basename(argv[0]));\par
\tab\tab break;\par
\tab\tab\}\par
\tab\}\par
\par
if(essidlenmin > essidlenmax)\par
\tab\{\par
\tab fprintf(stderr, "minimum ESSID length is > maximum ESSID length\\n");\par
\tab exit(EXIT_FAILURE);\par
\tab\}\par
\par
if(argc < 2)\par
\tab\{\par
\tab fprintf(stderr, "no option selected\\n");\par
\tab return EXIT_SUCCESS;\par
\tab\}\par
\par
if(initlists() == false) exit(EXIT_FAILURE);\par
\par
readoui();\par
if((ouicount > 0) && (flagvendorout == true))\par
\tab\{\par
\tab showvendorlist();\par
\tab printstatus();\par
\tab closelists();\par
\tab return EXIT_SUCCESS;\par
\tab\}\par
\par
if(pmkideapolinname != NULL)\par
\tab\{\par
\tab if((fh_pmkideapol = fopen(pmkideapolinname, "r")) == NULL)\par
\tab\tab\{\par
\tab\tab printf("error opening file %s: %s\\n", pmkideapolinname, strerror(errno));\par
\tab\tab closelists();\par
\tab\tab exit(EXIT_FAILURE);\par
\tab\tab\}\par
\tab\}\par
\par
if(fh_pmkideapol != NULL) readpmkideapolfile(fh_pmkideapol);\par
if((pmkideapolcount > 0) && (macskipname != NULL)) removepmkideapol(macskipname);\par
\par
if(hashtypein > 0) hashtype = hashtypein;\par
\par
if((pmkideapolcount > 0) && (essidoutname != NULL)) processessid(essidoutname);\par
if((pmkideapolcount > 0) && (pmkideapoloutname != NULL) && (essidinname == NULL))\par
\tab\{\par
\tab if((lcmin == 0) && (lcmax == 0)) writeeapolpmkidfile(pmkideapoloutname);\par
\tab else writelceapolpmkidfile(pmkideapoloutname, lcmin, lcmax);\par
\tab\}\par
if((pmkideapolcount > 0) && (infooutname != NULL)) writeinfofile(infooutname);\par
if((pmkideapolcount > 0) && (flagessidgroup == true)) writeeapolpmkidessidgroups();\par
if((pmkideapolcount > 0) && (flagmacapgroup == true)) writeeapolpmkidmacapgroups();\par
if((pmkideapolcount > 0) && (flagmacclientgroup == true)) writeeapolpmkidmacclientgroups();\par
if((pmkideapolcount > 0) && (flagouigroup == true)) writeeapolpmkidouigroups();\par
if((pmkideapolcount > 0) && (flagpsk == true)) testhashfilepsk();\par
if((pmkideapolcount > 0) && (flagpmk == true)) testhashfilepmk();\par
if((pmkideapolcount > 0) && (hccapxoutname != NULL)) writehccapxfile(hccapxoutname);\par
if((pmkideapolcount > 0) && (hccapoutname != NULL)) writehccapfile(hccapoutname);\par
if((pmkideapolcount > 0) && (flaghccapsingleout == true)) writehccapsinglefile();\par
if((pmkideapolcount > 0) && (johnoutname != NULL)) writejohnfile(johnoutname);\par
if((pmkideapolcount > 0) && (pmkideapoloutname != NULL) && (essidinname != NULL)) processessidfile(essidinname, pmkideapoloutname);\par
if((pmkideapolcount > 0) && (macinname != NULL)) processmacfile(macinname, pmkideapoloutname);\par
\par
printstatus();\par
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);\par
closelists();\par
return EXIT_SUCCESS;\par
\}\par
/*===========================================================================*/\par
\par
}
 