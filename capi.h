/*
 * CAPI: Windows Crypto API header file.
 * Andrew Prout, aprout at ll mit edu
 */

#ifndef PUTTY_CAPI_H
#define PUTTY_CAPI_H

#ifdef _WINDOWS

struct capi_keyhandle_struct {
	void* win_provider;
	char* algorithm;
	unsigned char* pubkey;
	unsigned int pubkey_len;
	unsigned int win_keyspec;
};

struct CAPI_userkey {
	char			*certID; // StoreType\StoreName\HexSHA1
	unsigned char	*blob;
	int				bloblen;
};
#define CAPI_userkey_Comment_Length(x) (strlen(x->certID) + 5 /* "CAPI:" */)

extern struct ssh2_userkey capi_key_ssh2_userkey;

BOOL capi_get_pubkey(void *f, char* certID, unsigned char** pubkey, char **algorithm, int *blob_len);
BOOL capi_get_key_handle(void *f, char* certID, struct capi_keyhandle_struct** keyhandle);
BOOL capi_display_cert_ui(HWND hwnd, char* certID, WCHAR* title);
//BOOL capi_get_cert_handle(char* certID, PCCERT_CONTEXT* oCertContext);
unsigned char* capi_sig(struct capi_keyhandle_struct* keyhandle, char *sigdata, int sigdata_len, int *sigblob_len);
unsigned char* capi_sig_certID(char* certID, char *sigdata, int sigdata_len, int *sigblob_len);
void capi_release_key(struct capi_keyhandle_struct** keyhandle);
char* capi_get_key_string(char* certID);
char* CAPI_userkey_GetComment(struct CAPI_userkey* ckey);

struct CAPI_userkey* Create_CAPI_userkey(const char* certID, CERT_CONTEXT* pCertContext);
void Free_CAPI_userkey(struct CAPI_userkey* ckey);

#endif //#ifdef _WINDOWS

#endif //#ifndef PUTTY_CAPI_H
