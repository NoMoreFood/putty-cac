/*
 * CAPI: Windows Crypto API header file.
 * Andrew Prout, aprout at ll mit edu
 */

#pragma once
#ifdef PUTTY_CAC

struct capi_keyhandle_struct {
	void* win_provider;
	char* algorithm;
	unsigned char* pubkey;
	unsigned int pubkey_len;
	unsigned int win_keyspec;
};

struct capi_userkey {
	unsigned char	*blob;
	int				bloblen;
	char			*certid; // StoreType\StoreName\HexSHA1
};

extern struct ssh2_userkey capi_key_ssh2_userkey;

BOOL capi_get_pubkey(char* certid, unsigned char** pubkey, char **algorithm, int *blob_len);
BOOL capi_get_key_handle(char* certid, struct capi_keyhandle_struct** keyhandle);
BOOL capi_display_cert_ui(HWND hwnd, char* certid, WCHAR* title);
unsigned char* capi_sig(HCRYPTPROV hProv, DWORD keyspec, const char* sigdata, int sigdata_len, int* sigblob_len);
unsigned char* capi_sig_certid(char* certid, const char *sigdata, int sigdata_len, int *sigblob_len);
void capi_release_key(struct capi_keyhandle_struct** keyhandle);
char* capi_get_key_string(char* certid);
char* capi_userkey_getcomment(struct capi_userkey* ckey);

struct capi_userkey* create_capi_userkey(const char* certid, PCERT_CONTEXT pCertContext);
void free_capi_userkey(struct capi_userkey* ckey);

#endif // PUTTY_CAC
