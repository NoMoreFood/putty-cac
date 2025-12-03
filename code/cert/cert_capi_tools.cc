#ifdef PUTTY_CAC

#include <windows.h>
#include <certenroll.h>
#include <atlbase.h>
#include <comutil.h>

#include <string>

#include "cert_common.h"
#include "cert_capi.h"

#pragma comment(lib,"comsuppw.lib")
#include <fstream>
CComPtr<IObjectId> GetObjectId(_bstr_t sAlgName)
{
    CComPtr<IObjectId> oAlgOid;
    if (FAILED(CoCreateInstance(__uuidof(CObjectId), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oAlgOid)))) exit(0);
    oAlgOid->InitializeFromValue(sAlgName);
    return oAlgOid;
}

EXTERN_C LPSTR cert_capi_create_key(LPCSTR szAlgName, LPCSTR sSubjectName, BOOL bHardware)
{
    std::string sSubjectNameWithCn = std::string("CN=") + sSubjectName;
    _bstr_t sProviderName = bHardware ? MS_SMART_CARD_KEY_STORAGE_PROVIDER : MS_KEY_STORAGE_PROVIDER;
    _bstr_t sAlgOid;

    // determine bits and oid from passed strings
    DWORD iBits = 0;
    if (false);
    else if (strcmp(szAlgName, "rsa-1024") == 0) { iBits = 1024; sAlgOid = szOID_RSA_RSA; }
    else if (strcmp(szAlgName, "rsa-2048") == 0) { iBits = 2048; sAlgOid = szOID_RSA_RSA; }
    else if (strcmp(szAlgName, "rsa-3072") == 0) { iBits = 3072; sAlgOid = szOID_RSA_RSA; }
    else if (strcmp(szAlgName, "rsa-4096") == 0) { iBits = 4096; sAlgOid = szOID_RSA_RSA; }
    else if (strcmp(szAlgName, "ecdsa-sha2-nistp256") == 0) { iBits = 256; sAlgOid = szOID_ECC_CURVE_P256; }
    else if (strcmp(szAlgName, "ecdsa-sha2-nistp384") == 0) { iBits = 384; sAlgOid = szOID_ECC_CURVE_P384; }
    else if (strcmp(szAlgName, "ecdsa-sha2-nistp521") == 0) { iBits = 521; sAlgOid = szOID_ECC_CURVE_P521; }
    else return NULL;

    // initialize com
    HRESULT iInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (iInit != S_OK && iInit != S_FALSE) return NULL;

    // create provider information structure
    CComPtr<ICspInformation> oProviderInfo = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CCspInformation), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oProviderInfo))) ||
        FAILED(oProviderInfo->InitializeFromName(sProviderName)))
    {
        return NULL;
    }

    // create string used for issuer and subject
    CComPtr<IX500DistinguishedName> oName = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CX500DistinguishedName), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oName))) ||
        FAILED(oName->Encode(_bstr_t(sSubjectNameWithCn.c_str()), XCN_CERT_NAME_STR_NONE)))
    {
        return NULL;
    }

    // initialize privatre key
    CComPtr<IX509PrivateKey> oPrivateKey = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CX509PrivateKey), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oPrivateKey))) ||
        FAILED(oPrivateKey->put_ProviderName(sProviderName)) ||
        FAILED(oPrivateKey->put_MachineContext(VARIANT_FALSE)) ||
        FAILED(oPrivateKey->put_Algorithm(GetObjectId(sAlgOid))) ||
        FAILED(oPrivateKey->put_Length(iBits)) ||
        FAILED(oPrivateKey->put_KeyProtection(XCN_NCRYPT_UI_NO_PROTECTION_FLAG)) ||
        FAILED(oPrivateKey->put_ExportPolicy(XCN_NCRYPT_ALLOW_EXPORT_NONE)) ||
        FAILED(oPrivateKey->Create()))
    {
        return NULL;
    }

    // give the certificate a long lifetime
    DOUBLE iNotBefore = 0, iNotAfter = 0;
    SYSTEMTIME tSystemTimeStart;
    GetSystemTime(&tSystemTimeStart);
    SystemTimeToVariantTime(&tSystemTimeStart, &iNotBefore);
    SYSTEMTIME tSystemTimeEnd = tSystemTimeStart;
    tSystemTimeEnd.wYear += 10;
    SystemTimeToVariantTime(&tSystemTimeEnd, &iNotAfter);

    // create certificate request
    CComPtr<IX509CertificateRequestCertificate2> oRequest = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CX509CertificateRequestCertificate), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oRequest))) ||
        FAILED(oRequest->InitializeFromPrivateKey(ContextUser, oPrivateKey, _bstr_t(L""))) ||
        FAILED(oRequest->put_Subject(oName)) ||
        FAILED(oRequest->put_Issuer(oName)) ||
        FAILED(oRequest->put_NotBefore(iNotBefore)) ||
        FAILED(oRequest->put_NotAfter(iNotAfter)) ||
        FAILED(oRequest->put_HashAlgorithm(GetObjectId(szOID_NIST_sha256))))
    {
        return NULL;
    }

    // create com structure for key usage 
    CComPtr<IX509ExtensionKeyUsage> oKeyUsage = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CX509ExtensionKeyUsage), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oKeyUsage))) ||
        FAILED(oKeyUsage->InitializeEncode(XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE)))
    {
        return NULL;
    }

    // create list of oids for enhanced key usage
    CComPtr<IObjectIds> oEnhancedKeyUsageOids = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CObjectIds), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oEnhancedKeyUsageOids))) ||
        FAILED(oEnhancedKeyUsageOids->Add(GetObjectId(szOID_PKIX_KP_CLIENT_AUTH))) ||
        (bHardware && FAILED(oEnhancedKeyUsageOids->Add(GetObjectId(szOID_KP_SMARTCARD_LOGON)))))
    {
        return NULL;
    }

    // create com structure for enhanced key usage list
    CComPtr<IX509ExtensionEnhancedKeyUsage> oEnhancedKeyUsageList = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CX509ExtensionEnhancedKeyUsage), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oEnhancedKeyUsageList))) ||
        FAILED(oEnhancedKeyUsageList->InitializeEncode(oEnhancedKeyUsageOids)))
    {
        return NULL;
    }

    // add key usage and enhanced key usage to extension list
    CComPtr<IX509Extensions> oExtensions = nullptr;
    if (FAILED(oRequest->get_X509Extensions(&oExtensions)) ||
        FAILED(oExtensions->Add(oKeyUsage)) ||
        FAILED(oExtensions->Add(oEnhancedKeyUsageList)) ||
        FAILED(oRequest->Encode()))
    {
        return NULL;
    }

    // create and submit self-signed enrollment request
    CComPtr<IX509Enrollment2> oEnrollment = nullptr;
    BSTR sRequestString;
    BSTR sInstralledCert;
    if (FAILED(CoCreateInstance(__uuidof(CX509Enrollment), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oEnrollment))) ||
        FAILED(oEnrollment->InitializeFromRequest(oRequest)) ||
        FAILED(oEnrollment->CreateRequest(XCN_CRYPT_STRING_BASE64, &sRequestString)) ||
        FAILED(oEnrollment->InstallResponse(AllowUntrustedCertificate, sRequestString, XCN_CRYPT_STRING_BASE64, _bstr_t(L""))) ||
        FAILED(oEnrollment->get_Certificate(XCN_CRYPT_STRING_BINARY, &sInstralledCert)))
    {
        return NULL;
    }
    SysFreeString(sRequestString);

    // fetch dummy context so we can lookup the thumbprint
    PCCERT_CONTEXT tDummyCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        &((LPBYTE)sInstralledCert)[sizeof(UINT)],
        SysStringByteLen(sInstralledCert));
    SysFreeString(sInstralledCert);

    // now use the public key to find the unified certificate in the cer store
    LPSTR szThumbprint = NULL;
    if (tDummyCertContext != NULL)
    {
        HCERTSTORE hCertStore = cert_capi_get_cert_store();
        PCCERT_CONTEXT tUnifiedCert = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_PUBLIC_KEY, (PVOID)&tDummyCertContext->pCertInfo->SubjectPublicKeyInfo, NULL);
        if (tUnifiedCert != NULL)
        {
            szThumbprint = cert_get_cert_thumbprint(IDEN_CAPI, tUnifiedCert);
            CertFreeCertificateContext(tUnifiedCert);
        }
        CertCloseStore(hCertStore, 0);
    }

    // cleanup
    if (tDummyCertContext != NULL) CertFreeCertificateContext(tDummyCertContext);
    return szThumbprint;
}

#endif // PUTTY_CAC