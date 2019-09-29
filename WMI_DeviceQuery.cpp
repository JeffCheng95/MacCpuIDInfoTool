#pragma once
#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <comutil.h>
#include <Wbemidl.h>
#include <tchar.h>
#include <strsafe.h>
#include <algorithm>
#include <atlbase.h>
//#include <atlconv.h>
#include <ntddndis.h>
#include "WMI_DeviceQuery.h"

#include<iostream>

using namespace std;

#pragma comment (lib, "comsuppw.lib")
#pragma comment (lib, "wbemuuid.lib")

typedef struct _T_WQL_QUERY
{
	CHAR*	szSelect;		// SELECT���
	WCHAR*	szProperty;		// �����ֶ�
} T_WQL_QUERY;

// WQL��ѯ���
const T_WQL_QUERY szWQLQuery[] = {
	// ����ԭ��MAC��ַ
	"SELECT * FROM Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",
	L"PNPDeviceID",

	// Ӳ�����к�
	"SELECT * FROM Win32_DiskDrive WHERE (SerialNumber IS NOT NULL) AND (MediaType LIKE 'Fixed hard disk%')",
	L"SerialNumber",

	// �������к�
	"SELECT * FROM Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)",
	L"SerialNumber",	

	// ������ID
	"SELECT * FROM Win32_Processor WHERE (ProcessorId IS NOT NULL)",
	L"ProcessorId",

	// BIOS���к�
	"SELECT * FROM Win32_BIOS WHERE (SerialNumber IS NOT NULL)",
	L"SerialNumber",

	// �����ͺ�
	"SELECT * FROM Win32_BaseBoard WHERE (Product IS NOT NULL)",
	L"Product",

	// ������ǰMAC��ַ
	"SELECT * FROM Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",
	L"MACAddress",
};


_Ret_z_ inline LPTSTR W22T(_In_z_ LPWSTR lp)
{
	return LPTSTR(lp);
}


// ͨ����PNPDeviceID����ȡ����ԭ��MAC��ַ
static BOOL WMI_DoWithPNPDeviceID( const TCHAR *PNPDeviceID, TCHAR *MacAddress, UINT uSize )
{
	TCHAR	DevicePath[MAX_PATH];
	HANDLE	hDeviceFile;	
	BOOL	isOK = FALSE;

	// �����豸·����
	StringCchCopy( DevicePath, MAX_PATH, TEXT("\\\\.\\") );
	StringCchCat( DevicePath, MAX_PATH, PNPDeviceID );
	StringCchCat( DevicePath, MAX_PATH, TEXT("#{ad498944-762f-11d0-8dcb-00c04fc3358c}") );

	// ����PNPDeviceID���еġ�\���滻�ɡ�#�����Ի���������豸·����
	std::replace( DevicePath + 4, DevicePath + 4 + _tcslen(PNPDeviceID), TEXT('\\'), TEXT('#') ); 

	// ��ȡ�豸���
	hDeviceFile = CreateFile( DevicePath,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if( hDeviceFile != INVALID_HANDLE_VALUE )
	{	
		ULONG	dwID;
		BYTE	ucData[8];
		DWORD	dwByteRet;		

		// ��ȡ����ԭ��MAC��ַ
		dwID = OID_802_3_PERMANENT_ADDRESS;
		isOK = DeviceIoControl( hDeviceFile, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwID, sizeof(dwID), ucData, sizeof(ucData), &dwByteRet, NULL );
		if( isOK )
		{	// ���ֽ�����ת����16�����ַ���
			for( DWORD i = 0; i < dwByteRet; i++ )
			{
				StringCchPrintf( MacAddress + (i << 1), uSize - (i << 1), TEXT("%02X"), ucData[i] );
			}
		}

		CloseHandle( hDeviceFile );
	}

	return isOK;
}

static BOOL WMI_DoWithHarddiskSerialNumber( TCHAR *SerialNumber, UINT uSize )
{
	UINT	iLen;
	UINT	i;

	iLen = _tcslen( SerialNumber );
	if( iLen == 40 )	// InterfaceType = "IDE"
	{	// ��Ҫ��16���Ʊ��봮ת��Ϊ�ַ���
		TCHAR ch, szBuf[32];
		BYTE b;		

		for( i = 0; i < 20; i++ )
		{	// ��16�����ַ�ת��Ϊ��4λ
			ch = SerialNumber[i * 2];
			if( (ch >= '0') && (ch <= '9') )
			{
				b = ch - '0';
			}
			else if( (ch >= 'A') && (ch <= 'F') )
			{
				b = ch - 'A' + 10;
			}
			else if( (ch >= 'a') && (ch <= 'f') )
			{
				b = ch - 'a' + 10;
			}
			else
			{	// �Ƿ��ַ�
				break;
			}

			b <<= 4;

			// ��16�����ַ�ת��Ϊ��4λ
			ch = SerialNumber[i * 2 + 1];
			if( (ch >= '0') && (ch <= '9') )
			{
				b += ch - '0';
			}
			else if( (ch >= 'A') && (ch <= 'F') )
			{
				b += ch - 'A' + 10;
			}
			else if( (ch >= 'a') && (ch <= 'f') )
			{
				b += ch - 'a' + 10;
			}
			else
			{	// �Ƿ��ַ�
				break;
			}

			szBuf[i] = b;
		}

		if( i == 20 )
		{	// ת���ɹ�
			szBuf[i] = L'\0';
			StringCchCopy( SerialNumber, uSize, szBuf );
			iLen = _tcslen( SerialNumber );
		}
	}

	// ÿ2���ַ�����λ��
	for( i = 0; i < iLen; i += 2 )
	{
		std::swap( SerialNumber[i], SerialNumber[i+1] );
	}

	// ȥ���ո�
	std::remove( SerialNumber, SerialNumber + _tcslen(SerialNumber) + 1, L' ' );

	return TRUE;
}

static BOOL WMI_DoWithProperty( INT iQueryType, TCHAR *szProperty, UINT uSize )
{
	BOOL isOK = TRUE;

	switch( iQueryType )
	{
	case 0:		// ����ԭ��MAC��ַ		
		isOK = WMI_DoWithPNPDeviceID( szProperty, szProperty, uSize );
		break;

	case 1:		// Ӳ�����к�
		isOK = WMI_DoWithHarddiskSerialNumber( szProperty, uSize );
		break;

	case 6:		// ������ǰMAC��ַ
		// ȥ��ð��
		std::remove( szProperty, szProperty + _tcslen(szProperty) + 1, L':' );
		break;

	default:
		// ȥ���ո�
		std::remove( szProperty, szProperty + _tcslen(szProperty) + 1, L' ' );
	}

	return isOK;
}

// ����Windows Management Instrumentation��Windows����淶��
INT WMI_DeviceQuery( INT iQueryType, T_DEVICE_PROPERTY *properties, INT iSize )
{
	HRESULT hres;
	INT	iTotal = 0;
	
	// �жϲ�ѯ�����Ƿ�֧��
	if( (iQueryType < 0) || (iQueryType >= sizeof(szWQLQuery)/sizeof(T_WQL_QUERY)) )
	{
		return -1;	// ��ѯ���Ͳ�֧��
	}

    // ��ʼ��COM
    hres = CoInitializeEx( NULL, COINIT_MULTITHREADED ); 
    if( FAILED(hres) )
    {
        return -2;
    }

    // ����COM�İ�ȫ��֤����
	hres = CoInitializeSecurity( 
		NULL, 
		-1, 
		NULL, 
		NULL, 
		RPC_C_AUTHN_LEVEL_DEFAULT, 
		RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
		);
	if( FAILED(hres) )
    {
        CoUninitialize();
        return -2;
    }
    
	// ���WMI����COM�ӿ�
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance( 
		CLSID_WbemLocator,             
        NULL, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator,
		reinterpret_cast<LPVOID*>(&pLoc)
		); 
    if( FAILED(hres) )
    {
		CoUninitialize();
        return -2;
    }

    // ͨ�����ӽӿ�����WMI���ں˶�����"ROOT\\CIMV2"
	IWbemServices *pSvc = NULL;
	hres = pLoc->ConnectServer(
         _bstr_t( L"ROOT\\CIMV2" ),
         NULL,
         NULL,
         NULL,
         0,
         NULL,
         NULL,
         &pSvc
		 );    
    if( FAILED(hres) )
    {
		pLoc->Release(); 
        CoUninitialize();
        return -2;
    }

	// �����������İ�ȫ����
    hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
		);
	if( FAILED(hres) )
    {
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return -2;
    }

    // ͨ�������������WMI��������
    IEnumWbemClassObject *pEnumerator = NULL;
    hres = pSvc->ExecQuery(
		bstr_t("WQL"), 
		bstr_t( szWQLQuery[iQueryType].szSelect ),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator
		);
	if( FAILED(hres) )
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return -3;
    }

    // ѭ��ö�����еĽ������  
    while( pEnumerator )
    {
		IWbemClassObject *pclsObj = NULL;
		ULONG uReturn = 0;

		if( (properties != NULL) && (iTotal >= iSize) )
		{
			break;
		}

        pEnumerator->Next(
			WBEM_INFINITE,
			1, 
            &pclsObj,
			&uReturn
			);

        if( uReturn == 0 )
        {
            break;
        }

		if( properties != NULL )
		{	// ��ȡ����ֵ
			VARIANT vtProperty;
			
			VariantInit( &vtProperty );	
			pclsObj->Get( szWQLQuery[iQueryType].szProperty, 0, &vtProperty, NULL, NULL );
			StringCchCopy( properties[iTotal].szProperty, PROPERTY_MAX_LEN, W2T(vtProperty.bstrVal) );
			VariantClear( &vtProperty );

			// ������ֵ����һ���Ĵ���
			if( WMI_DoWithProperty( iQueryType, properties[iTotal].szProperty, PROPERTY_MAX_LEN ) )
			{
				iTotal++;
			}
		}
		else
		{
			iTotal++;
		}

		pclsObj->Release();
    } // End While

    // �ͷ���Դ
	pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();    
    CoUninitialize();

    return iTotal;
}



/*
���ܣ�ͨ��WMI��ȡ�豸����
����˵����
	iQueryType����Ҫ��ѯ���豸����
			0������ԭ��MAC��ַ
			1��Ӳ�����к�
			2���������к�
			3��CPU ID
			4��BIOS���к�
			5�������ͺ�
			6��������ǰMAC��ַ
	properties���洢�豸����ֵ
	iSize���ɴ洢������豸����
����ֵ��
	 -1����֧�ֵ��豸����ֵ
	 -2��WMI����ʧ��
	 -3������ȷ��WQL��ѯ���
	>=0����ȡ���豸����	
*/
//INT WMI_DeviceQuery( INT iQueryType, T_DEVICE_PROPERTY *properties, INT iSize );


// int _tmain(int argc, _TCHAR* argv[])
// {
// 	
// 	 /*  TCHAR *PNPDeviceID=new TCHAR[16];
// 	   TCHAR *MacAddress=new TCHAR[16];
// 		UINT uSize=1 ;*/
// 
// 	// WMI_DoWithPNPDeviceID(PNPDeviceID,MacAddress,uSize);
// 	INT iQueryType=3;
// 	INT iSize=1;
// 	T_DEVICE_PROPERTY *properties=new T_DEVICE_PROPERTY[1];
// 	
//  
// //	for(int i=0;i<7;i++)
// //	{   
// 		iQueryType=3;
// 		int err= WMI_DeviceQuery( iQueryType,properties , iSize );
// 		printf("CPU id: %s",properties);
// //		for(int j=0;j<16;j++)
// //		{
// //			if(char(properties[0].szProperty[j])=='\0') break;
// //		    cout<<char(properties[0].szProperty[j]);
// //		}
// //		cout<<endl;
// 	
// //	}
// 
// 	int k=0;
// 
// 	int a;
// 	scanf("%d",&a);
// 
// 
// 	return 0;
// }