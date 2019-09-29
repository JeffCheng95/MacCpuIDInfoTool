
// MacCpuInfoToolDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "MacCpuInfoTool.h"
#include "MacCpuInfoToolDlg.h"
#include "afxdialogex.h"
#include "WMI_DeviceQuery.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <atlconv.h>
#include <openssl/evp.h>
//-----------------MAC----------
#include <Iphlpapi.h>
#pragma  comment(lib,"iphlpapi.lib")
#pragma  comment(lib,"ws2_32.lib")
#pragma  comment(lib,"wsock32.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//��BYTE�ϳ�DWORD
#define MAKE_DWORD(a3, a2, a1, a0) ((DWORD)a3<<24 | (DWORD)a2<<16 | (DWORD)a1<<8 | (DWORD)a0) 
//��DWORD��ֳ�BYTE
#define HH_EXTRACT_DWORD(dwX) ((BYTE)( (dwX & 0xff000000)>>24 ) )
#define H_EXTRACT_DWORD(dwX) ((BYTE)( (dwX & 0x00ff0000)>>16 ) )
#define L_EXTRACT_DWORD(dwX) ((BYTE)( (dwX & 0x0000ff00)>>8 ))
#define LL_EXTRACT_DWORD(dwX) ((BYTE)(dwX & 0x000000ff)) 

#define MacCpuFile "GetLicenseInfo"
#define LiceFile "LicenceFile"
#define MAX_PRODUCT_COUNT 30
#define MAX_LICENCE_SIZE  2048

typedef struct ModeInfo {
	BYTE processNum;
	int endTime_Year;
	BYTE endTime_Month;
	BYTE endTime_Day;
	BYTE productId;
	CString proName;
}ModeInfo;

int g_fileType = 0;		//1��ʾ�������ļ��� 2��ʾ������Ȩ�ļ�
CString g_strMchInfo("");


CMacCpuInfoToolDlg::CMacCpuInfoToolDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MACCPUINFOTOOL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMacCpuInfoToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EI_FILEPATH, m_CfilePath);
	DDX_Control(pDX, IDC_EI_FILETYPE, m_CfileType);
	DDX_Control(pDX, IDC_EI_MACHINEINFO, m_CmachineInfo);
	DDX_Control(pDX, IDC_EI_PRODUCTINFO, m_CproductInfo);
}

BEGIN_MESSAGE_MAP(CMacCpuInfoToolDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BT_OPENFILE, &CMacCpuInfoToolDlg::OnBnClickedBtOpenfile)
	ON_BN_CLICKED(IDC_BT_READFILE, &CMacCpuInfoToolDlg::OnBnClickedBtReadfile)
END_MESSAGE_MAP()


// CMacCpuInfoToolDlg ��Ϣ�������

BOOL CMacCpuInfoToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CMacCpuInfoToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CMacCpuInfoToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void encrypt(unsigned char* in, int inl, unsigned char *out, int* len, unsigned char * key)
{
	unsigned char iv[8];
	EVP_CIPHER_CTX ctx;
	//��init���Ľ��ǽ�ctx�ڴ� memsetΪ0  
	EVP_CIPHER_CTX_init(&ctx);

	//cipher  = EVP_aes_128_ecb();  
	//ԭ��Ϊint EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv)   
	//�������ecb�������뱾ģʽ��˵������������ӽ��ܣ�ǰ��û�й�ϵ��Ҳ�ò���iv  
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, iv);

	*len = 0;
	int outl = 0;
	//���EVP_EncryptUpdate��ʵ��ʵ�ʾ��ǽ�in����inl�ĳ���ȥ���ܣ�ʵ�ֻ�ȡ�ø�cipher�Ŀ��С����aes_128��˵��16�ֽڣ�����block-size��������ȥ���ܡ�
	//�������Ϊ50�ֽڣ���˴�������48�ֽڣ�outlҲΪ48�ֽڡ�����in�е�������ֽڿ�����ctx->buf����������  
	//����inlΪblock_size�����������Σ���ctx->buf��û����ǰ����������ʱ��ֱ�Ӽӽ��ܲ�����ʡȥ�ܶ����������  
	EVP_EncryptUpdate(&ctx, out + *len, &outl, in + *len, inl);
	*len += outl;
	//�������n�ֽڡ��˴����д���
	//�����֧��pading���һ������ݵĻ��ͳ������򣬽�block_size-�������ֽ����������ֽ�����Ϊ�˸�����ֵ����block_size=16,���ݳ���Ϊ4���򽫺����12�ֽ�����Ϊ16-4=12������Ϊһ���������� 
	//����ǰ��Ϊ������ʱ������������Ϊ16�ֽڣ�����ٵ��ô�Finalʱ�������Ƕ�16��0���м��ܣ������Ĳ��ü��ɣ�Ҳ�����ò��ŵ�һ����Final��
	//int test = inl>>4;
	//if(inl != test<<4){
	EVP_EncryptFinal_ex(&ctx, out + *len, &outl);
	*len += outl;
	//}
	EVP_CIPHER_CTX_cleanup(&ctx);

}

void Decrypt(unsigned char* in, int inl, unsigned char *out, unsigned char *key)
{
	unsigned char iv[8];
	EVP_CIPHER_CTX ctx;
	//��init���Ľ��ǽ�ctx�ڴ� memsetΪ0  
	EVP_CIPHER_CTX_init(&ctx);

	//cipher  = EVP_aes_128_ecb();  
	//ԭ��Ϊint EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv)   
	//�������ecb�������뱾ģʽ��˵������������ӽ��ܣ�ǰ��û�й�ϵ��Ҳ�ò���iv  
	EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, iv);
	int len = 0;
	int outl = 0;

	int err = EVP_DecryptUpdate(&ctx, out + len, &outl, in + len, inl);
	if (!err)
	{
		printf("EVP_DecryptUpdate err!\n");
	}
	len += outl;

	err = EVP_DecryptFinal_ex(&ctx, out + len, &outl);
	if (!err)
	{
		printf("EVP_DecryptFinal_ex err!\n");
	}
	if (err != 0)
	{
		len += outl;
		//out[len]=0;
	}
	else
	{
		len = strlen((const char *)out);
	}
	out[len] = 0;
	EVP_CIPHER_CTX_cleanup(&ctx);
}

void Decrypt1(unsigned char* in, int inl, unsigned char *out, unsigned char *key)
{
	unsigned char iv[8];
	EVP_CIPHER_CTX ctx;
	//��init���Ľ��ǽ�ctx�ڴ� memsetΪ0  
	EVP_CIPHER_CTX_init(&ctx);

	//cipher  = EVP_aes_128_ecb();  
	//ԭ��Ϊint EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv)   
	//�������ecb�������뱾ģʽ��˵������������ӽ��ܣ�ǰ��û�й�ϵ��Ҳ�ò���iv  
	EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, iv);
	int len = 0;
	int outl = 0;

	EVP_DecryptUpdate(&ctx, out + len, &outl, in + len, inl);
	len += outl;

	EVP_DecryptFinal_ex(&ctx, out + len, &outl);
	len += outl;
	out[22] = 0;
	EVP_CIPHER_CTX_cleanup(&ctx);
}

int getLocalMultMac(char szMac[10][50])
{
	//char szMac[10][50] = {0};
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	int netCardNum = 0;
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	int macCount = 0;
	if (ERROR_SUCCESS == nRel)
	{
		unsigned char szText[256] = { 0 };
		int i = 0, j = 0;
		for (i = 0; i < 10; i++)
		{
			if (pIpAdapterInfo)
			{
				for (j = 0; j < pIpAdapterInfo->AddressLength; j++)
				{
					szText[j] = (unsigned char)pIpAdapterInfo->Address[j];
				}
				sprintf(szMac[i], "%02X-%02X-%02X-%02X-%02X-%02X", szText[0], szText[1], szText[2], szText[3], szText[4], szText[5]);
				//printf("%s\n", szMac[0]);	
				pIpAdapterInfo = pIpAdapterInfo->Next;
				macCount++;
			}
		}
	}
	if (pIpAdapterInfo)
	{
		delete pIpAdapterInfo;
	}
	return macCount;
}

char* GetCpuID(int nItem, char * buffer)
{
	INT iQueryType = 3;
	INT iSize = 1;
	T_DEVICE_PROPERTY *properties = new T_DEVICE_PROPERTY[1];
	iQueryType = 3;
	int err = WMI_DeviceQuery(iQueryType, properties, iSize);
	if (err <= 0)
	{
		CString strDevErr;
		strDevErr.Format(_T("��ȡ�豸��������WMI_DeviceQuery �����룺%d"), err);
		MessageBox(NULL, strDevErr, _T("��ʾ"), 0);
		buffer = NULL;
		return NULL;
	}
	int i = 0;
	for (int j = 0; j < 16; j++)
	{
		if (char(properties[0].szProperty[j]) == '\0')
		{
			break;
		}
		else
		{
			buffer[i] = char(properties[0].szProperty[j]);
			i++;
		}
	}
	int a = 0;

	buffer[i] = '\0';
	return buffer;

}

CString CMacCpuInfoToolDlg::Decrypt_MacCpuFile(CString strDir)
{
	CFile file;
	unsigned char key[200] = { -87, -92, 112, 55, 105, 91, 0, -115, 118, -128, -10, 82, -1, 11, -48, -95 };
	unsigned char HardInfo[MAX_LICENCE_SIZE], base64_out[MAX_LICENCE_SIZE], de[MAX_LICENCE_SIZE];
	memset(HardInfo, 0, MAX_LICENCE_SIZE);
	memset(base64_out, 0, MAX_LICENCE_SIZE);
	memset(de, 0, MAX_LICENCE_SIZE);

	if (file.Open(strDir, CFile::modeRead))
	{
		//��ȡ�ͻ�Ӳ����Ϣ��ͨ���ͻ��ṩ���ļ���
		int nBytes = file.Read(HardInfo, MAX_LICENCE_SIZE);

		int length = EVP_DecodeBlock(base64_out, HardInfo, nBytes);

		//EVP_DecodeBlock�ڲ�ͬ������EVP_DecodeInit + EVP_DecodeUpdate + Evp_DecodeFinalʵ�֣����ǲ�δ����β����'='�ַ�����˽���ַ�����������Ϊ3�ı���
		while (HardInfo[--nBytes] == '=')
			length--;

		Decrypt1(base64_out, length, de, key);
		file.Close();
	}

	return (CString)de;
}

CString CMacCpuInfoToolDlg::Decrypt_EncryptFile(CString strDir)
{
	USES_CONVERSION;

	CFile file;
	CString retStr;
	ModeInfo *pModeInfo = NULL;
	unsigned char buf[MAX_LICENCE_SIZE] = { 0 };
	unsigned char key[200] = { -87, -92, 112, 55, 105, 91, 0, -115, 118, -128, -10, 82, -1, 11, -48, -95 };
	unsigned char HardInfo[MAX_LICENCE_SIZE], base64_out[MAX_LICENCE_SIZE], de[MAX_LICENCE_SIZE];
	memset(HardInfo, 0, MAX_LICENCE_SIZE);
	memset(base64_out, 0, MAX_LICENCE_SIZE);
	memset(de, 0, MAX_LICENCE_SIZE);

	if (file.Open(strDir, CFile::modeRead))
	{
		int nBys = file.Read(buf, MAX_LICENCE_SIZE);
		file.Close();

		int length1 = EVP_DecodeBlock(base64_out, buf, nBys);

		while (buf[--nBys] == '=')
			length1--;

		Decrypt(base64_out, length1, de, key);

		//�����ַ����е�*�ŵĸ����ж���Ȩ��Ʒ����
		CString strProductNum[MAX_PRODUCT_COUNT];
		int productNum = 0;
		char * strBuf = strtok((char*)de, "*");
		for (int i = 0; strBuf != NULL; i++)
		{
			strProductNum[i] = strBuf;
			productNum++;
			strBuf = strtok(NULL, "*");
		}

		pModeInfo = new ModeInfo[productNum];
		memset(pModeInfo, 0, sizeof(ModeInfo)*productNum);
		if (NULL == pModeInfo) return NULL;

		retStr.Format(_T("��Ʒ������ %d\r\n"), productNum);

		for (int k = 0; k < productNum; k++)
		{
			char *ProdInfo = strtok(W2A(strProductNum[k].GetBuffer()), "#");
			g_strMchInfo.Format(_T("%S"), ProdInfo);
			retStr.Format(retStr + _T("\r\n----��%d����Ʒ----\r\n"), k+1);
			for (int j = 0; NULL != ProdInfo; j++)
			{
				ProdInfo = strtok(NULL, "#");
				if (j == 0)
					pModeInfo[k].processNum = atoi(ProdInfo);
				if (j == 1)
					pModeInfo[k].endTime_Year = atoi(ProdInfo);
				if (j == 2)
					pModeInfo[k].endTime_Month = atoi(ProdInfo);
				if (j == 3)
					pModeInfo[k].endTime_Day = atoi(ProdInfo);
				if (j == 4)
					pModeInfo[k].productId = atoi(ProdInfo);
			}
			retStr.Format(retStr + _T("��ƷID��%d\r\n��������%d\r\n��ֹʱ�䣺%d-%d-%d\r\n"),\
				pModeInfo[k].productId, pModeInfo[k].processNum, \
				pModeInfo[k].endTime_Year, pModeInfo[k].endTime_Month, pModeInfo[k].endTime_Day);
		}
	}
	return retStr;
}

void CMacCpuInfoToolDlg::OnBnClickedBtOpenfile()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CHAR szModuleName[_MAX_PATH] = { 0 };
	GetModuleFileNameA(GetModuleHandle(NULL), szModuleName, sizeof(szModuleName));
	CString defaultDir;	//Ĭ�ϴ򿪵��ļ�·��
	defaultDir.Format(L"%s", szModuleName);
	CString fileName = L"";			//Ĭ�ϴ򿪵��ļ���
	CString filter = L"�ļ� (*.*)|*.*||";	//�ļ����ǵ�����
	CFileDialog openFileDlg(true, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);
	INT_PTR result = openFileDlg.DoModal();
	CString filePath = defaultDir + "\\test.doc";
	if (result == IDOK) {
		filePath = openFileDlg.GetPathName();
	}
	else
	{
		filePath = "";
	}
	CString flName = filePath.Right(filePath.GetLength() - filePath.ReverseFind('\\') - 1);
	if (flName == MacCpuFile)
	{
		g_fileType = 1;
	}
	else if (flName == LiceFile)
	{
		g_fileType = 2;
	}
	else
	{
		g_fileType = 0;
		CString msgBuf;
		msgBuf.Format(_T("ѡ���ļ�����!\n������ѡ�� %s �� %s �ļ�!"), _T(MacCpuFile), _T(LiceFile));
		MessageBox(msgBuf, _T("��ʾ"), 0);
		filePath = "";
	}
	m_CfilePath.SetWindowTextW(filePath);
}


void CMacCpuInfoToolDlg::OnBnClickedBtReadfile()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString filePath;
	m_CfilePath.GetWindowTextW(filePath);
	if (g_fileType == 1)	//�������ļ�
	{
		m_CfileType.SetWindowTextW((LPCTSTR)_T("�������ļ�"));
		m_CmachineInfo.SetWindowTextW(Decrypt_MacCpuFile(filePath));
		m_CproductInfo.SetWindowTextW(NULL);
	}
	else if(g_fileType == 2)
	{
		m_CfileType.SetWindowTextW((LPCTSTR)_T("������Ȩ�ļ�"));
		m_CproductInfo.SetWindowTextW(Decrypt_EncryptFile(filePath));
		if (!g_strMchInfo.IsEmpty())
		{
			m_CmachineInfo.SetWindowTextW(g_strMchInfo);
		}
	}
	else
	{
		m_CfileType.SetWindowTextW(NULL);
		m_CmachineInfo.SetWindowTextW(NULL);
		m_CproductInfo.SetWindowTextW(NULL);
	}
}
