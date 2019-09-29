
// MacCpuInfoToolDlg.cpp : 实现文件
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

//把BYTE合成DWORD
#define MAKE_DWORD(a3, a2, a1, a0) ((DWORD)a3<<24 | (DWORD)a2<<16 | (DWORD)a1<<8 | (DWORD)a0) 
//把DWORD拆分成BYTE
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

int g_fileType = 0;		//1表示机器码文件； 2表示离线授权文件
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


// CMacCpuInfoToolDlg 消息处理程序

BOOL CMacCpuInfoToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMacCpuInfoToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMacCpuInfoToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void encrypt(unsigned char* in, int inl, unsigned char *out, int* len, unsigned char * key)
{
	unsigned char iv[8];
	EVP_CIPHER_CTX ctx;
	//此init做的仅是将ctx内存 memset为0  
	EVP_CIPHER_CTX_init(&ctx);

	//cipher  = EVP_aes_128_ecb();  
	//原型为int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv)   
	//另外对于ecb电子密码本模式来说，各分组独立加解密，前后没有关系，也用不着iv  
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, iv);

	*len = 0;
	int outl = 0;
	//这个EVP_EncryptUpdate的实现实际就是将in按照inl的长度去加密，实现会取得该cipher的块大小（对aes_128来说是16字节）并将block-size的整数倍去加密。
	//如果输入为50字节，则此处仅加密48字节，outl也为48字节。输入in中的最后两字节拷贝到ctx->buf缓存起来。  
	//对于inl为block_size整数倍的情形，且ctx->buf并没有以前遗留的数据时则直接加解密操作，省去很多后续工作。  
	EVP_EncryptUpdate(&ctx, out + *len, &outl, in + *len, inl);
	*len += outl;
	//余下最后n字节。此处进行处理。
	//如果不支持pading，且还有数据的话就出错，否则，将block_size-待处理字节数个数个字节设置为此个数的值，如block_size=16,数据长度为4，则将后面的12字节设置为16-4=12，补齐为一个分组后加密 
	//对于前面为整分组时，如输入数据为16字节，最后再调用此Final时，不过是对16个0进行加密，此密文不用即可，也根本用不着调一下这Final。
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
	//此init做的仅是将ctx内存 memset为0  
	EVP_CIPHER_CTX_init(&ctx);

	//cipher  = EVP_aes_128_ecb();  
	//原型为int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv)   
	//另外对于ecb电子密码本模式来说，各分组独立加解密，前后没有关系，也用不着iv  
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
	//此init做的仅是将ctx内存 memset为0  
	EVP_CIPHER_CTX_init(&ctx);

	//cipher  = EVP_aes_128_ecb();  
	//原型为int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv)   
	//另外对于ecb电子密码本模式来说，各分组独立加解密，前后没有关系，也用不着iv  
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
		strDevErr.Format(_T("获取设备属性有误！WMI_DeviceQuery 错误码：%d"), err);
		MessageBox(NULL, strDevErr, _T("提示"), 0);
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
		//读取客户硬件信息（通过客户提供的文件）
		int nBytes = file.Read(HardInfo, MAX_LICENCE_SIZE);

		int length = EVP_DecodeBlock(base64_out, HardInfo, nBytes);

		//EVP_DecodeBlock内部同样调用EVP_DecodeInit + EVP_DecodeUpdate + Evp_DecodeFinal实现，但是并未处理尾部的'='字符，因此结果字符串长度总是为3的倍数
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

		//根据字符串中的*号的个数判断授权产品数量
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

		retStr.Format(_T("产品总数： %d\r\n"), productNum);

		for (int k = 0; k < productNum; k++)
		{
			char *ProdInfo = strtok(W2A(strProductNum[k].GetBuffer()), "#");
			g_strMchInfo.Format(_T("%S"), ProdInfo);
			retStr.Format(retStr + _T("\r\n----第%d个产品----\r\n"), k+1);
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
			retStr.Format(retStr + _T("产品ID：%d\r\n进程数：%d\r\n截止时间：%d-%d-%d\r\n"),\
				pModeInfo[k].productId, pModeInfo[k].processNum, \
				pModeInfo[k].endTime_Year, pModeInfo[k].endTime_Month, pModeInfo[k].endTime_Day);
		}
	}
	return retStr;
}

void CMacCpuInfoToolDlg::OnBnClickedBtOpenfile()
{
	// TODO: 在此添加控件通知处理程序代码
	CHAR szModuleName[_MAX_PATH] = { 0 };
	GetModuleFileNameA(GetModuleHandle(NULL), szModuleName, sizeof(szModuleName));
	CString defaultDir;	//默认打开的文件路径
	defaultDir.Format(L"%s", szModuleName);
	CString fileName = L"";			//默认打开的文件名
	CString filter = L"文件 (*.*)|*.*||";	//文件过虑的类型
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
		msgBuf.Format(_T("选择文件有误!\n请重新选择 %s 或 %s 文件!"), _T(MacCpuFile), _T(LiceFile));
		MessageBox(msgBuf, _T("提示"), 0);
		filePath = "";
	}
	m_CfilePath.SetWindowTextW(filePath);
}


void CMacCpuInfoToolDlg::OnBnClickedBtReadfile()
{
	// TODO: 在此添加控件通知处理程序代码
	CString filePath;
	m_CfilePath.GetWindowTextW(filePath);
	if (g_fileType == 1)	//机器码文件
	{
		m_CfileType.SetWindowTextW((LPCTSTR)_T("机器码文件"));
		m_CmachineInfo.SetWindowTextW(Decrypt_MacCpuFile(filePath));
		m_CproductInfo.SetWindowTextW(NULL);
	}
	else if(g_fileType == 2)
	{
		m_CfileType.SetWindowTextW((LPCTSTR)_T("离线授权文件"));
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
