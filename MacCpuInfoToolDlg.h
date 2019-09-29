
// MacCpuInfoToolDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CMacCpuInfoToolDlg 对话框
class CMacCpuInfoToolDlg : public CDialogEx
{
// 构造
public:
	CMacCpuInfoToolDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MACCPUINFOTOOL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString Decrypt_MacCpuFile(CString strDir);		// 解析机器码文件
	CString Decrypt_EncryptFile(CString strDir);	// 解析离线授权文件
	void OnBnClickedBtOpenfile();
	void OnBnClickedBtReadfile();



public:
	// 显示文件中保存的机器信息(包含Mac地址和CPUID)
	CEdit m_CmachineInfo;
	// 显示文件中产品的授权信息
	CEdit m_CproductInfo;
	// 显示文件绝对路径
	CEdit m_CfilePath;
	// 显示读取的文件类型(机器码文件 or 离线授权文件)
	CEdit m_CfileType;
};
