
// MacCpuInfoToolDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"


// CMacCpuInfoToolDlg �Ի���
class CMacCpuInfoToolDlg : public CDialogEx
{
// ����
public:
	CMacCpuInfoToolDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MACCPUINFOTOOL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString Decrypt_MacCpuFile(CString strDir);		// �����������ļ�
	CString Decrypt_EncryptFile(CString strDir);	// ����������Ȩ�ļ�
	void OnBnClickedBtOpenfile();
	void OnBnClickedBtReadfile();



public:
	// ��ʾ�ļ��б���Ļ�����Ϣ(����Mac��ַ��CPUID)
	CEdit m_CmachineInfo;
	// ��ʾ�ļ��в�Ʒ����Ȩ��Ϣ
	CEdit m_CproductInfo;
	// ��ʾ�ļ�����·��
	CEdit m_CfilePath;
	// ��ʾ��ȡ���ļ�����(�������ļ� or ������Ȩ�ļ�)
	CEdit m_CfileType;
};
