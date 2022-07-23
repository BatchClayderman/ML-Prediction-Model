
// MLPredictionModelDlg.h : 头文件
//

#pragma once


// CMLPredictionModelDlg 对话框
class CMLPredictionModelDlg : public CDialogEx
{
	// 构造
public:
	CMLPredictionModelDlg(CWnd* pParent = NULL);	// 标准构造函数
	void CMLPredictionModelDlg::DealCode();
	// 对话框数据
	enum { IDD = IDD_MLPredictionModel_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedButtonExcelin();
	afx_msg void OnBnClickedButtonExcelout();
	afx_msg void OnBnClickedUpdate();
	afx_msg void OnBnClickedSetdefault();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnBnClickedInputrun();
	afx_msg void OnBnClickedExcel();
	afx_msg void OnBnClickedDict();
	afx_msg void OnBnClickedInstruction();
	afx_msg void OnBnClickedButtonG();
	afx_msg void OnBnClickedPythonrun();
	afx_msg void OnClose();
	static UINT CMLPredictionModelDlg::callckdn(LPVOID lpParameter);
	UINT CMLPredictionModelDlg::checkDownload();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg BOOL OnHelpInfo(HELPINFO* pHelpInfo);
	afx_msg void OnDropFiles(HDROP hDropInfo);
	void CMLPredictionModelDlg::InValidAlert();
	afx_msg void OnBnClickedClearcache();
	afx_msg void OnBnClickedWebrun();
	void CMLPredictionModelDlg::DevelopMode();
	void CMLPredictionModelDlg::UpdateState(const char* state_msg);
};
