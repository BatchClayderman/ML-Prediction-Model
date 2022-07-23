
// MLPredictionModelDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MLPredictionModel.h"
#include "MLPredictionModelDlg.h"
#include "afxdialogex.h"
#ifdef WIN32
#include <WinInet.h>
#endif
#pragma comment(lib, "Wininet.lib")//编译时请务必使用静态编译
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Version.lib ")
#ifdef _DEBUG
#ifdef DEBUG_NEW
#define new DEBUG_NEW
#endif
#endif


/* 定义状态码 */
#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif
#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif
#ifndef EOF
#define EOF (-1)
#endif
#ifndef EEOF
#define EEOF (-2)
#endif
#ifndef FAILURE_BUSY
#define FAILURE_BUSY 5
#endif
#ifndef FAILURE_MODULE
#define FAILURE_MODULE 4
#endif
#ifndef FAILURE_LOAD
#define FAILURE_LOAD 3
#endif
#ifndef FAILURE_OUTPUT
#define FAILURE_OUTPUT 2
#endif
#ifndef FAILURE_INPUT
#define FAILURE_INPUT 1
#endif
#ifndef EnoughTime
#define EnoughTime 5
#endif

/* 文件名宏定义 */
#ifndef String_Valid
#define String_Valid(x) (x == '.' || (x >= '0' && x <= '9'))
#endif//字符串合法
#ifndef Int_Valid
#define Int_Valid(x) (x >= 0 && x <= 100)
#endif//数值合法
#ifndef ExeSingleFile
#define ExeSingleFile "predict.exe"
#endif
#ifndef ExeBatchFile
#define ExeBatchFile "batch.exe"
#endif
#ifndef PythonSingleFile
#define PythonSingleFile "predict.py"
#endif
#ifndef PythonBatchFile
#define PythonBatchFile "batch.py"
#endif
#ifndef InputDefaultName
#define InputDefaultName "test"
#endif
#ifndef OutputDefaultName
#define OutputDefaultName "Output"
#endif
#ifndef LogIn
#define LogIn "LogIn.log"
#endif
#ifndef LogOut
#define LogOut "LogOut.log"
#endif
#ifndef DictIN
#define DictIN "input.txt"
#endif
#ifndef DictOUT
#define DictOUT "output.txt"
#endif
#ifndef HTEXT
#define HTEXT "help.txt"
#endif
#ifndef LocalSettings
#define LocalSettings
#ifndef AllTitle
#define AllTitle L"ML Prediction Software"
#endif
#ifndef zipLocal
#define zipLocal "\\MLPM.zip"
#endif
#ifndef exeLocal
#define exeLocal "\\MLPM.exe"
#endif
#endif
#ifndef RemoteSettings
#define RemoteSettings
#ifdef UNICODE
#define zipRemote L"https://cloud-inspired.goosebt.com/1/MLPM.zip"
#define exeRemote L"https://cloud-inspired.goosebt.com/1/MLPM.exe"
#define VersionUrl L"https://cloud-inspired.goosebt.com/1/MLPM.txt"
#define WebRun L"http://balical.club:8111/pages/Home.html#"
#define versionTmp L"version.tmp"
#define lockTmp L"lock.tmp"
#else
#define zipRemote "https://cloud-inspired.goosebt.com/1/MLPM.zip"
#define exeRemote "https://cloud-inspired.goosebt.com/1/MLPM.exe"
#define VersionUrl "https://cloud-inspired.goosebt.com/1/MLPM.txt"
#define WebRun "http://balical.club:8111/pages/Home.html#"
#define versionTmp "version.tmp"
#define lockTmp "lock.tmp"
#endif
#endif

#include <iostream>
#include <string>
#include <vector>
using namespace std;

typedef BOOL(_stdcall* WOW64_DISABLE_FSDIR)(PVOID*);
typedef BOOL(_stdcall* WOW64_REVERT_FSDIR) (PVOID);
typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
bool Downloading = false, UseEXE = true, tipsOnce = true, tmpWebRun = true;
short int UseMethod = 1, clickedTime = 1, CloseByThread = 0;
int ReturnValue = NULL;
DWORD ChildProcessId = NULL;
string strFolderPath = "", Inpath, Outpath, DefaultDict = "{'gender':0, 'age':74, 'vasopressin':0, 'urineoutput': 1736.0,'heartrate_mean':70.76,'sysbp_mean':122.4, 'diasbp_mean':49.88,'resprate_mean':14.96, 'tempc_mean':36.37 , 'spo2_mean':95.4,'baseexcess_mean':3.8, 'totalco2_mean':25.94, 'calcium_mean':1.13,'lactate_mean':2.3,'pco2_mean':38.83, 'ph_mean':7.42, 'po2_mean':177.88,'coronary heart disease.csv':0, 'diabetes.csv':0, 'family history of stroke.csv':0,'creatinine.csv_mean':0.66,'glucose.csv_mean':108.06, 'platelet.csv_mean':198.93,'potassium.csv_mean':3.88,'sodium.csv_mean':139.66, 'urea nitrogen.csv_mean':20.47,'WBC.csv_mean':9.71, 'aniongap':9.00,'bicarbonate':22.5, 'hematocrit':25.00,'hemoglobin':8.6, 'ptt':43.80, 'inr':1.25, 'pt':14.40, 'BMI':24.41}";
FILE* global_fp;
HHOOK hHook;


// 自变量结构体
struct input_set
{
	char option[35] = { 0 };
	CString DefaultSum = "";//默认值
};
input_set input_variables[35];

void InitLoadOption()
{
	strcpy_s(input_variables[0].option, "gender");
	strcpy_s(input_variables[1].option, "age");
	strcpy_s(input_variables[2].option, "vasopressin");
	strcpy_s(input_variables[3].option, "urineoutput");
	strcpy_s(input_variables[4].option, "heartrate_mean");

	strcpy_s(input_variables[5].option, "sysbp_mean");
	strcpy_s(input_variables[6].option, "diasbp_mean");
	strcpy_s(input_variables[7].option, "resprate_mean");
	strcpy_s(input_variables[8].option, "tempc_mean");
	strcpy_s(input_variables[9].option, "spo2_mean");

	strcpy_s(input_variables[10].option, "baseexcess_mean");
	strcpy_s(input_variables[11].option, "totalco2_mean");
	strcpy_s(input_variables[12].option, "calcium_mean");
	strcpy_s(input_variables[13].option, "lactate_mean");
	strcpy_s(input_variables[14].option, "pco2_mean");

	strcpy_s(input_variables[15].option, "ph_mean");
	strcpy_s(input_variables[16].option, "po2_mean");
	strcpy_s(input_variables[17].option, "coronary heart disease.csv");
	strcpy_s(input_variables[18].option, "diabetes.csv");
	strcpy_s(input_variables[19].option, "family history of stroke.csv");

	strcpy_s(input_variables[20].option, "creatinine.csv_mean");
	strcpy_s(input_variables[21].option, "glucose.csv_mean");
	strcpy_s(input_variables[22].option, "platelet.csv_mean");
	strcpy_s(input_variables[23].option, "potassium.csv_mean");
	strcpy_s(input_variables[24].option, "sodium.csv_mean");

	strcpy_s(input_variables[25].option, "urea nitrogen.csv_mean");
	strcpy_s(input_variables[26].option, "WBC.csv_mean");
	strcpy_s(input_variables[27].option, "aniongap");
	strcpy_s(input_variables[28].option, "bicarbonate");
	strcpy_s(input_variables[29].option, "hematocrit");

	strcpy_s(input_variables[30].option, "hemoglobin");
	strcpy_s(input_variables[31].option, "ptt");
	strcpy_s(input_variables[32].option, "inr");
	strcpy_s(input_variables[33].option, "pt");
	strcpy_s(input_variables[34].option, "BMI");

	return;
};

void InitLoadDefault()
{
	input_variables[0].DefaultSum = "0";
	input_variables[1].DefaultSum = "74";
	input_variables[2].DefaultSum = "0";
	input_variables[3].DefaultSum = "1736.0";
	input_variables[4].DefaultSum = "70.76";

	input_variables[5].DefaultSum = "122.4";
	input_variables[6].DefaultSum = "49.88";
	input_variables[7].DefaultSum = "14.96";
	input_variables[8].DefaultSum = "36.37";
	input_variables[9].DefaultSum = "95.4";

	input_variables[10].DefaultSum = "3.8";
	input_variables[11].DefaultSum = "25.94";
	input_variables[12].DefaultSum = "1.13";
	input_variables[13].DefaultSum = "2.3";
	input_variables[14].DefaultSum = "38.83";

	input_variables[15].DefaultSum = "7.42";
	input_variables[16].DefaultSum = "177.88";
	input_variables[17].DefaultSum = "0";
	input_variables[18].DefaultSum = "0";
	input_variables[19].DefaultSum = "0";

	input_variables[20].DefaultSum = "0.66";
	input_variables[21].DefaultSum = "108.06";
	input_variables[22].DefaultSum = "198.93";
	input_variables[23].DefaultSum = "3.88";
	input_variables[24].DefaultSum = "139.66";

	input_variables[25].DefaultSum = "20.47";
	input_variables[26].DefaultSum = "9.71";
	input_variables[27].DefaultSum = "9.00";
	input_variables[28].DefaultSum = "22.5";
	input_variables[29].DefaultSum = "25.00";

	input_variables[30].DefaultSum = "8.6";
	input_variables[31].DefaultSum = "43.80";
	input_variables[32].DefaultSum = "1.25";
	input_variables[33].DefaultSum = "14.40";
	input_variables[34].DefaultSum = "24.41";

	return;
}

void InitLoadMax()
{
	// TODO
	return;
}

void InitLoadMin()
{
	// TODO
	return;
}

void InitLoad()
{
	InitLoadOption();
	InitLoadDefault();
	InitLoadMax();
	InitLoadMin();
	return;
}


/* 优化部分 */
BOOL IsWow64()//判断是否为 Wow64
{
	BOOL bIsWow64 = FALSE;
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	HMODULE hmodule = ::GetModuleHandle(TEXT("kernel32"));
	if (!hmodule)
	{
		//TODO
		return FALSE;//默认不关闭
	}
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)::GetProcAddress(hmodule, "IsWow64Process");
	if (NULL != fnIsWow64Process)
		if (!fnIsWow64Process(::GetCurrentProcess(), &bIsWow64))
		{
			//TODO
			return FALSE;//默认不关闭
		}
	return bIsWow64;
}

BOOL WOW64FsDir(BOOL bDisable)//关闭重定向
{
	static WOW64_DISABLE_FSDIR pfnDisable = NULL;
	static WOW64_REVERT_FSDIR pfnrevert = NULL;
	static PVOID OldValue = NULL;
	static BOOL bInit = FALSE;
	if (!bInit && IsWow64())//if (!bInit && OVI_IS64(g_OsVer))
	{
		HMODULE hMod = LoadLibrary(TEXT("kernel32.dll"));
		if (hMod)
		{
			pfnDisable = (WOW64_DISABLE_FSDIR)GetProcAddress(hMod, "Wow64DisableWow64FsRedirection");
			pfnrevert = (WOW64_REVERT_FSDIR)GetProcAddress(hMod, "Wow64RevertWow64FsRedirection");
		}
		if (pfnDisable == NULL || pfnrevert == NULL)
			return FALSE;
		bInit = TRUE;
	}
	if (IsWow64())//if (OVI_IS64(g_OsVer))
	{
		if (bDisable)
			return pfnDisable(&OldValue);
		else
			return pfnrevert(OldValue);
	}
	return TRUE;
}

BOOL FindFirstFileExists(LPCTSTR lpPath, BOOL dwFilter)//检查文件是否存在
{
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(lpPath, &fd);
	BOOL bFilter = (FALSE == dwFilter) ? TRUE : fd.dwFileAttributes & dwFilter;
	BOOL RetValue = ((hFind != INVALID_HANDLE_VALUE) && bFilter) ? TRUE : FALSE;
	if (RetValue == FALSE)
	{
		TCHAR SystemPath[MAX_PATH];
		GetSystemDirectory(SystemPath, MAX_PATH);
#ifdef UNICODE
		TCHAR* _str = new TCHAR[lstrlen(SystemPath) + lstrlen(L"\\") + lstrlen(lpPath) + 1];
#else
		TCHAR* _str = new TCHAR[lstrlen(SystemPath) + lstrlen("\\") + lstrlen(lpPath) + 1];
#endif
		if (_str)
		{
			_str[0] = _T('\0');
			lstrcat(_str, SystemPath);
#ifdef UNICODE
			lstrcat(_str, L"\\");
#else
			lstrcat(_str, "\\");
#endif
			lstrcat(_str, lpPath);
			WIN32_FIND_DATA _fd;
			HANDLE _hFind = FindFirstFile(_str, &_fd);
			BOOL _bFilter = (FALSE == dwFilter) ? TRUE : _fd.dwFileAttributes & dwFilter;
			BOOL _RetValue = ((_hFind != INVALID_HANDLE_VALUE) && _bFilter) ? TRUE : FALSE;
			RetValue = _RetValue;
			delete[]_str;
			FindClose(_hFind);
		}
	}
	FindClose(hFind);
	return RetValue;
}

#ifdef WIN32
string GF_GetEXEPath()
{
	char FilePath[MAX_PATH];
	GetModuleFileNameA(NULL, FilePath, MAX_PATH);
	(strrchr(FilePath, '\\'))[1] = 0;
	return string(FilePath);
}
#else
string GF_GetEXEPath()
{
	int rval;
	char link_target[4096];
	char* last_slash;
	size_t result_Length;
	char* result;
	string strExeDir;
	rval = readlink("/proc/self/exe", link_target, 4096);
	if (rval < 0 || rval >= 1024)
		return "";
	link_target[rval] = 0;
	last_slash = strrchr(link_target, '/');
	if (last_slash == 0 || last_slash == link_target)
		return "";
	result_Length = last_slash - link_target;
	result = (char*)malloc(result_Length + 1);
	strncpy(result, link_target, result_Length);
	result[result_Length] = 0;
	strExeDir.append(result);
	strExeDir.append("/");
	free(result);
	return strExeDir;
}
#endif

BOOL AvoidBug()//处理一般不会考虑的问题
{
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);//更改优先级
	SetProcessPriorityBoost(GetCurrentProcess(), FALSE);//锁定优先级
	if (::IsWow64())//关闭重定向
		::WOW64FsDir(TRUE);
	fopen_s(&global_fp, (GF_GetEXEPath() + lockTmp).c_str(), "w");
	if (global_fp)
		return TRUE;
	else
		return FALSE;
}

LRESULT __stdcall CBTHookProc(long nCode, WPARAM wParam, LPARAM lParam)//并发编程 Funtion1
{
	if (nCode == HCBT_ACTIVATE)
	{
		SetDlgItemText((HWND)wParam, IDOK, TEXT("Abort"));
		UnhookWindowsHookEx(hHook);
	}
	return 0;
}


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMLPredictionModelDlg 对话框




CMLPredictionModelDlg::CMLPredictionModelDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CMLPredictionModelDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMLPredictionModelDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMLPredictionModelDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CMLPredictionModelDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON_EXCELIN, &CMLPredictionModelDlg::OnBnClickedButtonExcelin)
	ON_BN_CLICKED(IDC_BUTTON_EXCELOUT, &CMLPredictionModelDlg::OnBnClickedButtonExcelout)
	ON_BN_CLICKED(IDC_UPDATE, &CMLPredictionModelDlg::OnBnClickedUpdate)
	ON_BN_CLICKED(IDC_SETDEFAULT, &CMLPredictionModelDlg::OnBnClickedSetdefault)
	ON_WM_CTLCOLOR()
	ON_BN_CLICKED(IDC_INPUTRUN, &CMLPredictionModelDlg::OnBnClickedInputrun)
	ON_BN_CLICKED(IDC_EXCEL, &CMLPredictionModelDlg::OnBnClickedExcel)
	ON_BN_CLICKED(IDC_DICT, &CMLPredictionModelDlg::OnBnClickedDict)
	ON_BN_CLICKED(IDC_INSTRUCTION, &CMLPredictionModelDlg::OnBnClickedInstruction)
	ON_BN_CLICKED(IDC_BUTTON_G, &CMLPredictionModelDlg::OnBnClickedButtonG)
	ON_WM_SIZE()
	ON_BN_CLICKED(IDC_PythonRun, &CMLPredictionModelDlg::OnBnClickedPythonrun)
	ON_WM_CLOSE()
	ON_WM_HELPINFO()
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_ClearCache, &CMLPredictionModelDlg::OnBnClickedClearcache)
	ON_BN_CLICKED(IDC_WebRun, &CMLPredictionModelDlg::OnBnClickedWebrun)
END_MESSAGE_MAP()


// CMLPredictionModelDlg 消息处理程序

BOOL CMLPredictionModelDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	//ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	//ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	InitLoad();
	if (!AvoidBug())
	{
		AfxMessageBox("Another instance is running, please check the activity progress table if necessary.");
		exit(EXIT_FAILURE);
	}

	/* 设置默认值 */
	((CButton*)GetDlgItem(IDC_ExeRun))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_PythonRun))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_EXCEL))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_MALE))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_FEMALE))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO1))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO2))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO3))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO4))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO5))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO6))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO7))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO8))->SetCheck(TRUE);

	GetDlgItem(IDC_EDIT_1)->SetWindowTextA(input_variables[1].DefaultSum);
	GetDlgItem(IDC_EDIT_2)->SetWindowTextA(input_variables[34].DefaultSum);
	GetDlgItem(IDC_EDIT_4)->SetWindowTextA(input_variables[3].DefaultSum);
	GetDlgItem(IDC_EDIT_6)->SetWindowTextA(input_variables[4].DefaultSum);
	GetDlgItem(IDC_EDIT_7)->SetWindowTextA(input_variables[7].DefaultSum);
	GetDlgItem(IDC_EDIT_8)->SetWindowTextA(input_variables[8].DefaultSum);
	GetDlgItem(IDC_EDIT_9)->SetWindowTextA(input_variables[5].DefaultSum);
	GetDlgItem(IDC_EDIT_11)->SetWindowTextA(input_variables[6].DefaultSum);
	GetDlgItem(IDC_EDIT_15)->SetWindowTextA(input_variables[21].DefaultSum);
	GetDlgItem(IDC_EDIT_16)->SetWindowTextA(input_variables[22].DefaultSum);
	GetDlgItem(IDC_EDIT_17)->SetWindowTextA(input_variables[23].DefaultSum);
	GetDlgItem(IDC_EDIT_18)->SetWindowTextA(input_variables[24].DefaultSum);
	GetDlgItem(IDC_EDIT_19)->SetWindowTextA(input_variables[26].DefaultSum);
	GetDlgItem(IDC_EDIT_20)->SetWindowTextA(input_variables[28].DefaultSum);
	GetDlgItem(IDC_EDIT_21)->SetWindowTextA(input_variables[29].DefaultSum);
	GetDlgItem(IDC_EDIT_22)->SetWindowTextA(input_variables[32].DefaultSum);
	GetDlgItem(IDC_EDIT_23)->SetWindowTextA(input_variables[13].DefaultSum);
	GetDlgItem(IDC_EDIT_24)->SetWindowTextA(input_variables[14].DefaultSum);
	GetDlgItem(IDC_EDIT_25)->SetWindowTextA(input_variables[15].DefaultSum);
	GetDlgItem(IDC_EDIT_26)->SetWindowTextA(input_variables[16].DefaultSum);
	GetDlgItem(IDC_EDIT_27)->SetWindowTextA(input_variables[9].DefaultSum);
	GetDlgItem(IDC_EDIT_28)->SetWindowTextA(input_variables[10].DefaultSum);
	GetDlgItem(IDC_EDIT_29)->SetWindowTextA(input_variables[11].DefaultSum);
	GetDlgItem(IDC_EDIT_30)->SetWindowTextA(input_variables[12].DefaultSum);
	GetDlgItem(IDC_EDIT_31)->SetWindowTextA(input_variables[20].DefaultSum);
	GetDlgItem(IDC_EDIT_32)->SetWindowTextA(input_variables[25].DefaultSum);
	GetDlgItem(IDC_EDIT_33)->SetWindowTextA(input_variables[27].DefaultSum);
	GetDlgItem(IDC_EDIT_34)->SetWindowTextA(input_variables[30].DefaultSum);
	GetDlgItem(IDC_EDIT_35)->SetWindowTextA(input_variables[31].DefaultSum);
	GetDlgItem(IDC_EDIT_36)->SetWindowTextA(input_variables[33].DefaultSum);

	GetDlgItem(IDC_EDIT_37)->SetWindowTextA("");
	GetDlgItem(IDC_EDIT_38)->SetWindowTextA("");
	GetDlgItem(IDC_EDIT_39)->SetWindowTextA("");
	GetDlgItem(IDC_EDIT_40)->SetWindowTextA("");

	GetDlgItem(IDC_EDIT_DICTRUN)->SetWindowTextA(DefaultDict.c_str());
	CMLPredictionModelDlg::OnBnClickedExcel();
	CWinThread* dThread = AfxBeginThread(callckdn, this);//并发线程检查更新
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMLPredictionModelDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMLPredictionModelDlg::OnPaint()
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
HCURSOR CMLPredictionModelDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

UINT __cdecl GetCode(LPVOID lpParameter)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);
	char cmd[MAX_PATH << 2] = { 0 };
	if (UseEXE)
		strcpy_s(cmd, "\"");
	else
		//strcpy_s(cmd, "cmd /k python \"");//调试的时候用的
		strcpy_s(cmd, "python.exe \"");//原来调试时用的

	switch (UseMethod)
	{
	case 4://批处值
		if (UseEXE)
			strcat_s(cmd, (GF_GetEXEPath() + ExeBatchFile + "\" \"" + Inpath + "\" \"" + Outpath + "\"").c_str());
		else
			strcat_s(cmd, (GF_GetEXEPath() + PythonBatchFile + "\" \"" + Inpath + "\" \"" + Outpath + "\"").c_str());
		break;
	default://默认值
		if (UseEXE)
			strcat_s(cmd, (GF_GetEXEPath() + ExeSingleFile + "\"").c_str());
		else
			strcat_s(cmd, (GF_GetEXEPath() + PythonSingleFile + "\"").c_str());
		break;
	}
	BOOL working = ::CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW/*NORMAL_PRIORITY_CLASS*/, NULL, NULL, &si, &pi);
	if (working == 0)
	{
		Sleep(MAX_PATH << 2);
		HANDLE hWnd = ::FindWindowEx(NULL, NULL, NULL, "Running...");
		//HANDLE hWnd = ::GetForegroundWindow();
		if (hWnd)
		{
			CloseByThread = -1;
			::SendMessage((HWND)hWnd, WM_CLOSE, NULL, NULL);
		}
		AfxMessageBox("Failed to conduct remote procedure, please make sure no components are missing!");
		CloseHandle(pi.hProcess);//记得关闭句柄
		CloseHandle(pi.hThread);
		ChildProcessId = NULL;
		ReturnValue = EOF;
		return ReturnValue;//无意义
	}
	ChildProcessId = pi.dwProcessId;
	//WaitForSingleObject(pi.hProcess, INFINITE);
	HANDLE SingleObject[1] = { pi.hProcess };
	MsgWaitForMultipleObjects(1, SingleObject, FALSE, INFINITE, QS_ALLINPUT);
	unsigned long Result = NULL;//恒 >= 0
	GetExitCodeProcess(pi.hProcess, &Result);
	CloseHandle(pi.hProcess);//记得关闭句柄
	CloseHandle(pi.hThread);
	if (ChildProcessId == EEOF)
	{
		ChildProcessId = NULL;
		ReturnValue = EEOF;
		return ReturnValue;//无意义
	}
	ChildProcessId = NULL;
	ReturnValue = Result;
	HANDLE hWnd = ::FindWindowEx(NULL, NULL, NULL, "Running...");
	//HANDLE hWnd = ::GetForegroundWindow();
	if (hWnd)
	{
		CloseByThread = 1;
		::SendMessage((HWND)hWnd, WM_CLOSE, NULL, NULL);
	}
	return ReturnValue;//无意义
}

void CMLPredictionModelDlg::InValidAlert()//处理异常数值
{
	CMLPredictionModelDlg::UpdateState("Please check your input...");
	this->EnableWindow(TRUE);
	return;
}

void CMLPredictionModelDlg::OnBnClickedOk()
{
	this->EnableWindow(FALSE);
	FILE* fp;
	CMLPredictionModelDlg::UpdateState("Running");
	CButton* pABC = (CButton*)GetDlgItem(IDC_ExeRun);
	UseEXE = (bool)(pABC->GetCheck());
	if (UseMethod == 1 || UseMethod == 2)//每一个 if 里面都要声明 if 语句内变量，因此不使用 switch
	{
		CButton* p2;
		CString DictText = "", tmpString;
		DictText += "{'gender':";
		p2 = (CButton*)GetDlgItem(IDC_MALE);
		if (p2->GetCheck())
			DictText += "1";
		else
			DictText += "0";
		DictText += ", 'age':";
		GetDlgItem(IDC_EDIT_1)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789")) != tmpString)
		{
			AfxMessageBox("Age invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'vasopressin':";
		p2 = (CButton*)GetDlgItem(IDC_RADIO1);
		if (p2->GetCheck())
			DictText += "1";
		else
			DictText += "0";
		DictText += ", 'urineoutput':";
		GetDlgItem(IDC_EDIT_4)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Day urine output invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'heartrate_mean':";
		GetDlgItem(IDC_EDIT_6)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Heart rate invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'sysbp_mean':";
		GetDlgItem(IDC_EDIT_9)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Systolic blood pressure invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'diasbp_mean':";
		GetDlgItem(IDC_EDIT_11)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Diastolic blood pressure invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'resprate_mean':";
		GetDlgItem(IDC_EDIT_7)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Respiratory rate invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'tempc_mean':";
		GetDlgItem(IDC_EDIT_8)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Body temperature invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'spo2_mean':";
		GetDlgItem(IDC_EDIT_27)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("SPO2 invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'baseexcess_mean':";
		GetDlgItem(IDC_EDIT_28)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Base excess invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'totalco2_mean':";
		GetDlgItem(IDC_EDIT_29)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Total CO2 invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'calcium_mean':";
		GetDlgItem(IDC_EDIT_30)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Calcium invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'lactate_mean':";
		GetDlgItem(IDC_EDIT_23)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Lactate invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'pco2_mean':";
		GetDlgItem(IDC_EDIT_24)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("PCO2 invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'ph_mean':";
		GetDlgItem(IDC_EDIT_25)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("PH invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'po2_mean':";
		GetDlgItem(IDC_EDIT_26)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("PO2 invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'coronary heart disease.csv':";
		p2 = (CButton*)GetDlgItem(IDC_RADIO3);
		if (p2->GetCheck())
			DictText += "1";
		else
			DictText += "0";
		DictText += ", 'diabetes.csv':";
		p2 = (CButton*)GetDlgItem(IDC_RADIO5);
		if (p2->GetCheck())
			DictText += "1";
		else
			DictText += "0";
		DictText += ", 'family history of stroke.csv':";
		p2 = (CButton*)GetDlgItem(IDC_RADIO7);
		if (p2->GetCheck())
			DictText += "1";
		else
			DictText += "0";
		DictText += ", 'creatinine.csv_mean':";
		GetDlgItem(IDC_EDIT_31)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Serum creatinine invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'glucose.csv_mean':";
		GetDlgItem(IDC_EDIT_15)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Glucose invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'platelet.csv_mean':";
		GetDlgItem(IDC_EDIT_16)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Platelet invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'potassium.csv_mean':";
		GetDlgItem(IDC_EDIT_17)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Potassium invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'sodium.csv_mean':";
		GetDlgItem(IDC_EDIT_18)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Sodium invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'urea nitrogen.csv_mean':";
		GetDlgItem(IDC_EDIT_32)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Urea nitrogen invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'WBC.csv_mean':";
		GetDlgItem(IDC_EDIT_19)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("WBC invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'aniongap':";
		GetDlgItem(IDC_EDIT_33)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Anion gap invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'bicarbonate':";
		GetDlgItem(IDC_EDIT_20)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Bicarbonate invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'hematocrit':";
		GetDlgItem(IDC_EDIT_21)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Hematocrit invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'hemoglobin':";
		GetDlgItem(IDC_EDIT_34)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("Hemoglobin invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'ptt':";
		GetDlgItem(IDC_EDIT_35)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("PTT invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'inr':";
		GetDlgItem(IDC_EDIT_22)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("INR invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'pt':";
		GetDlgItem(IDC_EDIT_36)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("PT invalid!");
			CMLPredictionModelDlg::InValidAlert();
			return;
		}
		DictText += tmpString;
		DictText += ", 'BMI':";
		GetDlgItem(IDC_EDIT_2)->GetWindowTextA(tmpString);
		if (tmpString.GetLength() == 0 || tmpString.SpanIncluding(_T("0123456789.")) != tmpString)
		{
			AfxMessageBox("BMI invalid!");
			CMLPredictionModelDlg::UpdateState("Ready");
			this->EnableWindow(TRUE);
			return;
		}
		DictText += tmpString;
		DictText += "}";
		fopen_s(&fp, (GF_GetEXEPath() + DictIN).c_str(), "w");
		if (fp == NULL)
		{
			AfxMessageBox("Failed to write file!");
			CMLPredictionModelDlg::UpdateState("Ready");
			this->EnableWindow(TRUE);
			return;//记得
		}
		fputs(DictText, fp);
		fclose(fp);
	}
	else if (UseMethod == 3)
	{
		CString DictText = "";
		GetDlgItem(IDC_EDIT_DICTRUN)->GetWindowTextA(DictText);
		fopen_s(&fp, (GF_GetEXEPath() + DictIN).c_str(), "w");
		if (fp == NULL)
		{
			AfxMessageBox("Failed to write file!");
			CMLPredictionModelDlg::UpdateState("Ready");
			this->EnableWindow(TRUE);
			return;//记得
		}
		fputs(DictText, fp);
		fclose(fp);
	}
	else if (UseMethod == 4)
	{
		CString FinalInpath = "", FinalOutpath = "";
		GetDlgItem(IDC_EDIT_EXCELIN)->GetWindowTextA(FinalInpath);
		GetDlgItem(IDC_EDIT_EXCELOUT)->GetWindowTextA(FinalOutpath);
		Inpath = FinalInpath.GetBuffer(0);
		Outpath = FinalOutpath.GetBuffer(0);
		Inpath.erase(remove(Inpath.begin(), Inpath.end(), '\"'), Inpath.end());
		Outpath.erase(remove(Outpath.begin(), Outpath.end(), '\"'), Outpath.end());
		if (Inpath == "" || Outpath == "")
		{
			AfxMessageBox("Please enter file path");
			CMLPredictionModelDlg::UpdateState("Ready");
			this->EnableWindow(TRUE);
			return;//记得
		}
		FinalOutpath = Outpath.c_str();
		if (FindFirstFileExists(FinalOutpath, FALSE))
			if (MessageBoxW(NULL, L"File is already exists, are you sure to cover it?", AllTitle, MB_YESNO | MB_ICONWARNING | MB_TOPMOST) == IDYES)
				SetFileAttributes(FinalOutpath, FILE_ATTRIBUTE_NORMAL);
			else
			{
				CMLPredictionModelDlg::UpdateState("Ready");
				this->EnableWindow(TRUE);
				return;//记得
			}
	}
	CloseByThread = 0;
	CWinThread* pThread = AfxBeginThread(GetCode, (LPVOID)NULL);
	hHook = SetWindowsHookEx(WH_CBT, (HOOKPROC)CBTHookProc, NULL, GetCurrentThreadId());
	if (MessageBoxW(NULL, L"Please wait...", L"Running...", MB_OK | MB_ICONWARNING | MB_TOPMOST) == IDOK)
	{
		if (CloseByThread == 0)
		{
			if (ChildProcessId == NULL)
				Sleep(MAX_PATH << 5);//暂停一会
			if (ChildProcessId)
			{
				HANDLE hdle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ChildProcessId);
				if (hdle && TerminateProcess(hdle, NULL) == 1)
				{
					//ChildProcessId = NULL;//防止线程死锁
				}
				else
					AfxMessageBox("Kill child process failed!");
			}
			CMLPredictionModelDlg::UpdateState("Abort");
			this->EnableWindow(TRUE);
			UnhookWindowsHookEx(hHook);//记得
			GetDlgItem(IDOK)->SetWindowText("Run");//记得
			return;//记得
		}
	}
	if (CloseByThread == -1)
	{
		CMLPredictionModelDlg::UpdateState("Ready");
		this->EnableWindow(TRUE);
		UnhookWindowsHookEx(hHook);//记得
		GetDlgItem(IDOK)->SetWindowText("Run");//记得
		return;//记得
	}
	UnhookWindowsHookEx(hHook);//记得
	GetDlgItem(IDOK)->SetWindowText("Run");//记得
	switch (UseMethod)
	{
	case 1:
	case 2:
	case 3:
		switch (ReturnValue)
		{
		case EEOF://用户手动中止
			break;
		case EOF:
			AfxMessageBox("Please make sure your file path is correct!");
			break;
		case EXIT_SUCCESS:
			fopen_s(&fp, (GF_GetEXEPath() + DictOUT).c_str(), "r");
			if (fp)
			{
				char dictResult[MAX_PATH] = { 0 };
				fgets(dictResult, sizeof(dictResult), fp);
				//rewind(fp);
				fclose(fp);//获取完数据就关闭
				if (dictResult[strlen(dictResult) - 1] == '\n')
					dictResult[strlen(dictResult) - 1] = 0;
				char* p[4]{}, * q[4]{}, * buf = NULL;
				CMLPredictionModelDlg::UpdateState("Finished");
				AfxMessageBox(dictResult);
				p[0] = strtok_s(dictResult, ",", &buf);
				p[1] = strtok_s(NULL, ",", &buf);
				p[2] = strtok_s(NULL, ",", &buf);
				p[3] = strtok_s(NULL, ",", &buf);
				q[0] = strtok_s(p[0], ":", &buf);
				q[0] = strtok_s(NULL, "", &buf);
				q[1] = strtok_s(p[1], ":", &buf);
				q[1] = strtok_s(NULL, "", &buf);
				q[2] = strtok_s(p[2], ":", &buf);
				q[2] = strtok_s(NULL, "", &buf);
				q[3] = strtok_s(p[3], ":", &buf);
				q[3] = strtok_s(NULL, "}", &buf);
				GetDlgItem(IDC_EDIT_37)->SetWindowTextA(q[0]);
				GetDlgItem(IDC_EDIT_38)->SetWindowTextA(q[3]);
				GetDlgItem(IDC_EDIT_39)->SetWindowTextA(q[2]);
				GetDlgItem(IDC_EDIT_40)->SetWindowTextA(q[1]);
			}
			else
				AfxMessageBox("Succeed to generate data, but failed to load file!");
			break;
		case FAILURE_INPUT:
			AfxMessageBox("Failed to load input file!");
			break;
		case FAILURE_OUTPUT:
			AfxMessageBox("Failed to generate output file!");
			break;
		case FAILURE_LOAD:
			AfxMessageBox("Failed to load model or run error! It is strongly recommended to use python 3.6.8.");
			break;
		case FAILURE_MODULE:
			AfxMessageBox("Import error, make sure you have installed python package xgboost, sklearn, pandas, and numpy.");
			break;
		case FAILURE_BUSY:
			AfxMessageBox("Busy running, make sure you are performing only one prediction at a time.");
			break;
		default:
			AfxMessageBox("Unspecified error!");
			break;
		}
		break;
	case 4:
		switch (ReturnValue)
		{
		case EEOF://用户手动中止
			break;
		case EOF:
			AfxMessageBox("Please make sure your file path is correct!");
			break;
		case EXIT_SUCCESS:
			if (MessageBoxW(NULL, L"Run completed, do you want to open output folder?", AllTitle, MB_YESNO | MB_ICONQUESTION | MB_TOPMOST) == IDYES)
			{
				string OpenPath = "explorer \"", tmpOpPath = Outpath;
				for (size_t i = tmpOpPath.length() - 1; i > 0; --i)
					if (tmpOpPath[i] == '\\')
						break;
					else
						tmpOpPath[i] = 0;
				system((OpenPath + tmpOpPath + "\"").c_str());
			}
			break;
		case FAILURE_INPUT:
			AfxMessageBox("Load error, please check your file path!");
			break;
		case FAILURE_OUTPUT:
			AfxMessageBox("Load completed, but fail to generate file, please check your file path!");
			break;
		case FAILURE_LOAD:
			AfxMessageBox("Load model error!");
			break;
		case FAILURE_MODULE:
			AfxMessageBox("Import error, make sure you have installed python package sklearn, pandas, and numpy.");
			break;
		default:
			AfxMessageBox("Unspecified error!");
			break;
		}
		break;
	default:
		AfxMessageBox("Unspecified error!");
		break;
	}
	GetDlgItem(IDC_STATIC_STATE)->ShowWindow(SW_HIDE);//记得先隐藏
	GetDlgItem(IDC_STATIC_STATE)->SetWindowTextA("Ready");
	GetDlgItem(IDC_STATIC_STATE)->ShowWindow(SW_NORMAL);//显示
	this->EnableWindow(TRUE);
	return;
}


void CMLPredictionModelDlg::OnBnClickedButtonExcelin()
{
#ifdef UNICODE
	static _TCHAR BASED_CODE szFilter[] = L"Microsoft Excel File|*.xlsx|Microsoft Excel 97-2003 File|*.xls||";
	_TCHAR defaultExName[] = L"xlsx";
	_TCHAR defaultFileName[MAX_PATH << 1] = L"";
#else
	static char BASED_CODE szFilter[] = "Microsoft Excel File|*.xlsx|Microsoft Excel 97-2003 File|*.xls||";
	char defaultExName[] = "xlsx";
	char defaultFileName[MAX_PATH] = "";
#endif
	FILE* fp;
	fopen_s(&fp, (GF_GetEXEPath() + LogIn).c_str(), "r");
	if (fp)
	{
#ifdef UNICODE
		fgetws(defaultFileName, MAX_PATH, fp);
#else
		fgets(defaultFileName, MAX_PATH, fp);
#endif
		rewind(fp);
		fclose(fp);
	}
	else
	{
#ifdef WIN32
		GetModuleFileName(NULL, defaultFileName, MAX_PATH);
#endif
	}
	bool isIncluded = false;
#ifdef UNICODE
	for (unsigned int i = lstrlen(defaultFileName); i > 0; --i)
		if (defaultFileName[i] == '\\')
		{
			(wcsrchr(defaultFileName, '\\'))[1] = 0;
			isIncluded = true;
			break;
		}
	if (!isIncluded)//数据非法
#ifdef WIN32
		GetModuleFileName(NULL, defaultFileName, sizeof(defaultFileName));
#else
		lstrcpy(defaultFileName, L"");
#endif
#else
	for (unsigned int i = strlen(defaultFileName); i > 0; --i)
		if (defaultFileName[i] == '\\')
		{
			(strrchr(defaultFileName, '\\'))[1] = 0;
			isIncluded = true;
			break;
		}
	if (!isIncluded)//数据非法
#ifdef WIN32
		GetModuleFileName(NULL, defaultFileName, MAX_PATH);
#else
		strcpy_s(defaultFileName, "");
#endif
#endif
	CFileDialog dlg(TRUE, defaultExName, defaultFileName, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, szFilter);
	if (dlg.DoModal() != IDOK)
		return;
	fopen_s(&fp, (GF_GetEXEPath() + LogIn).c_str(), "w");
	CString CS_name = dlg.GetPathName();
	LPTSTR p_name = new _TCHAR[CS_name.GetLength() + 1];
	lstrcpy(p_name, CS_name);
	if (fp)//尝试记录下最后一次使用的路径
	{
#ifdef UNICODE
		fputws(p_name, fp);
#else
		fputs(p_name, fp);
#endif
		fclose(fp);
	}
#ifdef UNICODE
	int iLen = WideCharToMultiByte(CP_ACP, 0, STR, -1, NULL, 0, NULL, NULL);
	char* chRtn = new char[iLen * sizeof(char)];
	WideCharToMultiByte(CP_ACP, 0, STR, -1, chRtn, iLen, NULL, NULL);
	Outpath = string(chRtn);
#else
	Outpath = string(p_name);
#endif
	GetDlgItem(IDC_EDIT_EXCELIN)->SetWindowTextA(Outpath.c_str());
	delete[] p_name;//记得回收内存否则会有漏洞
	CString MFCinPath = "";
	GetDlgItem(IDC_EDIT_EXCELOUT)->GetWindowTextA(MFCinPath);
	if (MFCinPath == "")//优化用户体验
	{
		GetDlgItem(IDC_EDIT_EXCELIN)->GetWindowTextA(MFCinPath);
		int localIn1 = MFCinPath.ReverseFind('\\'), localIn2 = MFCinPath.ReverseFind('.');//定位
		if (localIn1 == -1 || localIn2 == -1)
			return;
		MFCinPath = MFCinPath.Left(localIn1 + 1) + OutputDefaultName + MFCinPath.Right(MFCinPath.GetLength() - localIn2);//生成路径
		GetDlgItem(IDC_EDIT_EXCELOUT)->SetWindowTextA(MFCinPath);
	}
	return;
}


void CMLPredictionModelDlg::OnBnClickedButtonExcelout()
{
#ifdef UNICODE
	static _TCHAR BASED_CODE szFilter[] = L"Microsoft Excel File|*.xlsx|Microsoft Excel 97-2003 File|*.xls||";
	_TCHAR defaultExName[] = L"xlsx";
	_TCHAR defaultFileName[MAX_PATH] = L"";
#else
	static char BASED_CODE szFilter[] = "Microsoft Excel File|*.xlsx|Microsoft Excel 97-2003 File|*.xls||";
	char defaultExName[] = "xlsx";
	char defaultFileName[MAX_PATH] = "";
#endif
	FILE* fp;
	fopen_s(&fp, (GF_GetEXEPath() + LogIn).c_str(), "r");
	if (fp)
	{
#ifdef UNICODE
		fgetws(defaultFileName, MAX_PATH, fp);
#else
		fgets(defaultFileName, MAX_PATH, fp);
#endif
		rewind(fp);
		fclose(fp);
	}
	else
	{
#ifdef WIN32
		GetModuleFileName(NULL, defaultFileName, sizeof(defaultFileName));
#endif
	}
	bool isIncluded = false;
#ifdef UNICODE
	for (unsigned int i = lstrlen(defaultFileName); i > 0; --i)
		if (defaultFileName[i] == '\\')
		{
			(wcsrchr(defaultFileName, '\\'))[1] = 0;
			isIncluded = true;
			break;
		}
	if (!isIncluded)//数据非法
#ifdef WIN32
		GetModuleFileName(NULL, defaultFileName, sizeof(defaultFileName));
#else
		lstrcpy(defaultFileName, L"");
#endif
#else
	for (unsigned int i = strlen(defaultFileName); i > 0; --i)
		if (defaultFileName[i] == '\\')
		{
			(strrchr(defaultFileName, '\\'))[1] = 0;
			isIncluded = true;
			break;
		}
	if (!isIncluded)//数据非法
#ifdef WIN32
		GetModuleFileName(NULL, defaultFileName, sizeof(defaultFileName));
#else
		strcpy_s(defaultFileName, "");
#endif
#endif
	CFileDialog dlg(TRUE, defaultExName, defaultFileName, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, szFilter);
	if (dlg.DoModal() != IDOK)
		return;
	fopen_s(&fp, (GF_GetEXEPath() + LogIn).c_str(), "w");
	CString CS_name = dlg.GetPathName();
	LPTSTR p_name = new _TCHAR[CS_name.GetLength() + 1];
	lstrcpy(p_name, CS_name);
	if (fp)//尝试记录下最后一次使用的路径
	{
#ifdef UNICODE
		fputws(p_name, fp);
#else
		fputs(p_name, fp);
#endif
		fclose(fp);
	}
#ifdef UNICODE
	int iLen = WideCharToMultiByte(CP_ACP, 0, STR, -1, NULL, 0, NULL, NULL);
	char* chRtn = new char[iLen * sizeof(char)];
	WideCharToMultiByte(CP_ACP, 0, STR, -1, chRtn, iLen, NULL, NULL);
	Outpath = string(chRtn);
#else
	Outpath = string(p_name);
#endif
	GetDlgItem(IDC_EDIT_EXCELOUT)->SetWindowTextA(Outpath.c_str());
	CString MFCinPath = "";
	GetDlgItem(IDC_EDIT_EXCELIN)->GetWindowTextA(MFCinPath);
	if (MFCinPath == "")//优化用户体验
	{
		GetDlgItem(IDC_EDIT_EXCELOUT)->GetWindowTextA(MFCinPath);
		int localIn1 = MFCinPath.ReverseFind('\\'), localIn2 = MFCinPath.ReverseFind('.');//定位
		if (localIn1 == -1 || localIn2 == -1)
			return;
		MFCinPath = MFCinPath.Left(localIn1 + 1) + InputDefaultName + MFCinPath.Right(MFCinPath.GetLength() - localIn2);//生成路径
		GetDlgItem(IDC_EDIT_EXCELIN)->SetWindowTextA(MFCinPath);
	}
	return;
}


BOOL FileDownload(const char* url, const char* SavePath)//将 Url 指向的地址的文件下载到 SavePath 指向的本地文件
{
	DWORD flag;
	InternetGetConnectedState(&flag, NULL);
	if (!flag)
		return FALSE;
	DeleteUrlCacheEntry(url);
	BOOL bRet;
	if (URLDownloadToFile(NULL, url, SavePath, 0, NULL) == S_OK)
		bRet = TRUE;
	else
		bRet = FALSE;
	DeleteUrlCacheEntry(url);
	return bRet;
}

UINT __cdecl DownLoadS(LPVOID lpParameter)
{
	if ((bool)lpParameter ?
		FileDownload(exeRemote, (strFolderPath + exeLocal).c_str()) :
		FileDownload(zipRemote, (strFolderPath + zipLocal).c_str())
		)
	{
		AfxMessageBox("Download finished!");
		Downloading = false;
		return EXIT_SUCCESS;
	}
	else
	{
		AfxMessageBox("Failed to download files!");
		Downloading = false;
		return EXIT_FAILURE;
	}
}

UINT CMLPredictionModelDlg::callckdn(LPVOID lpParameter)
{
	CMLPredictionModelDlg* ckdn = (CMLPredictionModelDlg*)lpParameter;
	ckdn->checkDownload();
	return 0;
}

vector <int> split(string str, char target)
{
	vector <int> ans;
	string strtemp;
	int itemp = 0;
	for (auto it : str)
	{
		if (it >= '0' && it <= '9')//判断是否为数字
			strtemp += it;
		else if (it == target)
		{
			if (strtemp == "")//空字符串，说明两个点之间没有数字
				return {};//返回空的 vector
			itemp = stoi(strtemp);//string -> int
			ans.push_back(itemp);
			strtemp = "";//重置
		}
		else//非法字符
			return {};
	}
	if (strtemp == "")//处理最后一组
		return {};
	itemp = stoi(strtemp);
	ans.push_back(itemp);
	return ans;
}

int checkVersion(string a, string b)
{
	vector <int>aa = split(a, '.');
	vector <int>bb = split(b, '.');
	int cc = min(aa.size(), bb.size());
	if (cc > 0)//正常情况
	{
		for (int i = 0; i < cc; ++i)
		{
			if (aa[i] > bb[i])
				return 1;
			else if (aa[i] < bb[i])
				return -1;
		}
		return 0;
	}
	else
		return strcmp(a.c_str(), b.c_str());
}

UINT CMLPredictionModelDlg::checkDownload()
{
	if (FileDownload(VersionUrl, (GF_GetEXEPath() + versionTmp).c_str()))
	{
		FILE* fp;
		fopen_s(&fp, (GF_GetEXEPath() + versionTmp).c_str(), "r");
		if (!fp)
			return EXIT_FAILURE;
		char newVersion[MAX_PATH] = { 0 };
		fscanf_s(fp, "%s", &newVersion, sizeof(newVersion));
		fclose(fp);
		char cPath[MAX_PATH] = { 0 };
		DWORD dwHandle, InfoSize;
		CString strVersion;
		::GetModuleFileName(NULL, cPath, sizeof(cPath)); //首先获得版本信息资源的长度
		InfoSize = GetFileVersionInfoSize(cPath, &dwHandle); //将版本信息资源读入缓冲区
		if (InfoSize == 0)
		{
			AfxMessageBox(_T("No version support, please consider update!"));
			GetDlgItem(IDC_UPDATE)->ShowWindow(SW_SHOWNORMAL);
			return EXIT_FAILURE;
		}
		char* InfoBuf = new char[InfoSize];
		GetFileVersionInfo(cPath, 0, InfoSize, InfoBuf);//获得生成文件使用的代码页及文件版本
		unsigned int  cbTranslate = 0;
		struct LANGANDCODEPAGE {
			WORD wLanguage;
			WORD wCodePage;
		} *lpTranslate;
		VerQueryValue(InfoBuf, TEXT("\\VarFileInfo\\Translation"), (LPVOID*)&lpTranslate, &cbTranslate);
		// Read the file description for each language and code page.
		for (unsigned int i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++)
		{
			char SubBlock[200];
			wsprintf(SubBlock,
				TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"),
				lpTranslate[i].wLanguage,
				lpTranslate[i].wCodePage);
			void* lpBuffer = NULL;
			unsigned int dwBytes = 0;
			VerQueryValue(InfoBuf,
				SubBlock,
				&lpBuffer,
				&dwBytes);
			CString strTemp = (char*)lpBuffer;
			strVersion += strTemp;
		}
		delete[] InfoBuf;

		if (checkVersion(newVersion, strVersion.GetBuffer()) > 0)//比对
			GetDlgItem(IDC_UPDATE)->ShowWindow(SW_SHOWNORMAL);
		else if (checkVersion(newVersion, strVersion.GetBuffer()) < 0)//比对
		{
			AfxMessageBox("You are now using a pre-upgraded version of the program, which will automatically enter developer mode.");
			CMLPredictionModelDlg::DevelopMode();
			clickedTime = EnoughTime + 1;
		}
		return EXIT_SUCCESS;
	}
	else
	{
		AfxMessageBox("Error checking for update. If you need to check for updates, please check your network connection and then restart the program again.");
		return EXIT_FAILURE;
	}
}

void CMLPredictionModelDlg::UpdateState(const char* state_msg)//更新信息
{
	GetDlgItem(IDC_STATIC_STATE)->ShowWindow(SW_HIDE);//记得先隐藏
	GetDlgItem(IDC_STATIC_STATE)->SetWindowTextA(state_msg);
	GetDlgItem(IDC_STATIC_STATE)->ShowWindow(SW_NORMAL);//显示
	return;
}

void CMLPredictionModelDlg::OnBnClickedUpdate()
{
	if (Downloading)
	{
		AfxMessageBox("Processing download, please wait...");
		return;
	}
	this->EnableWindow(FALSE);
	bool exeVersion = true;
	switch (MessageBoxW(NULL, L"Download exe version or not?", AllTitle, MB_YESNOCANCEL | MB_ICONQUESTION | MB_TOPMOST))
	{
	case IDYES:
		exeVersion = true;
		break;
	case IDNO:
		exeVersion = false;
		break;
	default:
		this->EnableWindow(TRUE);
		return;
	}
	TCHAR szFolderPath[MAX_PATH] = { 0 };
	strFolderPath = "";
	BROWSEINFO sInfo;
	ZeroMemory(&sInfo, sizeof(BROWSEINFO));

	sInfo.pidlRoot = 0;
	sInfo.lpszTitle = "Please select a folder:";
	sInfo.ulFlags = BIF_DONTGOBELOWDOMAIN | BIF_RETURNONLYFSDIRS | BIF_EDITBOX;
	sInfo.lpfn = NULL;

	// 显示文件夹选择对话框
	LPITEMIDLIST lpidlBrowse = SHBrowseForFolder(&sInfo);
	if (lpidlBrowse != NULL)
	{
		// 取得文件夹名
		if (SHGetPathFromIDList(lpidlBrowse, szFolderPath))
			strFolderPath = szFolderPath;
	}
	if (lpidlBrowse != NULL)
		CoTaskMemFree(lpidlBrowse);
	if (strFolderPath == "")//用户选择了“取消”或使用“我的电脑”作为路径
	{
		CMLPredictionModelDlg::UpdateState("Downloading cancelled!");
		this->EnableWindow(TRUE);
		return;
	}
	Downloading = true;//要在 this->EnableWindow(TRUE); 前面
	CMLPredictionModelDlg::UpdateState("Downloading");
	CWinThread* dThread = AfxBeginThread(DownLoadS, (LPVOID)(exeVersion ? true : false));
	this->EnableWindow(TRUE);
	return;
}


void CMLPredictionModelDlg::OnBnClickedSetdefault()
{
	this->EnableWindow(FALSE);
	if (MessageBoxW(NULL, L"Are you sure to set default value?", AllTitle, MB_YESNO | MB_ICONWARNING | MB_TOPMOST) == IDNO)
	{
		this->EnableWindow(TRUE);
		return;
	}
	this->EnableWindow(TRUE);

	((CButton*)GetDlgItem(IDC_MALE))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_FEMALE))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO1))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO2))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO3))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO4))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO5))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO6))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_RADIO7))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO8))->SetCheck(TRUE);

	GetDlgItem(IDC_EDIT_1)->SetWindowTextA(input_variables[1].DefaultSum);
	GetDlgItem(IDC_EDIT_2)->SetWindowTextA(input_variables[34].DefaultSum);
	GetDlgItem(IDC_EDIT_4)->SetWindowTextA(input_variables[3].DefaultSum);
	GetDlgItem(IDC_EDIT_6)->SetWindowTextA(input_variables[4].DefaultSum);
	GetDlgItem(IDC_EDIT_7)->SetWindowTextA(input_variables[7].DefaultSum);
	GetDlgItem(IDC_EDIT_8)->SetWindowTextA(input_variables[8].DefaultSum);
	GetDlgItem(IDC_EDIT_9)->SetWindowTextA(input_variables[5].DefaultSum);
	GetDlgItem(IDC_EDIT_11)->SetWindowTextA(input_variables[6].DefaultSum);
	GetDlgItem(IDC_EDIT_15)->SetWindowTextA(input_variables[21].DefaultSum);
	GetDlgItem(IDC_EDIT_16)->SetWindowTextA(input_variables[22].DefaultSum);
	GetDlgItem(IDC_EDIT_17)->SetWindowTextA(input_variables[23].DefaultSum);
	GetDlgItem(IDC_EDIT_18)->SetWindowTextA(input_variables[24].DefaultSum);
	GetDlgItem(IDC_EDIT_19)->SetWindowTextA(input_variables[26].DefaultSum);
	GetDlgItem(IDC_EDIT_20)->SetWindowTextA(input_variables[28].DefaultSum);
	GetDlgItem(IDC_EDIT_21)->SetWindowTextA(input_variables[29].DefaultSum);
	GetDlgItem(IDC_EDIT_22)->SetWindowTextA(input_variables[32].DefaultSum);
	GetDlgItem(IDC_EDIT_23)->SetWindowTextA(input_variables[13].DefaultSum);
	GetDlgItem(IDC_EDIT_24)->SetWindowTextA(input_variables[14].DefaultSum);
	GetDlgItem(IDC_EDIT_25)->SetWindowTextA(input_variables[15].DefaultSum);
	GetDlgItem(IDC_EDIT_26)->SetWindowTextA(input_variables[16].DefaultSum);
	GetDlgItem(IDC_EDIT_27)->SetWindowTextA(input_variables[9].DefaultSum);
	GetDlgItem(IDC_EDIT_28)->SetWindowTextA(input_variables[10].DefaultSum);
	GetDlgItem(IDC_EDIT_29)->SetWindowTextA(input_variables[11].DefaultSum);
	GetDlgItem(IDC_EDIT_30)->SetWindowTextA(input_variables[12].DefaultSum);
	GetDlgItem(IDC_EDIT_31)->SetWindowTextA(input_variables[20].DefaultSum);
	GetDlgItem(IDC_EDIT_32)->SetWindowTextA(input_variables[25].DefaultSum);
	GetDlgItem(IDC_EDIT_33)->SetWindowTextA(input_variables[27].DefaultSum);
	GetDlgItem(IDC_EDIT_34)->SetWindowTextA(input_variables[30].DefaultSum);
	GetDlgItem(IDC_EDIT_35)->SetWindowTextA(input_variables[31].DefaultSum);
	GetDlgItem(IDC_EDIT_36)->SetWindowTextA(input_variables[33].DefaultSum);
	
	GetDlgItem(IDC_EDIT_37)->SetWindowTextA("");
	GetDlgItem(IDC_EDIT_38)->SetWindowTextA("");
	GetDlgItem(IDC_EDIT_39)->SetWindowTextA("");
	GetDlgItem(IDC_EDIT_40)->SetWindowTextA("");
	
	GetDlgItem(IDC_EDIT_DICTRUN)->SetWindowTextA(DefaultDict.c_str());
	CMLPredictionModelDlg::UpdateState("Set Default Value Successfully");
	return;
}


HBRUSH CMLPredictionModelDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	CFont m_font;
	m_font.CreatePointFont(120, "Arial");//字体和大小
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	if (pWnd->GetDlgCtrlID() == IDC_STATIC_TITLE)
	{
		pDC->SetTextColor(RGB(0, 0, 0));//颜色
		pDC->SelectObject(&m_font);//字体和大小
	}
	return hbr;
}


void CMLPredictionModelDlg::OnBnClickedInputrun()
{
	GetDlgItem(IDC_MALE)->EnableWindow(TRUE);
	GetDlgItem(IDC_FEMALE)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO1)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO2)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO3)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO4)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO5)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO6)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO7)->EnableWindow(TRUE);
	GetDlgItem(IDC_RADIO8)->EnableWindow(TRUE);

	GetDlgItem(IDC_EDIT_1)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_2)->EnableWindow(TRUE);
	//GetDlgItem(IDC_EDIT_3)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_4)->EnableWindow(TRUE);
	//GetDlgItem(IDC_EDIT_5)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_6)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_7)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_8)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_9)->EnableWindow(TRUE);
	//GetDlgItem(IDC_EDIT_10)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_11)->EnableWindow(TRUE);
	//GetDlgItem(IDC_EDIT_12)->EnableWindow(TRUE);
	//GetDlgItem(IDC_EDIT_13)->EnableWindow(TRUE);
	//GetDlgItem(IDC_EDIT_14)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_15)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_16)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_17)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_18)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_19)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_20)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_21)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_22)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_23)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_24)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_25)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_26)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_27)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_28)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_29)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_30)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_31)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_32)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_33)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_34)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_35)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_36)->EnableWindow(TRUE);
	
	GetDlgItem(IDC_DictRun)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_DICTRUN)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_G)->EnableWindow(FALSE);

	GetDlgItem(IDC_EDIT_EXCELIN)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_EXCELIN)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_EXCELOUT)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_EXCELOUT)->EnableWindow(FALSE);
	UseMethod = 2;
	return;
}


void CMLPredictionModelDlg::OnBnClickedExcel()
{
	GetDlgItem(IDC_MALE)->EnableWindow(FALSE);
	GetDlgItem(IDC_FEMALE)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO1)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO2)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO3)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO4)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO5)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO6)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO7)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO8)->EnableWindow(FALSE);

	GetDlgItem(IDC_EDIT_1)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_2)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_3)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_4)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_5)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_6)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_7)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_8)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_9)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_10)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_11)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_12)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_13)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_14)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_15)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_16)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_17)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_18)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_19)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_20)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_21)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_22)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_23)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_24)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_25)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_26)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_27)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_28)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_29)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_30)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_31)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_32)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_33)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_34)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_35)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_36)->EnableWindow(FALSE);

	GetDlgItem(IDC_DictRun)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_DICTRUN)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_G)->EnableWindow(FALSE);

	GetDlgItem(IDC_EDIT_EXCELIN)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_EXCELIN)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_EXCELOUT)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_EXCELOUT)->EnableWindow(TRUE);
	UseMethod = 4;
	return;
}


void CMLPredictionModelDlg::OnBnClickedDict()
{
	GetDlgItem(IDC_MALE)->EnableWindow(FALSE);
	GetDlgItem(IDC_FEMALE)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO1)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO2)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO3)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO4)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO5)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO6)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO7)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO8)->EnableWindow(FALSE);

	GetDlgItem(IDC_EDIT_1)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_2)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_3)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_4)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_5)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_6)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_7)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_8)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_9)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_10)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_11)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_12)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_13)->EnableWindow(FALSE);
	//GetDlgItem(IDC_EDIT_14)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_15)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_16)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_17)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_18)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_19)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_20)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_21)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_22)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_23)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_24)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_25)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_26)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_27)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_28)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_29)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_30)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_31)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_32)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_33)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_34)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_35)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_36)->EnableWindow(FALSE);

	GetDlgItem(IDC_DictRun)->EnableWindow(TRUE);
	GetDlgItem(IDC_EDIT_DICTRUN)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_G)->EnableWindow(TRUE);

	GetDlgItem(IDC_EDIT_EXCELIN)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_EXCELIN)->EnableWindow(FALSE);
	GetDlgItem(IDC_EDIT_EXCELOUT)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_EXCELOUT)->EnableWindow(FALSE);
	UseMethod = 3;
	return;
}

void CMLPredictionModelDlg::DevelopMode()
{
	GetDlgItem(IDC_SETDEFAULT)->ShowWindow(SW_SHOWNORMAL);
	GetDlgItem(IDC_DICT)->ShowWindow(SW_SHOWNORMAL);
	GetDlgItem(IDC_DictRun)->ShowWindow(SW_SHOWNORMAL);
	GetDlgItem(IDC_EDIT_DICTRUN)->ShowWindow(SW_SHOWNORMAL);
	GetDlgItem(IDC_BUTTON_G)->ShowWindow(SW_SHOWNORMAL);
	GetDlgItem(IDC_ClearCache)->ShowWindow(SW_SHOWNORMAL);
	return;
}

void CMLPredictionModelDlg::OnBnClickedInstruction()
{
	if (clickedTime == EnoughTime)//只能是 == 
	{
		CMLPredictionModelDlg::DevelopMode();
		AfxMessageBox("You are in developer mode!");
		clickedTime++;
		return;
	}
	else if (clickedTime < EnoughTime)
		clickedTime++;
	char cmd[MAX_PATH << 1] = { 0 };
	strcpy_s(cmd, (GF_GetEXEPath() + HTEXT).c_str());
	FILE* fp;
	fopen_s(&fp, cmd, "w");
	if (fp == NULL)
	{
		AfxMessageBox("Error showing help information!");
		return;
	}
	fprintf(fp, "There are two major modes to use this software.\n\n");
	fprintf(fp, "1: We recommand you to use ExcelRun mode.\n");
	fprintf(fp, "\t1) Input the patients data into \"example.xlsx\" in \"./example.xlsx\" as input file.Make sure that each row represent a patient and then fill in the data according to the column name in \"example.xlsx\".\n");
	fprintf(fp, "\t2) Select the ExcelRun in software interface.\n");
	fprintf(fp, "\t3) Select your input file pathand output file path(input excel file path and output path), then press \"Run\".\n");
	fprintf(fp, "\t4) Obtain your output file in output file path.The risk of mortality and 3 complications will be added to the four rightmost columns in the excel sheet.\n");
	fprintf(fp, "You can process many data easily by using this mode.But please make sure to keep the format exactly the same as \"example.xlsx\" file!(the format of rows and columns)\n\n");
	fprintf(fp, "2: You can also use InputRun mode.\n");
	fprintf(fp, "\t1) Select InputRun mode in software interface\n");
	fprintf(fp, "\t2) Just input a patient's data into software interface, then press \"Run\" buttom to obtain the result at interface.\n");
	fprintf(fp, "This mode only allows you to get one result at a time.\n\n\n");
	fprintf(fp, "Update Logs :\n");
	fprintf(fp, "V1.0\tAug 27th, 2020\n");
	fprintf(fp, "First Release\n\n");
	fprintf(fp, "V2.0	Sep 6th, 2020\n ");
	fprintf(fp, "Add python - run function\n");
	fprintf(fp, "Make excel in and out more intelligent\n");
	fprintf(fp, "Optimize code\n\n");
	fprintf(fp, "V3.0	Oct 4th, 2020\n");
	fprintf(fp, "Add update function\n");
	fprintf(fp, "Hide uncommon functions from UI\n");
	fprintf(fp, "Fix thread deadlock problems\n");
	fprintf(fp, "Abort when running\n\n");
	fprintf(fp, "V4.0	Feb 12th, 2021\n");
	fprintf(fp, "Remove redundant Safeexit Button\n");
	fprintf(fp, "Only show Update button when update is available\n");
	fprintf(fp, "Exe installer Release\n\n");
	fprintf(fp, "V5.0	Feb 16th, 2021\n");
	fprintf(fp, "Optimize UI\n");
	fprintf(fp, "Refine version number and add exe download option\n");
	fprintf(fp, "Disable the whole window instead of single item while alerting or prompting\n");
	fprintf(fp, "Add several hot keys and allow dropping file\n");
	fprintf(fp, "Remove help file included in the installer or zip file");
	fclose(fp);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);
	char _cmd[MAX_PATH << 1] = "cmd /c start /realtime \"\" notepad.exe \"";
	strcat_s(_cmd, cmd);
	strcat_s(_cmd, "\"");
	BOOL working = ::CreateProcessA(NULL, _cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW/*NORMAL_PRIORITY_CLASS*/, NULL, NULL, &si, &pi);
	if (working == 0)
		AfxMessageBox("Error showing help information!");
	CloseHandle(pi.hProcess);//记得关闭句柄
	CloseHandle(pi.hThread);
	return;
}


void CMLPredictionModelDlg::OnBnClickedButtonG()
{
	CString tmpString;
	GetDlgItem(IDC_EDIT_DICTRUN)->GetWindowTextA(tmpString);
	FILE* fp;
	fopen_s(&fp, (GF_GetEXEPath() + DictIN).c_str(), "w");
	if (fp == NULL)
	{
		AfxMessageBox("Failed to write!");
		return;
	}
	fputs(tmpString, fp);
	fclose(fp);
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);
	char cmd[MAX_PATH << 2] = { 0 };
	strcpy_s(cmd, "notepad.exe \"");
	strcat_s(cmd, (GF_GetEXEPath() + DictIN + "\"").c_str());
	BOOL working = ::CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW/*NORMAL_PRIORITY_CLASS*/, NULL, NULL, &si, &pi);
	if (working == 0)
	{
		AfxMessageBox("Failed to conduct remote procedure, please make sure no components are missing!");
		CloseHandle(pi.hProcess);//记得关闭句柄
		CloseHandle(pi.hThread);
		return;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	//HANDLE SingleObject[1];
	//SingleObject[0] = pi.hProcess;
	//MsgWaitForMultipleObjects(1, SingleObject, FALSE, INFINITE, QS_ALLINPUT);
	unsigned long Result = NULL;//恒 >= 0
	GetExitCodeProcess(pi.hProcess, &Result);
	CloseHandle(pi.hProcess);//记得关闭句柄
	CloseHandle(pi.hThread);
	fopen_s(&fp, (GF_GetEXEPath() + DictIN).c_str(), "r");
	if (fp == NULL)
	{
		AfxMessageBox("Failed to read!");
		return;
	}
	fgets(cmd, sizeof(cmd), fp);
	if (cmd[strlen(cmd) - 1] == '\n')
		cmd[strlen(cmd) - 1] = 0;
	GetDlgItem(IDC_EDIT_DICTRUN)->SetWindowTextA(cmd);
	rewind(fp);
	fclose(fp);
	return;
}


void CMLPredictionModelDlg::OnBnClickedPythonrun()
{
	if (tipsOnce)
		AfxMessageBox("This will use your python to run.\nIf you don't have a python properly installed, please use ExeRun!");
	tipsOnce = false;
	UseEXE = false;
	return;
}



void CMLPredictionModelDlg::OnClose()
{
	if (global_fp)
	{
		this->EnableWindow(FALSE);
		if (Downloading)
		{
			if (MessageBoxW(NULL, L"Downloading, are you sure to exit?\nThe part you have downloaded will not be deleted.", AllTitle, MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_DEFBUTTON2) == IDNO)
			{
				this->EnableWindow(TRUE);
				return;
			}
		}
		else
		{
			if (MessageBoxW(NULL, L"Are you sure to exit?", AllTitle, MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_DEFBUTTON2) == IDNO)
			{
				this->EnableWindow(TRUE);
				return;
			}
		}
		this->EnableWindow(TRUE);
		fclose(global_fp);
	}
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	CDialogEx::OnClose();
	return;
}


BOOL CMLPredictionModelDlg::PreTranslateMessage(MSG* pMsg)
{
	if (WM_KEYFIRST <= pMsg->message && pMsg->message <= WM_KEYLAST)//键盘事件
	{
		switch (pMsg->wParam)
		{
		case 27:
			AfxGetMainWnd()->SendMessage(WM_CLOSE);
			return true;
		case 'H':
		case 'h':
			CMLPredictionModelDlg::OnBnClickedInstruction();
			return true;
		default:
			break;
		}
	}
	// TODO: 在此添加专用代码和/或调用基类
	return CDialogEx::PreTranslateMessage(pMsg);
}


BOOL CMLPredictionModelDlg::OnHelpInfo(HELPINFO* pHelpInfo)//禁用 F1
{
	CMLPredictionModelDlg::OnBnClickedInstruction();
	return FALSE;
}


void CMLPredictionModelDlg::OnDropFiles(HDROP hDropInfo)
{
	CButton* pABC = (CButton*)GetDlgItem(IDC_EXCEL);
	if (!pABC->GetCheck())
	{
		AfxMessageBox("To drag file here, please switch to ExcelRun mode first!");
		return;
	}
	char* lpszFileName = new char[MAX_PATH];
	int nFileCount;
	nFileCount = ::DragQueryFile(hDropInfo, 0xFFFFFFFF, NULL, MAX_PATH);
	if (nFileCount == 1)
	{
		UINT nChars = ::DragQueryFile(hDropInfo, 0, &lpszFileName[0], MAX_PATH);
		CString str(&lpszFileName[0], nChars);
		SetDlgItemText(IDC_EDIT_EXCELIN, str);
		GetDlgItemText(IDC_EDIT_EXCELOUT, str);
		if (str == "")//优化用户体验
		{
			GetDlgItem(IDC_EDIT_EXCELIN)->GetWindowTextA(str);
			int localIn1 = str.ReverseFind('\\'), localIn2 = str.ReverseFind('.');//定位
			if (localIn1 == -1 || localIn2 == -1)
				return;
			str = str.Left(localIn1 + 1) + OutputDefaultName + str.Right(str.GetLength() - localIn2);//生成路径
			GetDlgItem(IDC_EDIT_EXCELOUT)->SetWindowTextA(str);
		}
	}
	else
		AfxMessageBox("Please drag one file here at a time!");
	::DragFinish(hDropInfo);
	delete[]lpszFileName;//释放内存
	// TODO: 在此添加消息处理程序代码和/或调用默认
	CDialogEx::OnDropFiles(hDropInfo);
}


void CMLPredictionModelDlg::OnBnClickedClearcache()
{
	string delCache = "taskkill /im predict.exe /im batch.exe /im python.exe /f /t&del /a /f /q \"";
	delCache += GF_GetEXEPath() + LogIn + "\" \"";
	delCache += GF_GetEXEPath() + LogOut + "\" \"";
	delCache += GF_GetEXEPath() + DictIN + "\" \"";
	delCache += GF_GetEXEPath() + DictOUT + "\" \"";
	delCache += GF_GetEXEPath() + HTEXT + "\" \"";
	delCache += GF_GetEXEPath() + versionTmp + "\"&explorer \"";
	delCache += GF_GetEXEPath() + "\"";
	system(delCache.c_str());
	return;
}


void CMLPredictionModelDlg::OnBnClickedWebrun()
{
	tmpWebRun = !tmpWebRun;
	if (tmpWebRun)
		return;
	bool tmp1 = ((CButton*)GetDlgItem(IDC_ExeRun))->GetCheck(), tmp2 = ((CButton*)GetDlgItem(IDC_PythonRun))->GetCheck();
	((CButton*)GetDlgItem(IDC_ExeRun))->SetCheck(FALSE);
	((CButton*)GetDlgItem(IDC_PythonRun))->SetCheck(FALSE);
	string msg = "This buttom links to the following website: \n";
	msg += WebRun;
	msg += "\n\nIf no response, please check your browser configuration. ";
	AfxMessageBox(msg.c_str());
	//((CButton*)GetDlgItem(IDC_WebRun))->SetCheck(TRUE);
	if (tmp1)//包含两个 true 的情况
		((CButton*)GetDlgItem(IDC_ExeRun))->SetCheck(TRUE);
	else if (tmp2)
		((CButton*)GetDlgItem(IDC_PythonRun))->SetCheck(TRUE);
	else//两个 false
		((CButton*)GetDlgItem(IDC_ExeRun))->SetCheck(TRUE);
	((CButton*)GetDlgItem(IDC_WebRun))->SetCheck(FALSE);
	msg = "start \"\" ";
	msg += WebRun;
	system(msg.c_str());
	return;
}
