
// MLPredictionModel.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMLPredictionModelApp:
// �йش����ʵ�֣������ MLPredictionModel.cpp
//

class CMLPredictionModelApp : public CWinApp
{
public:
	CMLPredictionModelApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CMLPredictionModelApp theApp;