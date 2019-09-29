/* ----------------------------------------------------------
�ļ����ƣ�WMI_DeviceQuery.h

���ߣ��ؽ���

MSN��splashcn@msn.com

�汾��ʷ��
	V1.4	2010��05��17��
			������Ӳ�����кŴ����еĴ������ں�EVEREST Ultimate Edition 5.5һ�¡�

	V1.3	2010��05��11��
			�����˶�����ԭ��MAC��ַ�Ĳ�ѯ��

	V1.2	2010��05��05��
			���Ӷ�Ӳ�����кŵĽ�һ������

	V1.1	2010��04��30��
			����΢��MSDN���Ӵ��󣬲����Ӷ�������������жϡ�
			
	V1.0	2010��04��27��
			�����ʽ�汾��

����������
	����WMI��ȡ�豸���ԣ�
		0������ԭ��MAC��ַ
		1��Ӳ�����к�
		2���������к�
		3��CPU ID
		4��BIOS���к�
		5�������ͺ�
		6��������ǰMAC��ַ

�ӿں�����
	WMI_DeviceQuery
------------------------------------------------------------ */
#pragma once

#include <windows.h>

#ifndef MACRO_T_DEVICE_PROPERTY
	#define MACRO_T_DEVICE_PROPERTY

	#define PROPERTY_MAX_LEN	128	// �����ֶ���󳤶�
	typedef struct _T_DEVICE_PROPERTY
	{
		TCHAR szProperty[PROPERTY_MAX_LEN];
	} T_DEVICE_PROPERTY;
#endif

#define WMI_QUERY_TYPENUM	7	// WMI��ѯ֧�ֵ�������

#ifdef __cplusplus
extern "C"
{
#endif

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
INT WMI_DeviceQuery( INT iQueryType, T_DEVICE_PROPERTY *properties, INT iSize );

#ifdef __cplusplus
}
#endif
