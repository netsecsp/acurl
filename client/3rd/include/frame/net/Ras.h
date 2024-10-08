#if !defined(AFX_RAS_H__88966194_6F5D_4303_8670_7EAE695A32B3__INCLUDED_)
#define AFX_RAS_H__88966194_6F5D_4303_8670_7EAE695A32B3__INCLUDED_
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Author: Shengqian Yang, netsecsp@hotmail.com, China, last updated 01/15/2024
http://asynframe.sf.net

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
copyright notice, this list of conditions and the
following disclaimer.

* Redistributions in binary form must reproduce the
above copyright notice, this list of conditions
and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "../AsynNetwork.h"
NAMESPACE_BEGIN(asynsdk)

/////////////////////////////////////////////////////////////////////////////////
#define IN_Ras "com.svc.ras"

/////////////////////////////////////////////////////////////////////////////////
#define IN_Ras_DT_Modem      "modem"
#define IN_Ras_DT_Isdn       "isdn"
#define IN_Ras_DT_X25        "x25"
#define IN_Ras_DT_Vpn        "vpn"
#define IN_Ras_DT_Pad        "pad"
#define IN_Ras_DT_Generic    "GENERIC"
#define IN_Ras_DT_Serial     "SERIAL"
#define IN_Ras_DT_FrameRelay "FRAMERELAY"
#define IN_Ras_DT_Atm        "ATM"
#define IN_Ras_DT_Sonet      "SONET"
#define IN_Ras_DT_SW56       "SW56"
#define IN_Ras_DT_Irda       "IRDA"
#define IN_Ras_DT_Parallel   "PARALLEL"
#define IN_Ras_DT_PPPoE      "PPPoE"

NAMESPACE_END(asynsdk)

#endif // !defined(AFX_RAS_H__88966194_6F5D_4303_8670_7EAE695A32B3__INCLUDED_)