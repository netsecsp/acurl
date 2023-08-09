/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 05/01/2022
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
#include "stdafx.h"
#include "websocket_Downloader.h"
#include <frame/app/Utility.h>
#include <frame/asm/ISsl.h>

BEGIN_ASYN_MESSAGE_MAP(CWebsocketDownloader)
	ON_IOMSG_NOTIFY(OnIomsgNotify)
	ON_QUERY_RESULT(OnQueryResult, IUnknown)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CWebsocketDownloader::OnQueryResult( uint64_t lParam1, uint64_t lParam2, IUnknown **objects )
{
    if( lParam1 == EN_SystemEvent )
    {
        asynsdk::CStringSetter d(1);
        asynsdk::CMemorySetter c((void*)0);
        ((IKeyvalSetter*)objects[0])->Get(STRING_from_string(";dattype"), 0, 0, &d);
        ((IKeyvalSetter*)objects[0])->Get(STRING_from_string(";context"), 0, 0, &c);
        if( d.m_val.rfind("cert.verify") != std::string::npos )
        {// cert.verify
            return m_nochkcert? S_OK : ((ISsl*)lParam2)->VerifyPeerCertificate(*(handle*)c.m_val.ptr, 0x1000);
        }
    }
    return E_NOTIMPL;
}

HRESULT CWebsocketDownloader::OnIomsgNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation )
{
    uint32_t lErrorCode = NO_ERROR, lTransferedBytes;
    lpAsynIoOperation->GetCompletedResult(&lErrorCode, &lTransferedBytes, 0);

    switch(lAction)
    {
    case Io_connect:
    {
        if( lErrorCode != NO_ERROR )
        {
            printf("connect, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            break;
        }

        asynsdk::CStringSetter host(1);
        PORT port;
        {// 打印链接信息
            CComPtr<IAsynNetIoOperation> spAsynIoOperation;
            lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
            spAsynIoOperation->GetPeerAddress(&host, 0, &port, &m_af);
            printf("connected %s:%d[%s]\n", host.m_val.c_str(), port, m_af == AF_INET? "ipv4" : "ipv6");
        }

        asynsdk::CKeyvalSetter params(1);
      //params.Set(STRING_from_string("User-Agent"), 1, STRING_from_string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"));
        params.Set(STRING_from_string("Accept"    ), 1, STRING_from_string("*/*"));

        CComPtr<INet> spINet; m_spAsynTcpSocket->QueryInterface(IID_INet, (void **)&spINet);
        return spINet->SendPacket(STRING_from_string("GET"), STRING_from_string(m_curi), &params, lpAsynIoOperation);
    }

    case Io_recv:
    {
        if( lErrorCode != NO_ERROR )
        {
            printf("recv, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            break;
        }
        
        if( m_upgraded )
        {
            const BYTE ident = (BYTE)lParam1 & 0xf;

            if( ident == 0x8 )
            {
                printf("recv CTRL frame: shutdown\n");
                SetEvent(m_hNotify);
                break;
            }

            do{
            BYTE *frame; lpAsynIoOperation->GetIoBuffer(0, 0, &frame);
            if( ident == 0x1 )
            {
                if( m_file < 0 )
                {
                    std::string frame_ansi; asynsdk::Convert(CP_UTF8, (char*)frame, lTransferedBytes, CP_ACP, frame_ansi);
                    printf("recv TEXT frame: %s\n", frame_ansi.c_str());
                }
                else
                    _write(m_file, frame, lTransferedBytes);
                break;
            }
            if( ident == 0x2 )
            {
                if( m_file < 0 )
                    printf("recv DATA frame: %d\n", lTransferedBytes);
                else
                    _write(m_file, frame, lTransferedBytes);
                break;
            }
            if( ident >= 0x8 )
            {
                printf("recv CTRL frame: %d\n", lTransferedBytes);
            }
            }while(0);
            return m_spAsynTcpSocket->Read(lpAsynIoOperation); //接收数据
        }

        CComPtr<INetmsg> spHttpmsg;
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (void **)&spHttpmsg);

        STRING Method;
        STRING Params;
        STRING V;
        BOOL ack;
        spHttpmsg->Getline(&Method, &Params, &V, &ack );
        std::string method = string_from_STRING(Method);
        std::string params = string_from_STRING(Params);
        std::string v = string_from_STRING(V);
        printf("recv http %s packet: %.*s %.*s\n", ack? "ack" : "req", Method.len, Method.ptr, Params.len, Params.ptr);

        do{
        if( ack )
        {
           lErrorCode = atoi(method.c_str());
           if( lErrorCode / 100 != 1 )
           {
               printf("%d %s\n", lErrorCode, params.c_str());
               break;
           }
           else
           {
               m_upgraded = true; //mark 升级websocket协议成功
           }

           if(!m_savefile.empty())
           {
               m_file = _open(m_savefile.c_str(), O_BINARY|O_RDONLY);
               if( m_file < 0 )
               {
                   printf("open %s: %s\n", m_savefile.c_str(), strerror(errno));
                   break;
               }
           }

           return m_spAsynTcpSocket->Read(lpAsynIoOperation);
        }
        }while(0);

        SetEvent(m_hNotify);
        break;
    }

    case Io_send:
    {
        if( lErrorCode != NO_ERROR )
        {
            printf("send, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            break;
        }

        // 发送请求成功，准备接收http响应报文的头部数据
        lpAsynIoOperation->SetIoParam1(0); //表示只接收http头部
        return m_spAsynTcpSocket->Read(lpAsynIoOperation);
    }
    }

    return E_NOTIMPL; //通知系统释放lpAsynIoOperation
}
