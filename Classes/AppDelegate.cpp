#include "cocos2d.h"
#include "AppDelegate.h"
#include "SimpleAudioEngine.h"
#include "script_support/CCScriptSupport.h"
#include "CCLuaEngine.h"
#include "ODSocket.h"
#include "curl/curl.h"
#include "network/httpclient2.h"
#include "network/httpclienttest.h"
#include "network/luahttpclient.h"

USING_NS_CC;
using namespace CocosDenshion;


extern "C" void iWA_Mprint(void);
extern "C" void iWA_Auth_DoReceive(void);
extern "C" void iWA_Auth_Init(void);
extern "C" int iWA_Auth_DoAuth(char *server, short port, char *username, char *password);
extern "C" int iWA_Auth_DoAuthSample(void);


extern "C" void iWA_World_InitSessionInfoBlock(void);
extern "C" void iWA_World_DeinitSessionInfoBlock(void);
extern "C" void iWA_World_PrintSessionInfoBlock(void);
extern "C" void iWA_World_ReadWorldServerPacket(void);
extern "C" unsigned int iWA_World_WriteCmsgAuthSessionPacket(void);
extern "C" unsigned int iWA_World_WriteCmsgCharEnumPacket(void);
extern "C" unsigned int iWA_World_WriteCmsgPlayerLoginPacket(void);
extern "C" char* iWA_World_GetPacketBuf(void);
extern "C" void iWA_World_ReceivePacket(void);


class CCSocket : public CCObject
{
public:
    CCSocket();

    void check_socket_receive(float delta);

};

CCSocket::CCSocket()
{
    CCDirector::sharedDirector()->getScheduler()->scheduleSelector(schedule_selector(CCSocket::check_socket_receive), this, 0, false);
}

void CCSocket::check_socket_receive(float delta)
{
   //     CCLog("CCSocket::check_socket_receive() called");

        iWA_Auth_DoReceive();
         iWA_World_ReceivePacket();  
}




AppDelegate::AppDelegate()
{
    // fixed me
    //_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_LEAK_CHECK_DF);
}

AppDelegate::~AppDelegate()
{
    // end simple audio engine here, or it may crashed on win32
    SimpleAudioEngine::sharedEngine()->end();
    //CCScriptEngineManager::purgeSharedManager();
}





bool AppDelegate::applicationDidFinishLaunching()
{
    // initialize director
    CCDirector *pDirector = CCDirector::sharedDirector();
    pDirector->setOpenGLView(CCEGLView::sharedOpenGLView());
    
    CCEGLView::sharedOpenGLView()->setDesignResolutionSize(480, 320, kResolutionNoBorder);

    // turn on display FPS
    pDirector->setDisplayStats(true);

    // set FPS. the default value is 1.0/60 if you don't call this
    pDirector->setAnimationInterval(1.0 / 60);





#if 0

iWA_Mprint();
	iWA_Auth_TestBn();
	
iWA_Mprint();

   // iWA_Auth_TestSHA1();

iWA_Mprint();

	iWA_Auth_InitAuthInfoBlock();
	char *pkt = iWA_Auth_GetPacketBuf();
	int size = iWA_Auth_WriteLogonChallengeClientPacket();

iWA_Mprint();

	ODSocket cSocket;
	int ret;

	cSocket.Init();
	ret = cSocket.Create(AF_INET,SOCK_STREAM,0);
	ret = cSocket.Connect(_SERVER_IP_,3724);
	char recvBuf[1024] = "\0";
	
	ret = cSocket.Send(pkt, size, 0);
	ret = cSocket.Recv(recvBuf, 256,0);

	memcpy(pkt, recvBuf, ret);
	iWA_Auth_ReadLogonChallengeServerPacket();
	iWA_Auth_CalculateClientSrpValue();
	size = iWA_Auth_WriteLogonProofClientPacket();

	ret = cSocket.Send(pkt, size, 0);
	ret = cSocket.Recv(recvBuf,256,0);

	memcpy(pkt, recvBuf, ret);
	iWA_Auth_ReadLogonProofBuild6005ServerPacket();
	size = iWA_Auth_WriteRealmListClientPacket();

	ret = cSocket.Send(pkt, size, 0);
	ret = cSocket.Recv(recvBuf,256,0);

	memcpy(pkt, recvBuf, ret);
	iWA_Auth_ReadRealmListClientPacket();
	
	iWA_Auth_PrintAuthInfoBlock();


	
	//CCMessageBox(recvBuf,"recived data is:");
	
	cSocket.Close();

#if 1
	iWA_World_InitSessionInfoBlock();
	// iWA_World_PrintSessionInfoBlock();

	pkt = iWA_World_GetPacketBuf();

	ret = cSocket.Create(AF_INET,SOCK_STREAM,0);
	ret = cSocket.Connect(_SERVER_IP_,8085);

	ret = cSocket.Recv(recvBuf,1024,0);
	memcpy(pkt, recvBuf, ret);
	iWA_World_ReadWorldServerPacket();
	size = iWA_World_WriteCmsgAuthSessionPacket();

	ret = cSocket.Send(pkt, size, 0);
	ret = cSocket.Recv(recvBuf,1024,0);	
	memcpy(pkt, recvBuf, ret);
	iWA_World_ReadWorldServerPacket();
	size = iWA_World_WriteCmsgCharEnumPacket();

	ret = cSocket.Send(pkt, size, 0);
	ret = cSocket.Recv(recvBuf,1024,0);	
	memcpy(pkt, recvBuf, ret);
	iWA_World_ReadWorldServerPacket();	
	size = iWA_World_WriteCmsgPlayerLoginPacket();

	ret = cSocket.Send(pkt, size, 0);
	ret = cSocket.Recv(recvBuf,1024,0);	
	memcpy(pkt, recvBuf, ret);
	iWA_World_ReadWorldServerPacket();		




	iWA_World_DeinitSessionInfoBlock();	
#endif

	iWA_Auth_DeinitAuthInfoBlock();


	cSocket.Clean();



iWA_Mprint();


	return true;

#endif


    


#if 1
CCLog("set scheduler");
CCSocket *soc = new CCSocket();

iWA_Auth_Init();
iWA_Auth_DoAuthSample();

return 1;
#endif

    // register lua engine
    CCLuaEngine* pEngine = CCLuaEngine::defaultEngine();
    CCScriptEngineManager::sharedManager()->setScriptEngine(pEngine);

    // added by louhao, reg httpclient 
    lua_State* L = pEngine->getLuaState();
    tolua_httpclient_open(L);


#if (CC_TARGET_PLATFORM == CC_PLATFORM_ANDROID)
    CCString* pstrFileContent = CCString::createWithContentsOfFile("hello.lua");
    if (pstrFileContent)
    {
        pEngine->executeString(pstrFileContent->getCString());
    }
#else
    std::string path = CCFileUtils::sharedFileUtils()->fullPathFromRelativePath("hello.lua");
    pEngine->addSearchPath(path.substr(0, path.find_last_of("/")).c_str());
    pEngine->executeScriptFile(path.c_str());
#endif 

    return true;
}

// This function will be called when the app is inactive. When comes a phone call,it's be invoked too
void AppDelegate::applicationDidEnterBackground()
{
    CCDirector::sharedDirector()->stopAnimation();
    SimpleAudioEngine::sharedEngine()->pauseBackgroundMusic();
}

// this function will be called when the app is active again
void AppDelegate::applicationWillEnterForeground()
{
    CCDirector::sharedDirector()->startAnimation();
    SimpleAudioEngine::sharedEngine()->resumeBackgroundMusic();
}
