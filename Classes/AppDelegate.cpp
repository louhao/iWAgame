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




extern "C" void iWA_Mprint(void);

extern "C" void iWA_Auth_InitAuthInfoBlock(void);
extern "C" void iWA_Auth_PrintAuthInfoBlock(void);
extern "C" void iWA_Auth_DeinitAuthInfoBlock(void);

extern "C" char* iWA_Auth_GetPacketBuf();

	
extern "C" unsigned int iWA_Auth_WriteLogonChallengeClientPacket();
extern "C" unsigned int iWA_Auth_ReadLogonChallengeServerPacket();
extern "C" unsigned int iWA_Auth_WriteLogonProofClientPacket();
extern "C" unsigned int iWA_Auth_ReadLogonProofBuild6005ServerPacket();
extern "C" unsigned int iWA_Auth_WriteRealmListClientPacket();
extern "C" unsigned int iWA_Auth_ReadRealmListClientPacket();

extern "C" unsigned int iWA_Auth_CalculateClientSrpValue();

extern "C" void iWA_Auth_TestSHA1(void);
extern "C" void iWA_Auth_TestBn(void);

extern "C" void iWA_World_InitSessionInfoBlock(void);
extern "C" void iWA_World_DeinitSessionInfoBlock(void);
extern "C" void iWA_World_PrintSessionInfoBlock(void);
extern "C" void iWA_World_ReadWorldServerPacket(void);
extern "C" unsigned int iWA_World_WriteCmsgAuthSessionPacket(void);
extern "C" unsigned int iWA_World_WriteCmsgCharEnumPacket(void);
extern "C" unsigned int iWA_World_WriteCmsgPlayerLoginPacket(void);
extern "C" char* iWA_World_GetPacketBuf(void);

//#define _SERVER_IP_    "127.0.0.1"
//#define _SERVER_IP_    "192.168.10.105"
#define _SERVER_IP_    "192.168.1.6" 


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


#if 1   // test LuaHttpClient 
    printf("hello lua init");
    
    LuaHttpClientTest();
    return true;
#endif
    
#if 0   // test HttpClientTest
    
    HttpClientTest *hctest = new HttpClientTest();
    hctest->onMenuGetTestClicked(NULL);
    return true;
#endif

#if 0  // test curl easy interface
    {
        CURL *curl;
        CURLcode res;
        char buffer[10];
        
        curl = curl_easy_init();
        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, "www.baidu.com");
            res = curl_easy_perform(curl);
            /* always cleanup */
            curl_easy_cleanup(curl);
            if (res == 0)
            {
                printf("0 response");
            }
            else
            {
                printf("code: %i",res);
            }
        } 
        else 
        {
            printf("no curl");
        } 
    }
    return true;
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
