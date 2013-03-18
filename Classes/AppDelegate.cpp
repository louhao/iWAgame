#include "cocos2d.h"
#include "AppDelegate.h"
#include "SimpleAudioEngine.h"
#include "script_support/CCScriptSupport.h"
#include "CCLuaEngine.h"
#include "curl/curl.h"
#include "network/httpclient2.h"
#include "network/httpclienttest.h"
#include "network/luahttpclient.h"

USING_NS_CC;
using namespace CocosDenshion;


extern "C" void iWA_Mprint(void);
extern "C" void iWA_Auth_DoReceive(void);
extern "C" void iWA_Auth_Init(void);
extern "C" int iWA_Auth_DoAuth(char *server, short port, char *username, char *password, void *cb);
extern "C" int iWA_Auth_DoReg(char *server, short port, char *username, char *password, void *cb);
extern "C" int iWA_Auth_DoAuthSample(void);
extern "C" int iWA_Auth_DoRegSample(void);
extern "C" void iWA_World_DoReceive(void);
extern "C" int iWA_World_StartSample(char *server, unsigned short port);
extern "C" void iWA_World_Init(void);

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
    iWA_World_DoReceive();  
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



#if 1

    CCLog("set scheduler");
    CCSocket *soc = new CCSocket();

    iWA_Auth_Init();
  // iWA_Auth_DoRegSample();
    iWA_Auth_DoAuthSample();
   iWA_World_Init();
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
