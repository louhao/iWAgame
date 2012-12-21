//
//  LuaHttpClient.cpp
//  HelloCocos2dLua
//
//  Created by louhao on 12-11-20.
//
//
#include "httpclient2.h"
#include "LuaHttpClient.h"
#include "CCLuaEngine.h"
#include <string>


USING_NS_CC;
USING_NS_CC_EXT;



void LuaHttpClient::doGet(const char* url,int handler)
{
    LuaHttpClient *client = new LuaHttpClient();
    CCHttpRequest* request = new CCHttpRequest();
    request->setUrl(url);
    client->m_nHandler=handler;
    request->setRequestType(CCHttpRequest::kHttpGet);
    request->setResponseCallback(client, callfuncND_selector(LuaHttpClient::onHttpRequestCompleted));
    request->setTag(url);
    request->_saveToFile = true;
    CCHttpClient::getInstance()->send(request);
    request->release();
}


void LuaHttpClient::executeFunction(int responseCode, const char* data)
{
 //   CCLuaEngine *engine = CCScriptEngineManager::sharedManager()->getScriptEngine();
    CCLuaEngine* engine = CCLuaEngine::defaultEngine();
    lua_State* m_state = engine->getLuaState();
    lua_pushinteger(m_state, responseCode);
    lua_pushstring(m_state,data);
    engine->executeFunctionByHandler(this->m_nHandler, 2);
}


void LuaHttpClient::onHttpRequestCompleted(CCNode *sender, void *resp) {
    CCLog("LuaHttpClient::onHttpRequestCompleted");
    
    CCHttpResponse *response = (CCHttpResponse*)resp;
    
    if (!response)
    {
        return;
    }
    
    // You can get original request type from: response->request->reqType
    if (0 != strlen(response->getHttpRequest()->getTag()))
    {
        CCLog("%s completed", response->getHttpRequest()->getTag());
    }
    
    CCLog("response code: %d", response->getResponseCode());
    
    if (!response->isSucceed())
    {
        CCLog("response failed");
        CCLog("error buffer: %s", response->getErrorBuffer());
        return;
    }
    
    // dump data
    std::vector<char> *buffer = response->getResponseData();
    char data[10240];
    CCLog("response ok, data size %d", buffer->size());
    for (unsigned int i = 0; i < buffer->size(); i++)
    {
        data[i]=(*buffer)[i];
    }
    data[buffer->size()]='\0';
    //printf(data);
    
#if 0  // commented this if not called from lua
    this->executeFunction(response->getResponseCode(), data);
#endif
}

void LuaHttpClientTest()
{
    CCLog("LuaHttpClientTest");
    
    LuaHttpClient::doGet("http://www.gonworld.com/map.rar", 1);
    
    //LuaHttpClient::doGet("http://nxg.gonworld.com/nxg/aa.zip", 1);

    return;
    
    //LuaHttpClient::doGet("http://www.haosht.com/reposync.zip", 1);

    return;
#if 0    
std::string zipfile = CCFileUtils::sharedFileUtils()->getWriteablePath() + "test2.zip";
    
std::string unzippath = CCFileUtils::sharedFileUtils()->getWriteablePath() + "unziptest/";
    
    CCLog("zipfile : %s", zipfile.c_str());
    CCLog("unzippath : %s", unzippath.c_str());
    
    CCFileUtils::sharedFileUtils()->unzipFileToPath(zipfile.c_str(), unzippath.c_str());
#endif
}


static int tolua_LuaHttpClient_doGet00(lua_State* tolua_S)
{
    tolua_Error tolua_err;
    if (
        !tolua_isusertable(tolua_S,1,"LuaHttpClient",0,&tolua_err) ||
        !tolua_isstring(tolua_S,2,0,&tolua_err) ||
        !toluafix_isfunction(tolua_S,3,"LUA_FUNCTION",0,&tolua_err) ||
        !tolua_isnoobj(tolua_S,4,&tolua_err)
        )
        goto tolua_lerror;
    else
    {
        const char* url = ((const char*)  tolua_tostring(tolua_S,2,0));
        int funcID = (toluafix_ref_function(tolua_S,3,0));
        {
            LuaHttpClient::doGet(url, funcID);
        }
    }
    return 1;
tolua_lerror:
    tolua_error(tolua_S,"#ferror in function 'node'.",&tolua_err);
    return 0;
    
}



TOLUA_API int tolua_httpclient_open (lua_State* tolua_S)
{
    tolua_open(tolua_S);
    
    tolua_usertype(tolua_S,"LuaHttpClient");
    
    tolua_module(tolua_S,NULL,0);
    tolua_beginmodule(tolua_S,NULL);
    
    tolua_cclass(tolua_S, "LuaHttpClient", "LuaHttpClient", "CCObject", NULL);
    tolua_beginmodule(tolua_S,"LuaHttpClient");
    tolua_function(tolua_S,"doGet",tolua_LuaHttpClient_doGet00);
    tolua_endmodule(tolua_S);
    
    tolua_endmodule(tolua_S);
    return 1;
}



