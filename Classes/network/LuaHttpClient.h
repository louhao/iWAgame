//
//  LuaHttpClient.h
//  HelloCocos2dLua
//
//  Created by louhao on 12-11-20.
//
//

#ifndef Extension_LuaHttpClient_h
#define Extension_LuaHttpClient_h

extern "C" {
#include "tolua++.h"
#include "tolua_fix.h"
}

#include "cocos2d.h"
//#include "cocos-ext.h"

class LuaHttpClient : public cocos2d::CCObject
{
public:


    static void doGet(const char* url,int handler);
    
    void onHttpRequestCompleted(cocos2d::CCNode *sender, void *data);
    void executeFunction(int responseCode, const char* resp);
    
private:
    int m_nHandler;
};

void LuaHttpClientTest();


TOLUA_API int tolua_httpclient_open(lua_State* tolua_S);


#endif
