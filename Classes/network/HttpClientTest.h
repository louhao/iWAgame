#ifndef __HTTP_CLIENT_H__
#define __HTTP_CLIENT_H__

#include "httpclient2.h"
//#include "cocos-ext.h"

class HttpClientTest : public cocos2d::CCLayer
{
public:
    HttpClientTest();
    virtual ~HttpClientTest();
//    void toExtensionsMainLayer(cocos2d::CCObject *sender);
    
    //Menu Callbacks
    void onMenuGetTestClicked(cocos2d::CCObject *sender);
    void onMenuPostTestClicked(cocos2d::CCObject *sender);
    void onMenuPostBinaryTestClicked(cocos2d::CCObject *sender);
    
    //Http Response Callback
    void onHttpRequestCompleted(cocos2d::CCNode *sender, void *data);

private:
    cocos2d::CCLabelTTF* m_labelStatusCode;
};

void runHttpClientTest();

#endif //__HTTPREQUESTHTTP_H
