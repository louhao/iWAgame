LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := hellolua_shared

LOCAL_MODULE_FILENAME := libhellolua

LOCAL_SRC_FILES := hellolua/main.cpp \
                   ../../Classes/AppDelegate.cpp \
                   ../../Classes/ODSocket.cpp \
                   ../../Classes/iWA_Basic.c \
                   ../../Classes/iWA_Net.c \
                   ../../Classes/iWA_Crypto.c \
                   ../../Classes/iWA_Auth.c \
                   ../../Classes/iWA_World.c \
                   ../../Classes/iWA_Socket.c \
                   ../../Classes/bn/sha1.c \
                   ../../Classes/bn/bn_lib.c \
                   ../../Classes/bn/bn_add.c \
                   ../../Classes/bn/bn_asm.c \
                   ../../Classes/bn/bn_ctx.c \
                   ../../Classes/bn/bn_div.c \
                   ../../Classes/bn/bn_exp.c \
                   ../../Classes/bn/bn_gcd.c \
                   ../../Classes/bn/bn_mod.c \
                   ../../Classes/bn/bn_mont.c \
                   ../../Classes/bn/bn_mul.c \
                   ../../Classes/bn/bn_print.c \
                   ../../Classes/bn/bn_rand.c \
                   ../../Classes/bn/bn_recp.c \
                   ../../Classes/bn/bn_shift.c \
                   ../../Classes/bn/bn_sqr.c \
                   ../../Classes/bn/bn_word.c \
                   ../../Classes/bn/mem.c \
                   ../../Classes/bn/mem_clr.c \
                   ../../../../scripting/lua/cocos2dx_support/CCLuaEngine.cpp \
                   ../../../../scripting/lua/cocos2dx_support/Cocos2dxLuaLoader.cpp \
                   ../../../../scripting/lua/cocos2dx_support/LuaCocos2d.cpp \
                   ../../../../scripting/lua/cocos2dx_support/tolua_fix.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../Classes \
                    $(LOCAL_PATH)/../../../../cocos2dx/platform/third_party/android/prebuilt/libcurl/include

LOCAL_WHOLE_STATIC_LIBRARIES := cocos2dx_static
LOCAL_WHOLE_STATIC_LIBRARIES += cocosdenshion_static
LOCAL_WHOLE_STATIC_LIBRARIES += cocos_lua_static

include $(BUILD_SHARED_LIBRARY)

$(call import-module,cocos2dx)
$(call import-module,CocosDenshion/android)
$(call import-module,scripting/lua/proj.android/jni)
