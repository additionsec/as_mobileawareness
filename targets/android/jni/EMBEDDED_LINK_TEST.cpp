#include <jni.h>
#include <stdint.h>

#include "as_mobileawareness.h"

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	// one of everything, for linking purposes

        jint ret = AS_JNI_OnLoad(vm, reserved);
	uint8_t uuid[32];
	ret = AS_UUID_Default_Serial(uuid);
	ret = AS_Initialize( NULL, uuid, NULL, 0, NULL );
	ret = AS_Register_Identity("");
	ret = AS_Send_Message(2,"");
	long lret = AS_Heartbeat(42);
	AS_Login_Status(1);
	AS_Network_Reachability();
	uint32_t v = AS_Version();
}

}
